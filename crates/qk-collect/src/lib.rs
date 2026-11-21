//! Agentless collectors and actions. Scans are read-only and never use sudo; patching and
//! rebooting run only the exact commands listed in the host's QuietKeep sudoers rule.

use qk_core::host::OsType;
use qk_core::updates::{parse_apt_held, parse_apt_upgradable, parse_pacman_updates, PackageUpdate};
use qk_ssh::{quote, Command, Connection, Result};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub updates: Vec<PackageUpdate>,
    pub reboot_required: bool,
    /// Installed packages. Empty when the inventory could not be read.
    pub packages: Vec<qk_core::updates::InstalledPackage>,
    /// `ID` and `VERSION_ID` from /etc/os-release, such as `debian` and `13`.
    pub os_release: Option<(String, String)>,
    /// Packages `apt-get autoremove` would remove.
    pub autoremove: u32,
}

const OS_RELEASE: &str = r#". /etc/os-release 2>/dev/null; echo "$ID $VERSION_ID""#;

fn parse_os_release(text: &str) -> Option<(String, String)> {
    let mut it = text.split_whitespace();
    let id = it.next()?;
    let version = it.next().unwrap_or("");
    let ok = |s: &str| !s.is_empty() && s.len() <= 32 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    (ok(id) && (version.is_empty() || ok(version))).then(|| (id.to_lowercase(), version.to_string()))
}

pub fn packages_command(os: OsType) -> Command {
    match os {
        OsType::Apt | OsType::Kali | OsType::Proxmox => Command::new("env").args([
            "LC_ALL=C",
            "dpkg-query",
            "-W",
            "-f=${db:Status-Abbrev}\t${Package}\t${Version}\t${source:Package}\t${source:Version}\n",
        ]),
        OsType::Pacman => Command::new("pacman").arg("-Q"),
    }
}

pub fn parse_packages(os: OsType, text: &str) -> Vec<qk_core::updates::InstalledPackage> {
    use qk_core::updates::InstalledPackage;
    text.lines()
        .filter_map(|l| match os {
            OsType::Pacman => {
                let mut it = l.split_whitespace();
                let (name, version) = (it.next()?.to_string(), it.next()?.to_string());
                Some(InstalledPackage { source: name.clone(), source_version: version.clone(), name, version })
            }
            _ => {
                let mut it = l.split('\t');
                if !it.next()?.starts_with("ii") {
                    return None;
                }
                let name = it.next()?.trim().to_string();
                let version = it.next()?.trim().to_string();
                let source = it.next().map(str::trim).filter(|s| !s.is_empty()).unwrap_or(&name).to_string();
                let source_version = it.next().map(str::trim).filter(|s| !s.is_empty()).unwrap_or(&version).to_string();
                Some(InstalledPackage { name, version, source, source_version })
            }
        })
        .filter(|p| !p.name.is_empty() && !p.version.is_empty())
        .collect()
}

/// Proxmox kernels do not always write /var/run/reboot-required, so compare the running
/// kernel against the newest installed pve/proxmox kernel package as well.
const PROXMOX_REBOOT_CHECK: &str = r#"[ -f /var/run/reboot-required ] && exit 0
running=$(uname -r)
newest=$(dpkg-query -W -f='${Status} ${Package}\n' 'pve-kernel-*' 'proxmox-kernel-*' 2>/dev/null \
  | awk '$3 == "installed" && ($4 ~ /^pve-kernel-[0-9]/ || $4 ~ /^proxmox-kernel-[0-9].*-pve(-signed)?$/) {print $4}' \
  | sed 's/.*-kernel-//; s/-signed$//' | sort -V | tail -n 1)
[ -n "$newest" ] && [ "$newest" != "$running" ]"#;

/// Arch removes the running kernel's modules directory when a new kernel is installed.
const PACMAN_REBOOT_CHECK: &str = r#"[ ! -d "/usr/lib/modules/$(uname -r)" ]"#;

pub fn upgradable_command(os: OsType) -> Command {
    match os {
        OsType::Apt | OsType::Kali | OsType::Proxmox => {
            Command::new("env").args(["LC_ALL=C", "apt", "list", "--upgradable"])
        }
        OsType::Pacman => Command::new("checkupdates"),
    }
}

pub fn reboot_check_command(os: OsType) -> Command {
    match os {
        OsType::Apt | OsType::Kali => Command::new("test").args(["-f", "/var/run/reboot-required"]),
        OsType::Proxmox => Command::new("sh").args(["-c", PROXMOX_REBOOT_CHECK]),
        OsType::Pacman => Command::new("sh").args(["-c", PACMAN_REBOOT_CHECK]),
    }
}

pub async fn scan(conn: &Connection, os: OsType) -> Result<ScanResult> {
    let out = conn.run(&upgradable_command(os)).await?;
    let text = String::from_utf8_lossy(&out.stdout);
    let updates = match os {
        OsType::Pacman => match out.exit_status {
            Some(0) => parse_pacman_updates(&text),
            Some(2) => Vec::new(),
            _ => {
                let fallback = conn.run(&Command::new("pacman").arg("-Qu")).await?;
                parse_pacman_updates(&String::from_utf8_lossy(&fallback.stdout))
            }
        },
        _ => parse_apt_upgradable(&text),
    };
    let mut updates = updates;
    if matches!(os, OsType::Apt | OsType::Kali) && !updates.is_empty() {
        let sim = conn.run(&Command::new("env").args(["LC_ALL=C", "apt-get", "-s", "upgrade"])).await?;
        if sim.success() {
            let held = parse_apt_held(&String::from_utf8_lossy(&sim.stdout));
            for u in &mut updates {
                u.held = held.get(&u.name).map(|r| r.to_string());
            }
        }
    }
    let reboot_required = conn.run(&reboot_check_command(os)).await?.success();
    let inventory = conn.run(&packages_command(os)).await?;
    let packages = if inventory.success() {
        parse_packages(os, &String::from_utf8_lossy(&inventory.stdout))
    } else {
        Vec::new()
    };
    let autoremove = if os == OsType::Pacman {
        0
    } else {
        let sim = conn.run(&Command::new("env").args(["LC_ALL=C", "apt-get", "-s", "autoremove"])).await?;
        if sim.success() { count_removals(&String::from_utf8_lossy(&sim.stdout)) } else { 0 }
    };
    let release = conn.run(&Command::new("sh").args(["-c", OS_RELEASE])).await?;
    let os_release = parse_os_release(&String::from_utf8_lossy(&release.stdout));
    Ok(ScanResult { updates, reboot_required, packages, os_release, autoremove })
}

/// Counts the packages an `apt-get -s` simulation would remove.
pub fn count_removals(simulation: &str) -> u32 {
    simulation.lines().filter(|l| l.starts_with("Remv ")).count() as u32
}

pub const SUDOERS_PATH: &str = "/etc/sudoers.d/quietkeep";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Patch,
    /// Installs updates `apt-get upgrade` keeps back because they need new packages, such as new kernels.
    Held,
    Autoremove,
    Reboot,
}

const APT_UPDATE: &[&str] = &["/usr/bin/apt-get", "update", "-qq"];
const APT_UPGRADE: &[&str] = &[
    "/usr/bin/env",
    "DEBIAN_FRONTEND=noninteractive",
    "/usr/bin/apt-get",
    "-y",
    "-o",
    "Dpkg::Options::=--force-confdef",
    "-o",
    "Dpkg::Options::=--force-confold",
    "upgrade",
];
const PROXMOX_UPGRADE: &[&str] = &[
    "/usr/bin/env",
    "DEBIAN_FRONTEND=noninteractive",
    "/usr/bin/apt-get",
    "-y",
    "-o",
    "Dpkg::Options::=--force-confdef",
    "-o",
    "Dpkg::Options::=--force-confold",
    "dist-upgrade",
];
const APT_AUTOREMOVE: &[&str] = &["/usr/bin/env", "DEBIAN_FRONTEND=noninteractive", "/usr/bin/apt-get", "-y", "autoremove"];
const PACMAN_UPGRADE: &[&str] = &["/usr/bin/pacman", "-Syu", "--noconfirm"];
const REBOOT: &[&str] = &["/usr/bin/systemctl", "reboot"];

/// The exact root commands an action runs, in order. Each is an argv starting with an absolute path.
/// Empty when the action does not apply to the OS.
pub fn privileged_commands(os: OsType, action: Action) -> Vec<&'static [&'static str]> {
    match (action, os) {
        (Action::Reboot, _) => vec![REBOOT],
        (Action::Patch, OsType::Apt | OsType::Kali) => vec![APT_UPDATE, APT_UPGRADE],
        (Action::Patch, OsType::Proxmox) => vec![APT_UPDATE, PROXMOX_UPGRADE],
        (Action::Patch, OsType::Pacman) => vec![PACMAN_UPGRADE],
        (Action::Held, OsType::Apt | OsType::Kali | OsType::Proxmox) => vec![APT_UPDATE, PROXMOX_UPGRADE],
        (Action::Autoremove, OsType::Apt | OsType::Kali | OsType::Proxmox) => vec![APT_AUTOREMOVE],
        (Action::Held | Action::Autoremove, OsType::Pacman) => vec![],
    }
}

pub fn display_command(argv: &[&str]) -> String {
    argv.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" ")
}

fn sudoers_escape(arg: &str) -> String {
    let mut out = String::with_capacity(arg.len());
    for c in arg.chars() {
        if matches!(c, '\\' | ',' | ':' | '=' | ' ') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn sudoers_line(argv: &[&str]) -> String {
    argv.iter().map(|a| sudoers_escape(a)).collect::<Vec<_>>().join(" ")
}

/// Commands `sudo -l` lists as runnable as root without a password, as sudoers writes them.
pub fn nopasswd_commands(listing: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in listing.lines().map(str::trim) {
        if !(line.starts_with("(root") || line.starts_with("(ALL")) {
            continue;
        }
        let Some(i) = line.find("NOPASSWD:") else { continue };
        out.extend(line[i + "NOPASSWD:".len()..].split(", ").map(|c| c.trim().to_string()));
    }
    out
}

/// A sudoers drop-in that lets `username` run only QuietKeep's exact commands for this OS,
/// with no wildcards. `username` must already be validated as a POSIX login name.
pub fn sudoers_rule(username: &str, os: OsType) -> String {
    let mut cmds: Vec<String> = Vec::new();
    for action in [Action::Patch, Action::Held, Action::Autoremove, Action::Reboot] {
        for argv in privileged_commands(os, action) {
            let line = sudoers_line(argv);
            if !cmds.contains(&line) {
                cmds.push(line);
            }
        }
    }
    format!(
        "# QuietKeep: allows only these exact commands, nothing else.\n\
         Cmnd_Alias QUIETKEEP = {}\n\
         {username} ALL=(root) NOPASSWD: QUIETKEEP\n",
        cmds.join(", \\\n    ")
    )
}

/// True when sudo on the host allows every command of the action without a password.
/// Reads the user's own `sudo -l` listing, because `sudo -l <command>` also succeeds for
/// commands that are allowed only with a password.
pub async fn sudo_allowed(conn: &Connection, os: OsType, action: Action, as_root: bool) -> Result<bool> {
    if as_root {
        return Ok(true);
    }
    let out = conn.run(&Command::new("env").args(["LC_ALL=C", "sudo", "-n", "-l"])).await?;
    if !out.success() {
        return Ok(false);
    }
    let allowed = nopasswd_commands(&String::from_utf8_lossy(&out.stdout));
    Ok(privileged_commands(os, action)
        .into_iter()
        .all(|argv| allowed.iter().any(|a| a == "ALL" || *a == sudoers_line(argv))))
}

#[derive(Debug, Clone, Serialize)]
pub struct ActionReport {
    pub success: bool,
    /// Last part of the combined output, for the activity log and error messages.
    pub output_tail: String,
}

const TAIL_BYTES: usize = 4000;

/// Runs the action's commands, through `sudo -n` unless the login user is already root.
pub async fn run_action(conn: &Connection, os: OsType, action: Action, as_root: bool) -> Result<ActionReport> {
    let mut log = Vec::new();
    for argv in privileged_commands(os, action) {
        let cmd = if as_root {
            Command::new(argv[0]).args(argv[1..].iter().copied())
        } else {
            Command::new("sudo").args(["-n", "--"]).args(argv.iter().copied())
        };
        let out = conn.run(&cmd).await?;
        log.extend_from_slice(&out.stdout);
        log.extend_from_slice(&out.stderr);
        if !out.success() {
            return Ok(ActionReport { success: false, output_tail: tail(&log) });
        }
    }
    Ok(ActionReport { success: true, output_tail: tail(&log) })
}

pub(crate) fn tail(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let start = text.len().saturating_sub(TAIL_BYTES);
    let start = (start..text.len()).find(|i| text.is_char_boundary(*i)).unwrap_or(text.len());
    text[start..].trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sudoers_rule_is_exact() {
        let rule = sudoers_rule("keeper", OsType::Apt);
        assert!(rule.contains("/usr/bin/apt-get update -qq"));
        assert!(rule.contains("DEBIAN_FRONTEND\\=noninteractive"));
        assert!(rule.contains("Dpkg\\:\\:Options\\:\\:\\=--force-confold upgrade"));
        assert!(rule.contains("/usr/bin/systemctl reboot"));
        assert!(rule.ends_with("keeper ALL=(root) NOPASSWD: QUIETKEEP\n"));
        assert!(!rule.contains('*'));
        assert!(sudoers_rule("root", OsType::Proxmox).contains("dist-upgrade"));
        assert!(rule.contains("--force-confold dist-upgrade"));
        assert!(rule.contains("/usr/bin/apt-get -y autoremove"));
        assert_eq!(rule.matches("apt-get update -qq").count(), 1);
        assert!(privileged_commands(OsType::Pacman, Action::Held).is_empty());
        assert!(sudoers_rule("arch", OsType::Pacman).contains("/usr/bin/pacman -Syu --noconfirm"));
    }

    #[test]
    fn nopasswd_listing_is_exact() {
        let listing = "User qkpw may run the following commands on box:\n    (ALL : ALL) ALL\n    (root) NOPASSWD: /usr/bin/apt-get update -qq, /usr/bin/env DEBIAN_FRONTEND\\=noninteractive /usr/bin/apt-get -y -o Dpkg\\:\\:Options\\:\\:\\=--force-confdef -o Dpkg\\:\\:Options\\:\\:\\=--force-confold upgrade, /usr/bin/systemctl reboot\n";
        let allowed = nopasswd_commands(listing);
        let ok = |a: Action| privileged_commands(OsType::Apt, a).into_iter().all(|argv| allowed.contains(&sudoers_line(argv)));
        assert!(ok(Action::Patch));
        assert!(ok(Action::Reboot));
        assert!(!ok(Action::Held));
        assert!(!ok(Action::Autoremove));
        assert_eq!(nopasswd_commands("    (ALL) NOPASSWD: ALL"), vec!["ALL"]);
        assert!(nopasswd_commands("    (ALL : ALL) ALL").is_empty());
    }

    #[test]
    fn removals_are_counted() {
        let sim = "Reading package lists...\nRemv linux-image-6.8.0-40-generic [6.8.0-40.40]\nRemv libfoo1 [1.0]\n";
        assert_eq!(count_removals(sim), 2);
        assert_eq!(count_removals("0 upgraded, 0 newly installed, 0 to remove"), 0);
    }

    #[test]
    fn display() {
        assert_eq!(
            display_command(APT_UPGRADE),
            "/usr/bin/env DEBIAN_FRONTEND=noninteractive /usr/bin/apt-get -y -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade"
        );
    }
}
pub mod docker;
pub mod telemetry;
pub mod access;

#[cfg(test)]
mod package_tests {
    use super::*;

    #[test]
    fn installed_packages_are_parsed() {
        let apt = "ii \tsudo\t1.9.16p2-3\tsudo\t1.9.16p2-3\nrc \told-pkg\t1.0\t\t\nii \tlinux-image-6.8.0-1060-aws\t6.8.0-1060.63\tlinux-signed-aws-6.8\t6.8.0-1060.63\nii \tbare\t2.0\n";
        let p = parse_packages(OsType::Apt, apt);
        assert_eq!(p.len(), 3);
        assert_eq!(p[1].source, "linux-signed-aws-6.8");
        assert_eq!((p[2].source.as_str(), p[2].source_version.as_str()), ("bare", "2.0"));
        assert_eq!(parse_os_release("ubuntu 22.04\n"), Some(("ubuntu".into(), "22.04".into())));
        assert_eq!(parse_os_release("arch\n"), Some(("arch".into(), String::new())));
        assert_eq!(parse_os_release("x;rm 1\n"), None);
        assert_eq!(parse_packages(OsType::Pacman, "sudo 1.9.16-1\nbash 5.2\n").len(), 2);
    }
}
