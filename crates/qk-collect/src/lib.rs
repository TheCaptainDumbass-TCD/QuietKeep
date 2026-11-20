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
    /// Installed packages as (name, version). Empty when the inventory could not be read.
    pub packages: Vec<(String, String)>,
}

pub fn packages_command(os: OsType) -> Command {
    match os {
        OsType::Apt | OsType::Kali | OsType::Proxmox => Command::new("env").args([
            "LC_ALL=C",
            "dpkg-query",
            "-W",
            "-f=${db:Status-Abbrev}\t${Package}\t${Version}\n",
        ]),
        OsType::Pacman => Command::new("pacman").arg("-Q"),
    }
}

pub fn parse_packages(os: OsType, text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|l| match os {
            OsType::Pacman => {
                let mut it = l.split_whitespace();
                Some((it.next()?.to_string(), it.next()?.to_string()))
            }
            _ => {
                let mut it = l.split('\t');
                let status = it.next()?;
                if !status.starts_with("ii") {
                    return None;
                }
                Some((it.next()?.trim().to_string(), it.next()?.trim().to_string()))
            }
        })
        .filter(|(n, v)| !n.is_empty() && !v.is_empty())
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
    Ok(ScanResult { updates, reboot_required, packages })
}

pub const SUDOERS_PATH: &str = "/etc/sudoers.d/quietkeep";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Patch,
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
const PACMAN_UPGRADE: &[&str] = &["/usr/bin/pacman", "-Syu", "--noconfirm"];
const REBOOT: &[&str] = &["/usr/bin/systemctl", "reboot"];

/// The exact root commands an action runs, in order. Each is an argv starting with an absolute path.
pub fn privileged_commands(os: OsType, action: Action) -> Vec<&'static [&'static str]> {
    match (action, os) {
        (Action::Reboot, _) => vec![REBOOT],
        (Action::Patch, OsType::Apt | OsType::Kali) => vec![APT_UPDATE, APT_UPGRADE],
        (Action::Patch, OsType::Proxmox) => vec![APT_UPDATE, PROXMOX_UPGRADE],
        (Action::Patch, OsType::Pacman) => vec![PACMAN_UPGRADE],
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

/// A sudoers drop-in that lets `username` run only QuietKeep's exact commands for this OS,
/// with no wildcards. `username` must already be validated as a POSIX login name.
pub fn sudoers_rule(username: &str, os: OsType) -> String {
    let mut cmds: Vec<String> = privileged_commands(os, Action::Patch)
        .into_iter()
        .chain(privileged_commands(os, Action::Reboot))
        .map(|argv| argv.iter().map(|a| sudoers_escape(a)).collect::<Vec<_>>().join(" "))
        .collect();
    cmds.dedup();
    format!(
        "# QuietKeep: allows only these exact commands, nothing else.\n\
         Cmnd_Alias QUIETKEEP = {}\n\
         {username} ALL=(root) NOPASSWD: QUIETKEEP\n",
        cmds.join(", \\\n    ")
    )
}

/// True when sudo on the host allows every command of the action without a password.
pub async fn sudo_allowed(conn: &Connection, os: OsType, action: Action, as_root: bool) -> Result<bool> {
    if as_root {
        return Ok(true);
    }
    for argv in privileged_commands(os, action) {
        let check = Command::new("sudo").args(["-n", "-l"]).args(argv.iter().copied());
        if !conn.run(&check).await?.success() {
            return Ok(false);
        }
    }
    Ok(true)
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
        assert!(sudoers_rule("arch", OsType::Pacman).contains("/usr/bin/pacman -Syu --noconfirm"));
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
        let apt = "ii \tsudo\t1.9.16p2-3\nrc \told-pkg\t1.0\nii \topenssh-server\t1:10.0p1-7\n";
        assert_eq!(
            parse_packages(OsType::Apt, apt),
            vec![("sudo".into(), "1.9.16p2-3".into()), ("openssh-server".into(), "1:10.0p1-7".into())]
        );
        assert_eq!(parse_packages(OsType::Pacman, "sudo 1.9.16-1\nbash 5.2\n").len(), 2);
    }
}
