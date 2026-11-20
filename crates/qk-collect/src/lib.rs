//! Read-only agentless collectors. Scans never use sudo and never change the host.

use qk_core::host::OsType;
use qk_core::updates::{parse_apt_upgradable, parse_pacman_updates, PackageUpdate};
use qk_ssh::{Command, Connection, Result};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub updates: Vec<PackageUpdate>,
    pub reboot_required: bool,
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
    let reboot_required = conn.run(&reboot_check_command(os)).await?.success();
    Ok(ScanResult { updates, reboot_required })
}
