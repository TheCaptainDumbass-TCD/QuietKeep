# Changelog

QuietKeep follows semantic versioning. Versions below 1.0.0 are pre-release builds of the Rust rewrite.

## Unreleased

- Set up access button: enter a host password once and QuietKeep installs its key and optional sudoers rule. The password is never stored
- Hosts logged in as root run patch and reboot commands without sudo
- Remove button renamed to Delete host
- Host telemetry on the dashboard: load, memory, root disk and uptime with 24 hour and 7 day charts

## 0.2.0

- Package renamed to `quietkeep`
- About section in Settings with version, build, data folder and access key
- Patch scans for apt, Kali, Proxmox and pacman hosts
- Confirmed patching and rebooting through an exact command sudoers rule
- Docker inventory, image update checks and confirmed compose updates
- CISA KEV catalog with download permission and offline search
- Scheduled background scans and a tray scan action

## 0.1.0

- Tauri 2 desktop shell with tray, themes and single instance
- Host list with CSV import and export
- SSH host key pinning and app owned access key
