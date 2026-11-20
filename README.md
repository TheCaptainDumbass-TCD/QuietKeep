# QuietKeep

Standalone desktop app for Debian 13 and Ubuntu that keeps a small to medium homelab patched and monitored. It runs entirely on the local machine with no external server.

## Status

Early development. The first release is agentless and uses SSH. An optional agent is planned.

## Features

- Host list with CSV import and export in the original QuietKeep format
- SSH host key pinning with explicit approval and an app owned ed25519 key
- Read only patch scans for apt, Kali, Proxmox and pacman hosts
- Confirmed patching and rebooting through an exact command sudoers rule
- Docker inventory with registry digest checks and confirmed compose updates
- CISA KEV catalog with offline search, downloaded only after you allow it
- Scheduled background scans from the tray, off by default
- System, light and dark themes

## Security model

- QuietKeep opens no listening port. It only connects out to hosts you add.
- It never trusts a host key on its own. You approve each fingerprint, and a changed key blocks the connection.
- It uses its own SSH key, never your personal keys. You add its public key to each host yourself.
- Scans never use sudo. Patching and rebooting run only the commands listed in `/etc/sudoers.d/quietkeep`, which you install on each host. QuietKeep never asks for or stores sudo passwords.
- Every patch, reboot, container update and download asks for confirmation first.

## Install

```sh
sudo apt install ./quietkeep_0.2.0_amd64.deb
```

Tested on clean Debian 13 and Ubuntu 24.04 systems. Removing the package with `sudo apt remove quietkeep` leaves your data in place.

## Data

All data lives in `~/.local/share/dev.quietwire.quietkeep` with owner only permissions:

| File | Contents |
|---|---|
| `quietkeep.db` | Hosts, scan results, settings and activity log (SQLite) |
| `identity_ed25519` | QuietKeep's private SSH key |
| `cisa_kev.json` | Cached CISA KEV catalog |

The package never touches this folder. Delete it yourself to remove all QuietKeep data.

## Build

Requirements: Rust stable, the `wasm32-unknown-unknown` target, `trunk`, `tauri-cli` 2 and the Tauri Linux dependencies (WebKitGTK 4.1, GTK 3, Ayatana AppIndicator, librsvg).

```sh
cargo test --workspace --exclude qk-ui
cd crates/quietkeep && cargo tauri build
```

The package is written to `target/release/bundle/deb/`.

## Layout

| Crate | Purpose |
|---|---|
| `qk-core` | Shared domain types, validation, CSV and update parsers |
| `qk-store` | Local SQLite storage and migrations |
| `qk-ssh` | SSH transport with host key pinning |
| `qk-collect` | Package and Docker collectors, patch and reboot actions |
| `qk-intel` | CISA KEV catalog |
| `qk-jobs` | Job runner (planned) |
| `qk-auth` | Local unlock and secret storage (planned) |
| `quietkeep` | Tauri 2 desktop shell, tray and scheduler |
| `qk-ui` | Rust/WebAssembly user interface (Leptos) |
