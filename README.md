# QuietKeep

Standalone desktop app for Debian 13 and Ubuntu that keeps a small to medium homelab patched and monitored. It runs entirely on the local machine with no external server.

## Status

Early development (0.8.x). QuietKeep is agentless and uses SSH. An optional host agent is planned. Version 1.0.0 will be the first public release.

## Features

- Host list with CSV import and export in the original QuietKeep format
- SSH host key pinning with explicit approval and an app owned ed25519 key
- One click Set up access for a single host or all hosts, using your own SSH key through ssh-agent
- Read only patch scans for apt, Kali, Proxmox and pacman hosts
- Held back apt updates (phased by Ubuntu or kept back) shown apart from installable ones
- Host telemetry charts for load, memory, root disk and uptime
- Confirmed patching and rebooting through an exact command sudoers rule
- Docker inventory with release tracking, pin moves, `.env` tag updates, moving `docker run` containers to compose and confirmed compose updates
- CISA KEV catalog with offline search, downloaded only after you allow it
- Scheduled background scans from the tray, off by default
- Panels you can hide and reorder
- System, light and dark themes

## Security model

- QuietKeep opens no listening port. It only connects out to hosts you add.
- It never trusts a host key on its own. You approve each fingerprint, and a changed key blocks the connection.
- It uses its own SSH key for all normal work. Set up access logs in once with your own key through ssh-agent and installs QuietKeep's key. Your private keys never leave the agent.
- QuietKeep's private key is encrypted, and its passphrase is kept in the desktop keyring (GNOME Keyring or KWallet).
- Scans never use sudo. Patching and rebooting run only the commands listed in `/etc/sudoers.d/quietkeep`. Set up access can install that rule with a sudo password you type once. QuietKeep never stores passwords.
- Every patch, reboot, container update and download asks for confirmation first. Registry checks for Docker images run only after you allow them.

## Install

```sh
sudo apt install ./quietkeep_0.8.0_amd64.deb
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
| `qk-auth` | Desktop keyring storage for the SSH key passphrase |
| `quietkeep` | Tauri 2 desktop shell, tray and scheduler |
| `qk-ui` | Rust/WebAssembly user interface (Leptos) |

## Upgrading

Install the newer package the same way. apt sees that `quietkeep` is already installed and upgrades it in place, so there is no need to remove the old version first. Hosts, trusted keys and settings are kept.

```sh
sudo apt install ./quietkeep_0.8.0_amd64.deb
```

If QuietKeep is running in the tray during the upgrade, it shows a "QuietKeep was updated" banner. Click Restart to switch to the new version, or choose Quit from the tray menu and start it again.

## License

Copyright (C) 2026 Dennis Ayotte

QuietKeep is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License or (at your option) any later version. See [LICENSE](LICENSE).
