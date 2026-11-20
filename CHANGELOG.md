# Changelog

QuietKeep follows semantic versioning. Versions below 1.0.0 are pre-release builds of the Rust rewrite.

## 0.6.1

- Docker: each host is its own bordered card with a colored header, and columns line up across hosts
- Docker: images pinned to a digest show Pinned, and Unknown now explains why on hover (docker buildx missing, locally built image or registry unreachable)
- Patches and Docker: the status line is a colored banner with a spinner while work runs, then green, amber or red when it finishes

## 0.6.0

- APT and Kali scans detect updates that `apt upgrade` holds back, either phased by Ubuntu or kept back for new dependencies. They show as "+N held" next to the pending count, are labeled in Details with an explanation and no longer count as patchable, so Patch is not offered for updates it cannot install

## 0.5.1

- Patches panel: Patch is amber when updates are pending and Reboot is amber when a reboot is needed. Both are disabled when there is nothing to do, and disabled buttons are clearly grayed out with a tooltip
- Set up access explains a read-only disk in plain words, does not rewrite ~/.ssh permissions that are already correct and clears an old error when you switch login method

## 0.5.0

- Set up all hosts: one approval trusts each reachable host's key and installs QuietKeep's key with your SSH key, with a result for every host
- Hosts where QuietKeep's own key works show Access ready instead of Set up access

## 0.4.2

- Set up access is one approval step: the fingerprint check no longer shows commands to run, and an optional detail covers checking it yourself
- Toolbar Access key button renamed to Show public key

## 0.4.1

- Hosts that are not set up yet show a Set up access button that verifies the host key and then installs QuietKeep's key
- Deleting a host requires typing its name to confirm

## 0.4.0

- Set up access can log in with your own SSH key through your ssh-agent, for hosts that only accept key logins. A password is only asked for as the sudo password when installing the sudoers rule
- QuietKeep's SSH key is encrypted, with its passphrase kept in the desktop keyring (GNOME Keyring or KWallet). Existing keys are encrypted in place on first start
- Shows a "QuietKeep was updated" banner with a Restart button after the package is upgraded while the app is running
- Panels section in Settings: show, hide and reorder sidebar panels

## 0.3.1

- Licensed under GPL-3.0-or-later
- Package shows the author, license and app name in software centers (AppStream metadata and Debian copyright file)

## 0.3.0

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
