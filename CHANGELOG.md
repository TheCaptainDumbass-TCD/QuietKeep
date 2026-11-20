# Changelog

QuietKeep follows semantic versioning. Versions below 1.0.0 are pre-release builds of the Rust rewrite.

## 0.10.0

- Docker: database containers with a new major release get a Details button. It explains why there is no one click upgrade, how a safe upgrade works and how long the current PostgreSQL version gets security fixes
- Docker: Snooze until next major hides that notice until a newer major release appears
- Docker: Clean up images on each host lists images no container uses, including stopped rollback copies, with their size. Only the images you select are removed with docker image rm. Volumes and containers are never touched
- Docker rows now refresh when only their update state changes

## 0.9.0

- Even spacing between sections on every page. The access key on Settings has its own section
- Security: click a CVE to see its description, required action and dates, with buttons that open its NVD or CVE.org page in your browser
- Hosts: Add host adds a single host. The OS column shows the release a host reports, such as Debian 13, Ubuntu 26.04 LTS or Proxmox VE 9.0. The SSH user moved into the host name tooltip
- Patches: filter hosts by operating system. Patch all installs updates on every host in the view one at a time after one confirmation and never reboots

## 0.8.1

- Rollback copies are listed under each host's table instead of inside it, with how long ago they stopped and a Remove button. After 30 days QuietKeep highlights them and asks whether to remove them. Removing a copy never touches data volumes
- When a registry cannot be reached or limits requests, QuietKeep keeps the last known result instead of showing Unknown
- Fewer registry requests for images with very large tag lists, which avoids ghcr.io rate limits

## 0.8.0

- Move pin: an image pinned to an older build can be pointed at the newest build of its tag, with a backup of the compose file
- Image tags set through a `.env` variable (such as Immich's `IMMICH_VERSION`) are updated in the `.env` file, after a backup
- Move to compose: a container started with `docker run` can be moved to a compose file built from its current settings. The preview hides environment values, settings QuietKeep cannot copy block the move, and the original container is kept stopped for rollback. If the new container does not start, the original is started again
- Stopped rollback copies show Kept for rollback instead of update actions
- Table row lines no longer break next to empty action cells

## 0.7.0

- Docker release tracking: with your permission QuietKeep reads tag lists and digests from the registries your images come from (Docker Hub, ghcr.io, quay.io, codeberg.org and others). It never logs in or pulls. A new release of the same kind of tag shows as "v0.13.4 available"
- Update to a new release: QuietKeep backs up the compose file, changes the one image line and then pulls and recreates the project
- Major releases are flagged. Database images (PostgreSQL, MySQL, MariaDB, MongoDB) never get a one click major upgrade because their data needs a migration
- Pinned images show whether the pin is still the newest build of its tag or has fallen behind
- Containers not started with docker compose show Update by hand instead of a button
- Results are cached for three hours and Docker Hub rate limits are explained, so scheduled scans stay within Docker Hub's hourly limit
- Rust 1.82 or newer is required to build

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
