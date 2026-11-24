# Contributing to QuietKeep

Read this before changing code.

## Project

QuietKeep is a standalone desktop app for Debian 13 and Ubuntu that keeps a small to medium homelab patched and monitored. It runs entirely on the local machine with no external server. It is a fresh Rust rewrite. The older QuietKeep web app is reference only and is never modified.

- Author and maintainer: Dennis Ayotte <dennis@thecaptaindumbass.com>
- License: GPL-3.0-or-later
- Package name: `quietkeep`, app ID `dev.quietwire.quietkeep`
- Stack: Tauri 2 desktop shell, Leptos (Rust/WebAssembly) UI, SQLite storage, russh for SSH

## Ground rules

- Ask before every outbound, privileged or destructive action. Never assume the user agrees.
- Open no listening port. Connect out only to hosts the user adds and to downloads the user allows (CISA KEV, OSV fixed versions and container registries).
- Agentless SSH comes first. An optional host agent may come later.
- Managed hosts accept SSH keys only. Set up access logs in once through the user's ssh-agent. Password login is a fallback only.
- Never trust a host key automatically. A pinned fingerprint must match exactly or the connection is refused.
- QuietKeep's own SSH key is encrypted, and its passphrase lives in the desktop keyring.
- Read only scans never use sudo. Patching and rebooting use an exact command sudoers rule with no wildcards.
- Never store passwords. A sudo password typed during setup is used once and dropped.
- Never commit secrets, private keys or host lists.

## UI rules

- A button with nothing to do is disabled, grayed out and has a tooltip that says why.
- State is color coded: amber when a patch or reboot is needed, red for failures, green when work finishes.
- Destructive actions need typed confirmation. Delete host requires typing the host name.
- Long running work shows an amber status banner with a spinner.
- Every change must look right in both light and dark themes.

## Writing rules

These apply to docs, UI text, commit messages, changelog entries and package metadata.

- No em dashes or en dashes. Use commas, colons or separate sentences.
- No Oxford commas: write "A, B and C".
- American spelling: color, labeled, gray.
- Plain words and short sentences. User facing text says what will happen and why.

## Layout

| Crate | Purpose |
|---|---|
| `qk-core` | Shared domain types, validation, CSV and update parsers |
| `qk-store` | SQLite storage and migrations |
| `qk-ssh` | SSH transport, host key pinning, identity loading and ssh-agent login |
| `qk-collect` | Package, telemetry and Docker collectors, access setup, patch and reboot actions |
| `qk-intel` | CISA KEV catalog, OSV fixed versions and host matching |
| `qk-auth` | Desktop keyring storage for the SSH key passphrase |
| `qk-jobs` | Job runner (planned) |
| `quietkeep` | Tauri 2 desktop shell, commands, tray and scheduler |
| `qk-ui` | Leptos user interface |

## Build and test

```sh
cargo test --workspace --exclude qk-ui
cargo clippy --workspace --exclude qk-ui
cargo check -p qk-ui --target wasm32-unknown-unknown
cd crates/quietkeep && cargo tauri build
```

The package is written to `target/release/bundle/deb/`.

Things that have caused trouble before:

- In Leptos `view!` attributes, wrap an `if` expression that contains `>` in braces: `class={if n > 0 { "a" } else { "b" }}`.
- A Leptos `<For>` key must include every field that changes how a row looks, or the row will not update.
- Workspace path dependencies carry no version number, or a version bump breaks `cargo metadata`.
- Tauri command arguments arrive in camelCase, so frontend argument structs use `#[serde(rename_all = "camelCase")]`.
- On a headless test machine the window may never appear because GTK waits on the D-Bus session bus. Start the app inside `dbus-run-session` with `gnome-keyring-daemon` running.

## Database

SQLite with `user_version` migrations in `crates/qk-store/src/migrations`, currently `0001` to `0015`. Add a new numbered file and list it in `MIGRATIONS`. Never edit a migration that has shipped. QuietKeep refuses a database newer than it understands.

## Releases

Semantic versioning, 0.x during alpha. 1.0.0 will be the first release with packages.

1. Bump `version` in the root `Cargo.toml`.
2. Add a section to `CHANGELOG.md`.
3. Add a `<release>` entry to `crates/quietkeep/dev.quietwire.quietkeep.metainfo.xml`.
4. Run the tests, clippy and the WebAssembly check.
5. Commit, create an annotated tag `vX.Y.Z` and build the `.deb`.
6. Push `main` and the tag. No packages are published while QuietKeep is in alpha.

Installing a newer `.deb` with `sudo apt install ./quietkeep_X.Y.Z_amd64.deb` upgrades in place. A running copy shows a restart banner.

## Testing

- Each crate has unit tests. `crates/qk-collect/tests/local_sshd.rs` needs a local sshd test user.
- Never patch or reboot a real host during testing without the owner's go-ahead.
