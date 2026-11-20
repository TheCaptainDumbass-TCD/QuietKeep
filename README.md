# QuietKeep

Standalone desktop app for Debian 13 and Ubuntu that keeps a small to medium homelab patched and monitored. It runs entirely on the local machine with no external server.

## Status

Early development. First release is agentless (SSH). An optional agent is planned.

## Layout

| Crate | Purpose |
|---|---|
| `qk-core` | Shared domain types and validation |
| `qk-store` | Local SQLite storage and migrations |
| `qk-ssh` | SSH transport with host key pinning |
| `qk-collect` | Package, Docker and telemetry collectors |
| `qk-jobs` | Scheduler and job runner |
| `qk-auth` | Local unlock, secret storage and sessions |
| `qk-intel` | CISA KEV and threat data |

The desktop shell (Tauri 2) and Rust/WebAssembly UI are added in the next milestone.
