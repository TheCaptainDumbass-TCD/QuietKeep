//! Docker inventory and image update checks. Checks are read-only: they compare the local
//! image digest with the registry digest without pulling anything.

use std::collections::HashMap;

use qk_ssh::{Command, Connection, Result};
use serde::{Deserialize, Serialize};

use crate::ActionReport;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Container {
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
    pub project: Option<String>,
    pub service: Option<String>,
    pub config_file: Option<String>,
    /// `None` when the registry could not be checked or the image is pinned by digest.
    pub update_available: Option<bool>,
    /// Plain-language reason when `update_available` is `None`.
    #[serde(default)]
    pub update_note: Option<String>,
    /// Registry digests of the local image (`repo@sha256:...`).
    #[serde(default)]
    pub local_digests: Vec<String>,
    /// Image reference the container was created from, including any `@sha256:` pin.
    #[serde(default)]
    pub configured_image: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct PsLine {
    names: String,
    image: String,
    state: String,
    status: String,
    #[serde(default)]
    labels: String,
}

fn label(labels: &str, key: &str) -> Option<String> {
    labels
        .split(',')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.to_string())
        .filter(|v| !v.is_empty())
}

/// Parses `docker ps -a --format '{{json .}}'`, one JSON object per line.
pub fn parse_ps(output: &str) -> Vec<Container> {
    output
        .lines()
        .filter_map(|l| serde_json::from_str::<PsLine>(l.trim()).ok())
        .map(|p| Container {
            name: p.names,
            image: p.image,
            state: p.state,
            status: p.status,
            project: label(&p.labels, "com.docker.compose.project"),
            service: label(&p.labels, "com.docker.compose.service"),
            config_file: label(&p.labels, "com.docker.compose.project.config_files"),
            update_available: None,
            update_note: None,
            local_digests: Vec::new(),
            configured_image: None,
        })
        .collect()
}

pub async fn inventory(conn: &Connection) -> Result<Vec<Container>> {
    let out = conn
        .run(&Command::new("docker").args(["ps", "-a", "--format", "{{json .}}"]))
        .await?;
    Ok(parse_ps(&String::from_utf8_lossy(&out.stdout)))
}

async fn local_digests(conn: &Connection, image: &str) -> Result<Option<Vec<String>>> {
    let out = conn
        .run(&Command::new("docker").args(["image", "inspect", image, "--format", "{{json .RepoDigests}}"]))
        .await?;
    Ok(out.success().then(|| serde_json::from_slice(&out.stdout).ok()).flatten())
}

async fn remote_digest(conn: &Connection, image: &str) -> Result<Option<String>> {
    let out = conn
        .run(&Command::new("docker").args([
            "buildx", "imagetools", "inspect", image, "--format", "{{json .Manifest.Digest}}",
        ]))
        .await?;
    Ok(out.success().then(|| serde_json::from_slice::<String>(&out.stdout).ok()).flatten())
}

pub const NOTE_PINNED: &str =
    "Pinned to a fixed digest in its compose file, so it only changes when you edit that file.";
pub const NOTE_NO_BUILDX: &str = "docker buildx is not installed on this host, so the registry cannot be checked. Install the docker-buildx package (docker-buildx-plugin on Docker's own repository).";
pub const NOTE_NO_LOCAL: &str = "The local image has no registry digest. It was built locally or loaded from a file.";
pub const NOTE_REGISTRY: &str = "The registry could not be checked. It may be offline, private or rate limiting requests.";

/// The image reference the container was created from, which keeps an `@sha256:` pin that `docker ps` drops.
async fn configured_image(conn: &Connection, container: &str) -> Result<Option<String>> {
    let out = conn
        .run(&Command::new("docker").args(["inspect", container, "--format", "{{.Config.Image}}"]))
        .await?;
    Ok(out.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string()))
}

/// Records each container's configured image and local digests. With `host_registry` set it
/// also asks the host's `docker buildx` for the registry digest, the fallback used when the
/// user has not allowed QuietKeep to contact registries itself.
pub async fn check_updates(conn: &Connection, containers: &mut [Container], host_registry: bool) -> Result<()> {
    let buildx = host_registry && conn.run(&Command::new("docker").args(["buildx", "version"])).await?.success();
    let mut locals: HashMap<String, Vec<String>> = HashMap::new();
    let mut remotes: HashMap<String, Option<String>> = HashMap::new();
    for c in containers.iter_mut() {
        c.configured_image = configured_image(conn, &c.name).await?;
        if !locals.contains_key(&c.image) {
            let l = local_digests(conn, &c.image).await?.unwrap_or_default();
            locals.insert(c.image.clone(), l);
        }
        c.local_digests = locals[&c.image].clone();
        let pinned = c.image.contains('@') || c.configured_image.as_deref().is_some_and(|i| i.contains("@sha256:"));
        if pinned {
            c.update_available = None;
            c.update_note = Some(NOTE_PINNED.into());
            continue;
        }
        if !host_registry {
            continue;
        }
        if !buildx {
            c.update_note = Some(NOTE_NO_BUILDX.into());
            continue;
        }
        if !remotes.contains_key(&c.image) {
            let r = remote_digest(conn, &c.image).await?;
            remotes.insert(c.image.clone(), r);
        }
        match (c.local_digests.is_empty(), &remotes[&c.image]) {
            (false, Some(remote)) => c.update_available = Some(!c.local_digests.iter().any(|d| d.ends_with(remote))),
            (true, _) => c.update_note = Some(NOTE_NO_LOCAL.into()),
            (false, None) => c.update_note = Some(NOTE_REGISTRY.into()),
        }
    }
    Ok(())
}

pub(crate) const SET_IMAGE: &str = r#"f=$1; old=$2; new=$3
[ -w "$f" ] || { echo "cannot write $f"; exit 3; }
tmp="$f.quietkeep-tmp"
awk -v old="$old" -v new="$new" 'BEGIN { sq = sprintf("%c", 39) }
{ line = $0
  if (match(line, /^[ \t]*image:[ \t]*/)) {
    pre = substr(line, 1, RLENGTH); val = substr(line, RLENGTH + 1); sub(/[ \t]+$/, "", val); q = ""
    a = substr(val, 1, 1); z = substr(val, length(val), 1)
    if (length(val) > 1 && a == z && (a == "\"" || a == sq)) { q = a; val = substr(val, 2, length(val) - 2) }
    if (val == old) { line = pre q new q; c++ }
  }
  print line }
END { exit c ? 0 : 4 }' "$f" > "$tmp" || { rc=$?; rm -f "$tmp"; exit $rc; }
bak="$f.quietkeep-$(date +%Y%m%d-%H%M%S).bak"
cp -p "$f" "$bak" && cat "$tmp" > "$f" && rm -f "$tmp" && echo "$bak""#;

/// Backs up a compose file, then changes every `image: <old>` line to `image: <new>`. Prints the
/// backup path. Exits 3 when the file is not writable and 4 when no line matches exactly.
pub fn set_image_command(file: &str, old: &str, new: &str) -> Command {
    Command::new("sh").args(["-c", SET_IMAGE, "sh", file, old, new])
}

pub fn compose_update_commands(config_file: &str) -> Vec<Command> {
    vec![
        Command::new("docker").args(["compose", "-f", config_file, "pull"]),
        Command::new("docker").args(["compose", "-f", config_file, "up", "-d"]),
    ]
}

/// Pulls new images for a compose project and recreates changed containers. No sudo is used.
pub async fn update_compose(conn: &Connection, config_file: &str) -> Result<ActionReport> {
    let mut log = Vec::new();
    for cmd in compose_update_commands(config_file) {
        let out = conn.run(&cmd).await?;
        log.extend_from_slice(&out.stdout);
        log.extend_from_slice(&out.stderr);
        if !out.success() {
            return Ok(ActionReport { success: false, output_tail: crate::tail(&log) });
        }
    }
    Ok(ActionReport { success: true, output_tail: crate::tail(&log) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ps() {
        let out = r#"{"Image":"nginx:alpine","Labels":"com.docker.compose.project=web,com.docker.compose.project.config_files=/srv/web/compose.yaml,com.docker.compose.service=web","Names":"web-web-1","State":"running","Status":"Up 2 hours"}
{"Image":"redis:7","Labels":"","Names":"cache","State":"exited","Status":"Exited (0) 3 days ago"}
not json"#;
        let c = parse_ps(out);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].project.as_deref(), Some("web"));
        assert_eq!(c[0].config_file.as_deref(), Some("/srv/web/compose.yaml"));
        assert_eq!(c[0].service.as_deref(), Some("web"));
        assert_eq!(c[1].project, None);
        assert_eq!(c[1].state, "exited");
    }

    #[test]
    fn compose_commands_are_quoted() {
        let cmds = compose_update_commands("/srv/my app/compose.yaml");
        assert_eq!(cmds[0].as_str(), "docker compose -f '/srv/my app/compose.yaml' pull");
        assert_eq!(cmds[1].as_str(), "docker compose -f '/srv/my app/compose.yaml' up -d");
    }
}

#[cfg(test)]
mod set_image_tests {
    use super::SET_IMAGE;

    fn run(file: &std::path::Path, old: &str, new: &str) -> std::process::Output {
        std::process::Command::new("sh").args(["-c", SET_IMAGE, "sh"]).arg(file).args([old, new]).output().unwrap()
    }

    #[test]
    fn replaces_exact_image_lines_with_backup() {
        let dir = std::env::temp_dir().join(format!("qk-set-image-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("compose.yaml");
        std::fs::write(&f, "services:\n  web:\n    image: \"nginx:1.26.0\"\n  other:\n    image: nginx:1.26.0-alpine\n").unwrap();
        let out = run(&f, "nginx:1.26.0", "nginx:1.26.3");
        assert!(out.status.success());
        let backup = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert!(std::path::Path::new(&backup).exists());
        let text = std::fs::read_to_string(&f).unwrap();
        assert!(text.contains("    image: \"nginx:1.26.3\"\n"));
        assert!(text.contains("image: nginx:1.26.0-alpine"));
        assert_eq!(run(&f, "nginx:9.9", "nginx:10").status.code(), Some(4));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
