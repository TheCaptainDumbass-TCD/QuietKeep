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
    /// When a stopped container stopped, as unix time.
    #[serde(default)]
    pub finished_at: Option<i64>,
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
            finished_at: None,
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
        .run(&Command::new("docker").args([
            "image",
            "inspect",
            image,
            "--format",
            "{{json .RepoDigests}}",
        ]))
        .await?;
    Ok(out
        .success()
        .then(|| serde_json::from_slice(&out.stdout).ok())
        .flatten())
}

async fn remote_digest(conn: &Connection, image: &str) -> Result<Option<String>> {
    let out = conn
        .run(&Command::new("docker").args([
            "buildx",
            "imagetools",
            "inspect",
            image,
            "--format",
            "{{json .Manifest.Digest}}",
        ]))
        .await?;
    Ok(out
        .success()
        .then(|| serde_json::from_slice::<String>(&out.stdout).ok())
        .flatten())
}

pub const NOTE_PINNED: &str =
    "Pinned to a fixed digest in its compose file, so it only changes when you edit that file.";
pub const NOTE_NO_BUILDX: &str = "docker buildx is not installed on this host, so the registry cannot be checked. Install the docker-buildx package (docker-buildx-plugin on Docker's own repository).";
pub const NOTE_NO_LOCAL: &str =
    "The local image has no registry digest. It was built locally or loaded from a file.";
pub const NOTE_REGISTRY: &str =
    "The registry could not be checked. It may be offline, private or rate limiting requests.";

/// The image reference the container was created from, which keeps an `@sha256:` pin that `docker ps` drops.
async fn container_details(
    conn: &Connection,
    container: &str,
) -> Result<(Option<String>, Option<i64>)> {
    let out = conn
        .run(&Command::new("docker").args([
            "inspect",
            container,
            "--format",
            "{{.Config.Image}}|{{.State.FinishedAt}}",
        ]))
        .await?;
    if !out.success() {
        return Ok((None, None));
    }
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let (image, finished) = text.split_once('|').unwrap_or((&text, ""));
    Ok((Some(image.to_string()), rfc3339_to_unix(finished)))
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parses Docker's UTC timestamps such as `2026-11-20T03:47:00.123456789Z`. Docker reports
/// `0001-01-01T00:00:00Z` for containers that never stopped, which maps to `None`.
pub fn rfc3339_to_unix(s: &str) -> Option<i64> {
    let n = |a: usize, b: usize| s.get(a..b)?.parse::<i64>().ok();
    let (y, mo, d, h, mi, se) = (
        n(0, 4)?,
        n(5, 7)?,
        n(8, 10)?,
        n(11, 13)?,
        n(14, 16)?,
        n(17, 19)?,
    );
    (y >= 1970).then(|| days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se)
}

/// Records each container's configured image and local digests. With `host_registry` set it
/// also asks the host's `docker buildx` for the registry digest, the fallback used when the
/// user has not allowed QuietKeep to contact registries itself.
pub async fn check_updates(
    conn: &Connection,
    containers: &mut [Container],
    host_registry: bool,
) -> Result<()> {
    let buildx = host_registry
        && conn
            .run(&Command::new("docker").args(["buildx", "version"]))
            .await?
            .success();
    let mut locals: HashMap<String, Vec<String>> = HashMap::new();
    let mut remotes: HashMap<String, Option<String>> = HashMap::new();
    for c in containers.iter_mut() {
        let (image, finished) = container_details(conn, &c.name).await?;
        c.configured_image = image;
        c.finished_at = finished;
        if !locals.contains_key(&c.image) {
            let l = local_digests(conn, &c.image).await?.unwrap_or_default();
            locals.insert(c.image.clone(), l);
        }
        c.local_digests = locals[&c.image].clone();
        let pinned = c.image.contains('@')
            || c.configured_image
                .as_deref()
                .is_some_and(|i| i.contains("@sha256:"));
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
            (false, Some(remote)) => {
                c.update_available = Some(!c.local_digests.iter().any(|d| d.ends_with(remote)))
            }
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

pub(crate) const SET_ENV_TAG: &str = r#"f=$1; repo=$2; old=$3; new=$4; e="$(dirname "$f")/.env"
var=$(grep -E '^[[:space:]]*image:' "$f" | grep -F "$repo:\${" | sed -n 's/.*:\${\([A-Za-z0-9_]*\).*/\1/p' | head -n 1)
[ -n "$var" ] || exit 4
[ -w "$e" ] || { echo "cannot write $e"; exit 3; }
grep -qxF "$var=$old" "$e" || { echo "$var in $e is not set to $old"; exit 4; }
bak="$e.quietkeep-$(date +%Y%m%d-%H%M%S).bak"
cp -p "$e" "$bak" && awk -v k="$var" -v o="$old" -v n="$new" '$0 == k "=" o { print k "=" n; next } { print }' "$bak" > "$e" && echo "$bak""#;

/// For images whose tag comes from a variable, such as `image: app:${APP_VERSION:-latest}`,
/// backs up the `.env` file next to the compose file and changes `APP_VERSION=<old>` to
/// `<new>`. Prints the backup path. Exits 4 when the image does not use a variable.
pub fn set_env_tag_command(file: &str, repository: &str, old_tag: &str, new_tag: &str) -> Command {
    Command::new("sh").args(["-c", SET_ENV_TAG, "sh", file, repository, old_tag, new_tag])
}

pub(crate) const MOVE_TO_COMPOSE: &str = r#"c=$1; restart=$2; d="$HOME/$c"; f="$d/compose.yaml"; old="$c-quietkeep-old"
[ -e "$f" ] && { echo "$f already exists"; exit 5; }
mkdir -p "$d" && (umask 077 && cat > "$f") || { echo "cannot write $f"; exit 6; }
docker compose -f "$f" config -q || { rm -f "$f"; echo "the generated compose file was rejected by docker compose"; exit 7; }
docker compose -f "$f" pull || { rm -f "$f"; echo "pulling the image failed"; exit 8; }
docker stop "$c" >/dev/null && docker rename "$c" "$old" && docker update --restart=no "$old" >/dev/null || { echo "could not stop $c"; exit 9; }
if docker compose -f "$f" up -d; then echo "$f"; echo "$old"; exit 0; fi
docker rm -f "$c" >/dev/null 2>&1; docker rename "$old" "$c"; docker update --restart="$restart" "$c" >/dev/null 2>&1; docker start "$c" >/dev/null
echo "starting the compose project failed, so the original container was started again"; exit 10"#;

/// Writes the compose file read from stdin to `~/<container>/compose.yaml`, pulls, stops the
/// container, renames it to `<container>-quietkeep-old` and starts the compose project. If the
/// project does not start, the original container is renamed back and started again.
pub fn move_to_compose_command(container: &str, restart_policy: &str) -> Command {
    Command::new("sh").args(["-c", MOVE_TO_COMPOSE, "sh", container, restart_policy])
}

pub async fn inspect(
    conn: &Connection,
    container: &str,
) -> Result<Option<(serde_json::Value, serde_json::Value)>> {
    let c = conn
        .run(&Command::new("docker").args(["inspect", container]))
        .await?;
    let Some(c) = c
        .success()
        .then(|| serde_json::from_slice::<serde_json::Value>(&c.stdout).ok())
        .flatten()
    else {
        return Ok(None);
    };
    let c = c.get(0).cloned().unwrap_or_default();
    let image_id = c["Image"].as_str().unwrap_or_default().to_string();
    let i = conn
        .run(&Command::new("docker").args(["image", "inspect", &image_id]))
        .await?;
    let i = i
        .success()
        .then(|| serde_json::from_slice::<serde_json::Value>(&i.stdout).ok())
        .flatten()
        .and_then(|v| v.get(0).cloned())
        .unwrap_or_default();
    Ok(Some((c, i)))
}

/// A compose file that recreates a `docker run` container, plus a copy with environment values
/// masked for display and the settings QuietKeep could not carry over.
#[derive(Debug, Clone, Serialize)]
pub struct ComposePlan {
    pub yaml: String,
    pub masked: String,
    pub unsupported: Vec<String>,
    pub restart: String,
}

fn yq(s: &str) -> String {
    format!(
        "\"{}\"",
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('$', "$$")
    )
}

fn strs(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

pub fn compose_from_inspect(c: &serde_json::Value, image: &serde_json::Value) -> ComposePlan {
    let hc = &c["HostConfig"];
    let cfg = &c["Config"];
    let icfg = &image["Config"];
    let name = c["Name"]
        .as_str()
        .unwrap_or_default()
        .trim_start_matches('/')
        .to_string();
    let mut unsupported = Vec::new();
    if hc["Privileged"].as_bool() == Some(true) {
        unsupported.push("privileged mode".to_string());
    }
    for (key, label) in [
        ("CapAdd", "added capabilities"),
        ("Devices", "devices"),
        ("DeviceRequests", "GPU or device requests"),
        ("SecurityOpt", "security options"),
        ("Links", "container links"),
        ("Tmpfs", "tmpfs mounts"),
        ("Dns", "custom DNS servers"),
    ] {
        if hc[key].as_array().is_some_and(|a| !a.is_empty())
            || hc[key].as_object().is_some_and(|o| !o.is_empty())
        {
            unsupported.push(label.to_string());
        }
    }
    if hc["Sysctls"].as_object().is_some_and(|o| !o.is_empty()) {
        unsupported.push("sysctls".to_string());
    }
    let network = hc["NetworkMode"].as_str().unwrap_or("default").to_string();
    if !["default", "bridge", "host"].contains(&network.as_str()) {
        unsupported.push(format!("the {network} network"));
    }
    let restart = hc["RestartPolicy"]["Name"]
        .as_str()
        .filter(|r| !r.is_empty())
        .unwrap_or("no")
        .to_string();
    let base_env: Vec<String> = strs(&icfg["Env"]);
    let env: Vec<String> = strs(&cfg["Env"])
        .into_iter()
        .filter(|e| !base_env.contains(e))
        .collect();
    let mut out = vec!["services:".to_string(), format!("  {name}:")];
    out.push(format!(
        "    image: {}",
        yq(cfg["Image"].as_str().unwrap_or_default())
    ));
    out.push(format!("    container_name: {}", yq(&name)));
    out.push(format!("    restart: {}", yq(&restart)));
    if network == "host" {
        out.push("    network_mode: host".into());
    }
    let mut ports = Vec::new();
    if let Some(map) = hc["PortBindings"].as_object() {
        for (container_port, binds) in map {
            for b in binds.as_array().cloned().unwrap_or_default() {
                let ip = b["HostIp"].as_str().unwrap_or_default();
                let hp = b["HostPort"].as_str().unwrap_or_default();
                ports.push(if ip.is_empty() {
                    format!("{hp}:{container_port}")
                } else {
                    format!("{ip}:{hp}:{container_port}")
                });
            }
        }
    }
    if !ports.is_empty() && network != "host" {
        out.push("    ports:".into());
        out.extend(ports.iter().map(|p| format!("      - {}", yq(p))));
    }
    let mut named = Vec::new();
    let mut vols = Vec::new();
    for m in c["Mounts"].as_array().cloned().unwrap_or_default() {
        let dest = m["Destination"].as_str().unwrap_or_default();
        let ro = if m["RW"].as_bool() == Some(false) {
            ":ro"
        } else {
            ""
        };
        match m["Type"].as_str() {
            Some("volume") => {
                let n = m["Name"].as_str().unwrap_or_default().to_string();
                vols.push(format!("{n}:{dest}{ro}"));
                named.push(n);
            }
            Some("bind") => vols.push(format!(
                "{}:{dest}{ro}",
                m["Source"].as_str().unwrap_or_default()
            )),
            Some(other) => unsupported.push(format!("{other} mounts")),
            None => {}
        }
    }
    if !vols.is_empty() {
        out.push("    volumes:".into());
        out.extend(vols.iter().map(|v| format!("      - {}", yq(v))));
    }
    let hosts = strs(&hc["ExtraHosts"]);
    if !hosts.is_empty() {
        out.push("    extra_hosts:".into());
        out.extend(hosts.iter().map(|h| format!("      - {}", yq(h))));
    }
    let list = |v: &[String]| {
        format!(
            "[{}]",
            v.iter().map(|x| yq(x)).collect::<Vec<_>>().join(", ")
        )
    };
    let cmd = strs(&cfg["Cmd"]);
    if !cmd.is_empty() && cmd != strs(&icfg["Cmd"]) {
        out.push(format!("    command: {}", list(&cmd)));
    }
    let ep = strs(&cfg["Entrypoint"]);
    if !ep.is_empty() && ep != strs(&icfg["Entrypoint"]) {
        out.push(format!("    entrypoint: {}", list(&ep)));
    }
    if let Some(u) = cfg["User"]
        .as_str()
        .filter(|u| !u.is_empty() && Some(*u) != icfg["User"].as_str())
    {
        out.push(format!("    user: {}", yq(u)));
    }
    let head = out.join("\n");
    let tail = {
        let mut t = Vec::new();
        if !named.is_empty() {
            t.push("volumes:".to_string());
            for n in &named {
                t.push(format!("  {n}:"));
                t.push("    external: true".into());
            }
        }
        t.join("\n")
    };
    let env_block = |mask: bool| {
        if env.is_empty() {
            return String::new();
        }
        let mut b = vec!["\n    environment:".to_string()];
        for e in &env {
            let (k, v) = e.split_once('=').unwrap_or((e, ""));
            b.push(format!(
                "      {k}: {}",
                if mask {
                    "\"********\"".to_string()
                } else {
                    yq(v)
                }
            ));
        }
        b.join("\n")
    };
    let build = |mask: bool| format!("{head}{}\n{tail}\n", env_block(mask));
    ComposePlan {
        yaml: build(false),
        masked: build(true),
        unsupported,
        restart,
    }
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
            return Ok(ActionReport {
                success: false,
                output_tail: crate::tail(&log),
            });
        }
    }
    Ok(ActionReport {
        success: true,
        output_tail: crate::tail(&log),
    })
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
        assert_eq!(
            cmds[0].as_str(),
            "docker compose -f '/srv/my app/compose.yaml' pull"
        );
        assert_eq!(
            cmds[1].as_str(),
            "docker compose -f '/srv/my app/compose.yaml' up -d"
        );
    }
}

#[cfg(test)]
mod set_image_tests {
    use super::SET_IMAGE;

    fn run(file: &std::path::Path, old: &str, new: &str) -> std::process::Output {
        std::process::Command::new("sh")
            .args(["-c", SET_IMAGE, "sh"])
            .arg(file)
            .args([old, new])
            .output()
            .unwrap()
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

#[cfg(test)]
mod compose_tests {
    use super::compose_from_inspect;

    #[test]
    fn builds_compose_from_docker_run() {
        let c = serde_json::json!({
            "Name": "/open-webui",
            "Config": {"Image": "ghcr.io/open-webui/open-webui:v0.12.3", "Env": ["PATH=/usr/bin", "PORT=8080", "SECRET=a$b"], "Cmd": ["bash", "start.sh"]},
            "HostConfig": {"NetworkMode": "host", "RestartPolicy": {"Name": "always"}, "ExtraHosts": ["host.docker.internal:127.0.0.1"], "PortBindings": {}},
            "Mounts": [{"Type": "volume", "Name": "open-webui", "Destination": "/app/backend/data", "RW": true}]
        });
        let i =
            serde_json::json!({"Config": {"Env": ["PATH=/usr/bin"], "Cmd": ["bash", "start.sh"]}});
        let p = compose_from_inspect(&c, &i);
        assert!(p.unsupported.is_empty());
        assert!(p.yaml.contains("    network_mode: host\n"));
        assert!(p
            .yaml
            .contains("      - \"open-webui:/app/backend/data\"\n"));
        assert!(p.yaml.contains("      SECRET: \"a$$b\""));
        assert!(!p.masked.contains("a$$b"));
        assert!(p
            .yaml
            .contains("volumes:\n  open-webui:\n    external: true"));
        assert!(!p.yaml.contains("command:"));
        assert_eq!(p.restart, "always");
    }

    #[test]
    fn flags_unsupported_settings() {
        let c = serde_json::json!({"Name": "/x", "Config": {"Image": "x"}, "HostConfig": {"Privileged": true, "Devices": [{"PathOnHost": "/dev/dri"}], "NetworkMode": "mynet"}, "Mounts": []});
        let p = compose_from_inspect(&c, &serde_json::json!({}));
        assert_eq!(p.unsupported.len(), 3);
    }
}

#[cfg(test)]
mod time_tests {
    #[test]
    fn parses_docker_times() {
        assert_eq!(
            super::rfc3339_to_unix("2026-11-20T03:47:00.123Z"),
            Some(1795146420)
        );
        assert_eq!(super::rfc3339_to_unix("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(super::rfc3339_to_unix("0001-01-01T00:00:00Z"), None);
    }
}

/// An image that no container on the host uses, so removing it frees disk space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnusedImage {
    pub id: String,
    pub repository: String,
    pub tag: String,
    pub size: String,
    pub created: String,
}

#[derive(Deserialize)]
struct ImageLine {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "Repository", default)]
    repository: String,
    #[serde(rename = "Tag", default)]
    tag: String,
    #[serde(rename = "Size", default)]
    size: String,
    #[serde(rename = "CreatedSince", default)]
    created: String,
}

/// True for a full image ID such as `sha256:` followed by 64 hex digits.
pub fn valid_image_id(id: &str) -> bool {
    id.strip_prefix("sha256:").is_some_and(|h| {
        h.len() == 64
            && h.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    })
}

fn parse_images(out: &str, used: &std::collections::HashSet<String>) -> Vec<UnusedImage> {
    let mut seen = std::collections::HashSet::new();
    out.lines()
        .filter_map(|l| serde_json::from_str::<ImageLine>(l.trim()).ok())
        .filter(|i| valid_image_id(&i.id) && !used.contains(&i.id) && seen.insert(i.id.clone()))
        .map(|i| UnusedImage {
            id: i.id,
            repository: i.repository,
            tag: i.tag,
            size: i.size,
            created: i.created,
        })
        .collect()
}

/// Lists images that no container, running or stopped, uses. Read only.
pub async fn unused_images(
    conn: &Connection,
) -> Result<std::result::Result<Vec<UnusedImage>, String>> {
    let ids = conn
        .run(&Command::new("docker").args(["container", "ls", "-a", "-q", "--no-trunc"]))
        .await?;
    if !ids.success() {
        return Ok(Err(String::from_utf8_lossy(&ids.stderr).trim().to_string()));
    }
    let ids: Vec<String> = String::from_utf8_lossy(&ids.stdout)
        .split_whitespace()
        .map(str::to_string)
        .collect();
    let mut used = std::collections::HashSet::new();
    if !ids.is_empty() {
        let mut cmd =
            Command::new("docker").args(["container", "inspect", "--format", "{{.Image}}"]);
        for id in &ids {
            cmd = cmd.arg(id);
        }
        let out = conn.run(&cmd).await?;
        if !out.success() {
            return Ok(Err(String::from_utf8_lossy(&out.stderr).trim().to_string()));
        }
        used.extend(
            String::from_utf8_lossy(&out.stdout)
                .split_whitespace()
                .map(str::to_string),
        );
    }
    let out = conn
        .run(&Command::new("docker").args(["image", "ls", "--no-trunc", "--format", "{{json .}}"]))
        .await?;
    if !out.success() {
        return Ok(Err(String::from_utf8_lossy(&out.stderr).trim().to_string()));
    }
    Ok(Ok(parse_images(
        &String::from_utf8_lossy(&out.stdout),
        &used,
    )))
}

#[cfg(test)]
mod image_tests {
    use super::*;

    #[test]
    fn unused_images_skip_used_and_invalid_ids() {
        let a = format!("sha256:{}", "a".repeat(64));
        let b = format!("sha256:{}", "b".repeat(64));
        let out = format!(
            "{{\"ID\":\"{a}\",\"Repository\":\"nginx\",\"Tag\":\"1.27\",\"Size\":\"190MB\",\"CreatedSince\":\"3 weeks ago\"}}\n\
             {{\"ID\":\"{b}\",\"Repository\":\"nginx\",\"Tag\":\"1.28\",\"Size\":\"192MB\",\"CreatedSince\":\"2 days ago\"}}\n\
             {{\"ID\":\"sha256:bad; rm -rf /\",\"Repository\":\"x\",\"Tag\":\"y\"}}\n"
        );
        let used = std::collections::HashSet::from([b.clone()]);
        let images = parse_images(&out, &used);
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].id, a);
        assert_eq!(images[0].tag, "1.27");
        assert!(!valid_image_id("sha256:ABC"));
    }
}
