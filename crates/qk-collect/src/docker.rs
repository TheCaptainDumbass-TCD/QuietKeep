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

/// Fills `update_available` for each container by comparing local and registry digests.
pub async fn check_updates(conn: &Connection, containers: &mut [Container]) -> Result<()> {
    let mut results: HashMap<String, Option<bool>> = HashMap::new();
    for c in containers.iter() {
        if results.contains_key(&c.image) {
            continue;
        }
        let verdict = if c.image.contains('@') {
            None
        } else {
            match (local_digests(conn, &c.image).await?, remote_digest(conn, &c.image).await?) {
                (Some(local), Some(remote)) => Some(!local.iter().any(|d| d.ends_with(&remote))),
                _ => None,
            }
        };
        results.insert(c.image.clone(), verdict);
    }
    for c in containers.iter_mut() {
        c.update_available = results.get(&c.image).copied().flatten();
    }
    Ok(())
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
