use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use qk_core::host::HostSpec;
use qk_core::host_csv::{self, ImportReport};
use qk_ssh::{Command, PrivateKey, SshError, Target, TrustPolicy};
use qk_core::updates::PackageUpdate;
use qk_store::{Activity, Host, PatchStatus, Store};
use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::{DialogExt, FilePath};

pub struct AppState {
    pub store: Mutex<Store>,
    pub identity: Arc<PrivateKey>,
    /// Host keys seen by `probe_host_key` that the user has not yet approved.
    pub pending_keys: Mutex<HashMap<i64, String>>,
}

const SSH_TIMEOUT: Duration = Duration::from_secs(10);

type CmdResult<T> = Result<T, String>;

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

pub fn store<'a>(state: &'a State<'_, AppState>) -> std::sync::MutexGuard<'a, Store> {
    state.store.lock().unwrap_or_else(|p| p.into_inner())
}

#[derive(Serialize)]
pub struct AppInfo {
    name: &'static str,
    version: &'static str,
}

#[tauri::command]
pub fn app_info() -> AppInfo {
    AppInfo { name: "QuietKeep", version: env!("CARGO_PKG_VERSION") }
}

#[tauri::command]
pub fn list_hosts(state: State<'_, AppState>) -> CmdResult<Vec<Host>> {
    store(&state).list_hosts().map_err(err)
}

#[tauri::command]
pub fn add_host(state: State<'_, AppState>, spec: HostSpec) -> CmdResult<i64> {
    store(&state).add_host(&spec).map_err(err)
}

#[tauri::command]
pub fn delete_host(state: State<'_, AppState>, id: i64) -> CmdResult<bool> {
    store(&state).delete_host(id).map_err(err)
}

#[tauri::command]
pub fn recent_activity(state: State<'_, AppState>) -> CmdResult<Vec<Activity>> {
    store(&state).recent_activity(50).map_err(err)
}

fn local_path(path: FilePath) -> CmdResult<std::path::PathBuf> {
    path.into_path().map_err(err)
}

/// Asks the user for a CSV and returns a preview. Nothing is stored until `commit_import`.
#[tauri::command]
pub async fn pick_import_csv(app: AppHandle, state: State<'_, AppState>) -> CmdResult<Option<ImportReport>> {
    let Some(path) = app
        .dialog()
        .file()
        .set_title("Import hosts")
        .add_filter("CSV", &["csv"])
        .blocking_pick_file()
    else {
        return Ok(None);
    };
    let file = File::open(local_path(path)?).map_err(err)?;
    let existing: HashSet<String> = store(&state).host_names().map_err(err)?.into_iter().collect();
    host_csv::import(file, &existing).map(Some).map_err(err)
}

#[tauri::command]
pub fn commit_import(state: State<'_, AppState>, hosts: Vec<HostSpec>) -> CmdResult<usize> {
    store(&state).add_hosts(&hosts).map_err(err)
}

#[tauri::command]
pub async fn export_hosts_csv(app: AppHandle, state: State<'_, AppState>) -> CmdResult<Option<usize>> {
    let Some(path) = app
        .dialog()
        .file()
        .set_title("Export hosts")
        .set_file_name("quietkeep-hosts.csv")
        .add_filter("CSV", &["csv"])
        .blocking_save_file()
    else {
        return Ok(None);
    };
    let hosts: Vec<HostSpec> = store(&state).list_hosts().map_err(err)?.into_iter().map(|h| h.spec).collect();
    let file = File::create(local_path(path)?).map_err(err)?;
    host_csv::export(file, &hosts).map_err(err)?;
    Ok(Some(hosts.len()))
}

fn host(state: &State<'_, AppState>, id: i64) -> CmdResult<Host> {
    store(state).get_host(id).map_err(err)?.ok_or_else(|| "Host not found.".to_string())
}

fn target(h: &Host) -> Target {
    Target { address: h.spec.address.clone(), port: 22, username: h.spec.username.clone() }
}

#[derive(Serialize)]
pub struct HostKeyProbe {
    fingerprint: String,
    algorithm: String,
    changed_from: Option<String>,
}

/// Connects far enough to read the host's SSH key so the user can review it.
#[tauri::command]
pub async fn probe_host_key(state: State<'_, AppState>, id: i64) -> CmdResult<HostKeyProbe> {
    let h = host(&state, id)?;
    let policy = match &h.host_key {
        Some(fp) => TrustPolicy::Pinned(fp.clone()),
        None => TrustPolicy::Discover,
    };
    let probe = match qk_ssh::connect(&target(&h), state.identity.clone(), policy, SSH_TIMEOUT).await {
        Err(SshError::UnknownHostKey { fingerprint, algorithm }) => {
            HostKeyProbe { fingerprint, algorithm, changed_from: None }
        }
        Err(SshError::HostKeyMismatch { expected, actual }) => {
            HostKeyProbe { fingerprint: actual, algorithm: String::new(), changed_from: Some(expected) }
        }
        Err(SshError::AuthFailed(_)) | Ok(_) => return Err("This host key is already trusted.".into()),
        Err(e) => return Err(e.to_string()),
    };
    state
        .pending_keys
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(id, probe.fingerprint.clone());
    Ok(probe)
}

/// Pins a host key the user approved. Only a key QuietKeep itself just observed can be trusted.
#[tauri::command]
pub fn trust_host_key(state: State<'_, AppState>, id: i64, fingerprint: String) -> CmdResult<bool> {
    let pending = state.pending_keys.lock().unwrap_or_else(|p| p.into_inner()).remove(&id);
    if pending.as_deref() != Some(fingerprint.as_str()) {
        return Err("That key does not match what QuietKeep saw. Verify the host again.".into());
    }
    store(&state).set_host_key(id, &fingerprint).map_err(err)
}

#[tauri::command]
pub async fn test_connection(state: State<'_, AppState>, id: i64) -> CmdResult<String> {
    let h = host(&state, id)?;
    let Some(fp) = h.host_key.clone() else {
        return Err("Verify this host's key first.".into());
    };
    let conn = match qk_ssh::connect(&target(&h), state.identity.clone(), TrustPolicy::Pinned(fp), SSH_TIMEOUT).await {
        Ok(c) => c,
        Err(SshError::AuthFailed(user)) => {
            return Err(format!("Login as {user} was refused. Add QuietKeep's access key to that user's authorized_keys."))
        }
        Err(e) => return Err(e.to_string()),
    };
    let out = conn.run(&Command::new("uname").arg("-sr")).await.map_err(err)?;
    let _ = conn.close().await;
    if !out.success() {
        return Err(format!("uname exited with {:?}", out.exit_status));
    }
    let system = String::from_utf8_lossy(&out.stdout).trim().to_string();
    store(&state)
        .log_activity("host.connected", Some(id), &format!("Connected to {} ({system})", h.spec.name))
        .map_err(err)?;
    Ok(system)
}

#[tauri::command]
pub fn client_public_key(state: State<'_, AppState>) -> CmdResult<String> {
    qk_ssh::public_key_openssh(&state.identity).map_err(err)
}

#[tauri::command]
pub fn patch_status(state: State<'_, AppState>) -> CmdResult<Vec<PatchStatus>> {
    store(&state).patch_status().map_err(err)
}

#[tauri::command]
pub fn pending_updates(state: State<'_, AppState>, id: i64) -> CmdResult<Vec<PackageUpdate>> {
    store(&state).pending_updates(id).map_err(err)
}

/// Read-only scan of one trusted host: pending updates and whether a reboot is needed.
async fn scan_one(app: &AppHandle, h: Host) -> CmdResult<()> {
    let state = app.state::<AppState>();
    let Some(fp) = h.host_key.clone() else {
        return Err("Verify this host's key first.".into());
    };
    let identity = state.identity.clone();
    let result: qk_ssh::Result<qk_collect::ScanResult> = async {
        let conn = qk_ssh::connect(&target(&h), identity, TrustPolicy::Pinned(fp), SSH_TIMEOUT).await?;
        let scanned = qk_collect::scan(&conn, h.spec.os_type).await;
        let _ = conn.close().await;
        scanned
    }
    .await;
    match result {
        Ok(r) => {
            let security = r.updates.iter().filter(|u| u.security).count();
            let mut s = store(&state);
            s.record_scan(h.id, &r.updates, r.reboot_required).map_err(err)?;
            let reboot = if r.reboot_required { ", reboot required" } else { "" };
            s.log_activity(
                "scan.completed",
                Some(h.id),
                &format!("Scanned {}: {} updates ({security} security){reboot}", h.spec.name, r.updates.len()),
            )
            .map_err(err)?;
            Ok(())
        }
        Err(e) => {
            let msg = match e {
                SshError::AuthFailed(user) => format!("Login as {user} was refused. Install QuietKeep's access key."),
                other => other.to_string(),
            };
            let mut s = store(&state);
            s.record_scan_error(h.id, &msg).map_err(err)?;
            s.log_activity("scan.failed", Some(h.id), &format!("Scan of {} failed: {msg}", h.spec.name))
                .map_err(err)?;
            Err(msg)
        }
    }
}

#[tauri::command]
pub async fn scan_host(app: AppHandle, id: i64) -> CmdResult<bool> {
    let h = store(&app.state::<AppState>())
        .get_host(id)
        .map_err(err)?
        .ok_or_else(|| "Host not found.".to_string())?;
    scan_one(&app, h).await.map(|_| true)
}

#[derive(Serialize)]
pub struct ScanSummary {
    scanned: u32,
    failed: u32,
    skipped: u32,
}

/// Scans every host whose key the user has trusted. Hosts without a trusted key are skipped.
pub async fn scan_trusted(app: &AppHandle) -> CmdResult<ScanSummary> {
    let hosts = store(&app.state::<AppState>()).list_hosts().map_err(err)?;
    let (trusted, untrusted): (Vec<Host>, Vec<Host>) = hosts.into_iter().partition(|h| h.host_key.is_some());
    let tasks: Vec<_> = trusted
        .into_iter()
        .map(|h| {
            let app = app.clone();
            tauri::async_runtime::spawn(async move { scan_one(&app, h).await.is_ok() })
        })
        .collect();
    let mut summary = ScanSummary { scanned: 0, failed: 0, skipped: untrusted.len() as u32 };
    for task in tasks {
        if task.await.unwrap_or(false) {
            summary.scanned += 1;
        } else {
            summary.failed += 1;
        }
    }
    crate::scheduler::update_tray_tooltip(app);
    Ok(summary)
}

#[tauri::command]
pub async fn scan_all(app: AppHandle) -> CmdResult<ScanSummary> {
    scan_trusted(&app).await
}

pub const SCAN_INTERVAL_KEY: &str = "scan.interval_minutes";
pub const SCAN_INTERVALS: [u32; 5] = [0, 60, 360, 720, 1440];

pub fn scan_interval(state: &State<'_, AppState>) -> u32 {
    store(state)
        .get_setting(SCAN_INTERVAL_KEY)
        .ok()
        .flatten()
        .and_then(|v| v.parse().ok())
        .filter(|v| SCAN_INTERVALS.contains(v))
        .unwrap_or(0)
}

#[tauri::command]
pub fn get_scan_interval(state: State<'_, AppState>) -> u32 {
    scan_interval(&state)
}

/// Background scans stay off until the user picks an interval here.
#[tauri::command]
pub fn set_scan_interval(state: State<'_, AppState>, minutes: u32) -> CmdResult<u32> {
    if !SCAN_INTERVALS.contains(&minutes) {
        return Err("Unsupported scan interval.".into());
    }
    let s = store(&state);
    s.set_setting(SCAN_INTERVAL_KEY, &minutes.to_string()).map_err(err)?;
    let msg = match minutes {
        0 => "Turned off scheduled scans".to_string(),
        60 => "Scheduled scans every hour".to_string(),
        m => format!("Scheduled scans every {} hours", m / 60),
    };
    s.log_activity("settings.scan_interval", None, &msg).map_err(err)?;
    Ok(minutes)
}

fn parse_action(action: &str) -> CmdResult<qk_collect::Action> {
    match action {
        "patch" => Ok(qk_collect::Action::Patch),
        "reboot" => Ok(qk_collect::Action::Reboot),
        _ => Err("Unknown action.".into()),
    }
}

async fn connect_trusted(app: &AppHandle, h: &Host) -> CmdResult<qk_ssh::Connection> {
    let Some(fp) = h.host_key.clone() else {
        return Err("Verify this host's key first.".into());
    };
    let identity = app.state::<AppState>().identity.clone();
    qk_ssh::connect(&target(h), identity, TrustPolicy::Pinned(fp), SSH_TIMEOUT).await.map_err(|e| match e {
        SshError::AuthFailed(user) => format!("Login as {user} was refused. Install QuietKeep's access key."),
        other => other.to_string(),
    })
}

#[derive(Serialize)]
pub struct PrivilegeCheck {
    allowed: bool,
    commands: Vec<String>,
    rule: String,
    sudoers_path: &'static str,
}

/// Shows the user exactly which root commands an action runs and whether the host's sudoers allows them.
#[tauri::command]
pub async fn check_privileged(app: AppHandle, id: i64, action: String) -> CmdResult<PrivilegeCheck> {
    let action = parse_action(&action)?;
    let h = host(&app.state::<AppState>(), id)?;
    let os = h.spec.os_type;
    let conn = connect_trusted(&app, &h).await?;
    let allowed = qk_collect::sudo_allowed(&conn, os, action).await.map_err(err);
    let _ = conn.close().await;
    Ok(PrivilegeCheck {
        allowed: allowed?,
        commands: qk_collect::privileged_commands(os, action)
            .into_iter()
            .map(|argv| format!("sudo {}", qk_collect::display_command(argv)))
            .collect(),
        rule: qk_collect::sudoers_rule(&h.spec.username, os),
        sudoers_path: qk_collect::SUDOERS_PATH,
    })
}

/// Runs a confirmed patch or reboot. The UI calls this only after the user approves the listed commands.
#[tauri::command]
pub async fn run_action(app: AppHandle, id: i64, action: String) -> CmdResult<String> {
    let action = parse_action(&action)?;
    let h = host(&app.state::<AppState>(), id)?;
    let name = h.spec.name.clone();
    let conn = connect_trusted(&app, &h).await?;
    let result = qk_collect::run_action(&conn, h.spec.os_type, action).await;
    let _ = conn.close().await;
    let state = app.state::<AppState>();
    match (action, result) {
        (qk_collect::Action::Reboot, _) => {
            store(&state).log_activity("host.reboot", Some(id), &format!("Reboot requested for {name}")).map_err(err)?;
            Ok(format!("Reboot requested for {name}."))
        }
        (qk_collect::Action::Patch, Ok(report)) if report.success => {
            store(&state).log_activity("patch.completed", Some(id), &format!("Applied updates on {name}")).map_err(err)?;
            let _ = scan_one(&app, h).await;
            update_tray(&app);
            Ok(format!("Applied updates on {name}."))
        }
        (qk_collect::Action::Patch, Ok(report)) => {
            let last = report.output_tail.lines().last().unwrap_or("").to_string();
            store(&state)
                .log_activity("patch.failed", Some(id), &format!("Updates failed on {name}: {last}"))
                .map_err(err)?;
            Err(format!("Updates failed on {name}: {last}"))
        }
        (qk_collect::Action::Patch, Err(e)) => {
            store(&state)
                .log_activity("patch.failed", Some(id), &format!("Updates failed on {name}: {e}"))
                .map_err(err)?;
            Err(e.to_string())
        }
    }
}

fn update_tray(app: &AppHandle) {
    crate::scheduler::update_tray_tooltip(app);
}

#[tauri::command]
pub fn docker_status(state: State<'_, AppState>) -> CmdResult<Vec<qk_store::DockerHost>> {
    store(&state).docker_status().map_err(err)
}

async fn docker_one(app: &AppHandle, h: Host) -> CmdResult<()> {
    let result = async {
        let conn = connect_trusted(app, &h).await?;
        let r = async {
            let mut containers = qk_collect::docker::inventory(&conn).await?;
            qk_collect::docker::check_updates(&conn, &mut containers).await?;
            Ok::<_, qk_ssh::SshError>(containers)
        }
        .await
        .map_err(err);
        let _ = conn.close().await;
        r
    }
    .await;
    let state = app.state::<AppState>();
    let mut s = store(&state);
    match result {
        Ok(containers) => {
            let rows: Vec<qk_store::ContainerRow> = containers
                .into_iter()
                .map(|c| qk_store::ContainerRow {
                    name: c.name,
                    image: c.image,
                    state: c.state,
                    status: c.status,
                    project: c.project,
                    service: c.service,
                    config_file: c.config_file,
                    update_available: c.update_available,
                })
                .collect();
            let updates = rows.iter().filter(|c| c.update_available == Some(true)).count();
            s.record_docker(h.id, &rows).map_err(err)?;
            s.log_activity(
                "docker.scan",
                Some(h.id),
                &format!("Docker on {}: {} containers, {updates} image updates", h.spec.name, rows.len()),
            )
            .map_err(err)?;
            Ok(())
        }
        Err(e) => {
            s.record_docker_error(h.id, &e).map_err(err)?;
            Err(e)
        }
    }
}

#[tauri::command]
pub async fn scan_docker(app: AppHandle, id: i64) -> CmdResult<bool> {
    let h = host(&app.state::<AppState>(), id)?;
    docker_one(&app, h).await.map(|_| true)
}

/// Scans Docker hosts whose key is trusted. Read-only: nothing is pulled or restarted.
#[tauri::command]
pub async fn scan_docker_all(app: AppHandle) -> CmdResult<ScanSummary> {
    let hosts = store(&app.state::<AppState>()).list_hosts().map_err(err)?;
    let (trusted, untrusted): (Vec<Host>, Vec<Host>) =
        hosts.into_iter().filter(|h| h.spec.has_docker).partition(|h| h.host_key.is_some());
    let tasks: Vec<_> = trusted
        .into_iter()
        .map(|h| {
            let app = app.clone();
            tauri::async_runtime::spawn(async move { docker_one(&app, h).await.is_ok() })
        })
        .collect();
    let mut summary = ScanSummary { scanned: 0, failed: 0, skipped: untrusted.len() as u32 };
    for task in tasks {
        if task.await.unwrap_or(false) {
            summary.scanned += 1;
        } else {
            summary.failed += 1;
        }
    }
    Ok(summary)
}

fn compose_file(state: &State<'_, AppState>, id: i64, project: &str) -> CmdResult<String> {
    store(state)
        .docker_status()
        .map_err(err)?
        .into_iter()
        .find(|h| h.host_id == id)
        .and_then(|h| h.containers.into_iter().find(|c| c.project.as_deref() == Some(project)))
        .and_then(|c| c.config_file)
        .ok_or_else(|| "No compose file is known for this project. Scan the host again.".into())
}

/// The exact commands an update runs, shown to the user before they confirm.
#[tauri::command]
pub fn compose_update_preview(state: State<'_, AppState>, id: i64, project: String) -> CmdResult<Vec<String>> {
    let file = compose_file(&state, id, &project)?;
    Ok(qk_collect::docker::compose_update_commands(&file).iter().map(|c| c.as_str().to_string()).collect())
}

#[tauri::command]
pub async fn update_compose(app: AppHandle, id: i64, project: String) -> CmdResult<String> {
    let h = host(&app.state::<AppState>(), id)?;
    let file = compose_file(&app.state::<AppState>(), id, &project)?;
    let name = h.spec.name.clone();
    let conn = connect_trusted(&app, &h).await?;
    let result = qk_collect::docker::update_compose(&conn, &file).await;
    let _ = conn.close().await;
    let outcome = match result {
        Ok(r) if r.success => Ok(format!("Updated {project} on {name}.")),
        Ok(r) => Err(format!(
            "Updating {project} on {name} failed: {}",
            r.output_tail.lines().last().unwrap_or("")
        )),
        Err(e) => Err(format!("Updating {project} on {name} failed: {e}")),
    };
    let msg = match &outcome {
        Ok(m) | Err(m) => m.clone(),
    };
    let kind = if outcome.is_ok() { "docker.update" } else { "docker.update_failed" };
    store(&app.state::<AppState>()).log_activity(kind, Some(id), &msg).map_err(err)?;
    let _ = docker_one(&app, h).await;
    outcome
}
