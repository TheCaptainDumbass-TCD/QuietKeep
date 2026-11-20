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
    pub key_protection: String,
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
    commit: &'static str,
    identifier: String,
    platform: String,
    data_dir: String,
    schema_version: i64,
    key_protection: String,
}

#[tauri::command]
pub fn app_info(app: AppHandle, state: State<'_, AppState>) -> AppInfo {
    AppInfo {
        name: "QuietKeep",
        version: env!("CARGO_PKG_VERSION"),
        commit: env!("QK_BUILD_COMMIT"),
        identifier: app.config().identifier.clone(),
        platform: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        data_dir: app.path().app_data_dir().map(|p| p.display().to_string()).unwrap_or_default(),
        schema_version: store(&state).schema_version().unwrap_or(0),
        key_protection: state.key_protection.clone(),
    }
}

#[tauri::command]
pub fn list_hosts(state: State<'_, AppState>) -> CmdResult<Vec<Host>> {
    store(&state).list_hosts().map_err(err)
}

#[tauri::command]
pub fn add_host(state: State<'_, AppState>, spec: HostSpec) -> CmdResult<i64> {
    spec.validate().map_err(err)?;
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
            let _ = store(&state).set_access_ok(id, false);
            return Err(format!("Login as {user} was refused. Click Set up access to install QuietKeep's key."))
        }
        Err(e) => return Err(e.to_string()),
    };
    let out = conn.run(&Command::new("uname").arg("-sr")).await.map_err(err)?;
    let _ = conn.close().await;
    if !out.success() {
        return Err(format!("uname exited with {:?}", out.exit_status));
    }
    let system = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let _ = store(&state).set_access_ok(id, true);
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
        if scanned.is_ok() {
            if let Ok(Some(t)) = qk_collect::telemetry::collect(&conn).await {
                record_telemetry(app, h.id, &t);
            }
        }
        let _ = conn.close().await;
        scanned
    }
    .await;
    match result {
        Ok(r) => {
            let security = r.updates.iter().filter(|u| u.security).count();
            let mut s = store(&state);
            s.record_scan(h.id, &r.updates, r.reboot_required).map_err(err)?;
            s.record_packages(h.id, &r.packages).map_err(err)?;
            if let Some((os_id, os_version)) = &r.os_release {
                s.record_os_release(h.id, os_id, os_version).map_err(err)?;
            }
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
    let result = qk_ssh::connect(&target(h), identity, TrustPolicy::Pinned(fp), SSH_TIMEOUT).await;
    match &result {
        Ok(_) => { let _ = store(&app.state::<AppState>()).set_access_ok(h.id, true); }
        Err(SshError::AuthFailed(_)) => { let _ = store(&app.state::<AppState>()).set_access_ok(h.id, false); }
        Err(_) => {}
    }
    result.map_err(|e| match e {
        SshError::AuthFailed(user) => format!("Login as {user} was refused. Click Set up access to install QuietKeep's key."),
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
    let as_root = h.spec.username == "root";
    let allowed = qk_collect::sudo_allowed(&conn, os, action, as_root).await.map_err(err);
    let _ = conn.close().await;
    Ok(PrivilegeCheck {
        allowed: allowed?,
        commands: qk_collect::privileged_commands(os, action)
            .into_iter()
            .map(|argv| {
                let cmd = qk_collect::display_command(argv);
                if as_root { cmd } else { format!("sudo {cmd}") }
            })
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
    let result = qk_collect::run_action(&conn, h.spec.os_type, action, h.spec.username == "root").await;
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

const REGISTRY_ALLOWED_KEY: &str = "registry.allowed";

fn registry_choice(state: &State<'_, AppState>) -> Option<bool> {
    match store(state).get_setting(REGISTRY_ALLOWED_KEY).ok().flatten().as_deref() {
        Some("1") => Some(true),
        Some("0") => Some(false),
        _ => None,
    }
}

/// Whether the user allowed QuietKeep to contact container registries: `None` until they choose.
#[tauri::command]
pub fn registry_state(state: State<'_, AppState>) -> Option<bool> {
    registry_choice(&state)
}

#[tauri::command]
pub fn registry_set_allowed(state: State<'_, AppState>, allowed: bool) -> CmdResult<bool> {
    let s = store(&state);
    s.set_setting(REGISTRY_ALLOWED_KEY, if allowed { "1" } else { "0" }).map_err(err)?;
    let msg = if allowed { "Allowed registry checks for Docker images" } else { "Turned off registry checks for Docker images" };
    s.log_activity("settings.registry", None, msg).map_err(err)?;
    Ok(allowed)
}

async fn assess_all(containers: &[qk_collect::docker::Container]) -> Vec<Option<qk_intel::registry::Assessment>> {
    let inputs: Vec<(String, Vec<String>)> = containers
        .iter()
        .map(|c| (c.configured_image.clone().unwrap_or_else(|| c.image.clone()), c.local_digests.clone()))
        .collect();
    let n = inputs.len();
    tauri::async_runtime::spawn_blocking(move || {
        let mut client = qk_intel::registry::Client::new();
        let mut cache = std::collections::HashMap::new();
        inputs
            .into_iter()
            .map(|key| {
                Some(
                    cache
                        .entry(key.clone())
                        .or_insert_with(|| qk_intel::registry::assess_cached(&mut client, &key.0, &key.1))
                        .clone(),
                )
            })
            .collect::<Vec<_>>()
    })
    .await
    .unwrap_or_else(|_| vec![None; n])
}

async fn docker_one(app: &AppHandle, h: Host) -> CmdResult<()> {
    let registry = registry_choice(&app.state::<AppState>()) == Some(true);
    // Results of the last scan, reused when a registry cannot be reached this time.
    let previous: std::collections::HashMap<(String, String), qk_store::ContainerRow> = store(&app.state::<AppState>())
        .docker_status()
        .ok()
        .and_then(|v| v.into_iter().find(|x| x.host_id == h.id))
        .map(|x| x.containers.into_iter().map(|c| ((c.name.clone(), c.image.clone()), c)).collect())
        .unwrap_or_default();
    let result = async {
        let conn = connect_trusted(app, &h).await?;
        let r = async {
            let mut containers = qk_collect::docker::inventory(&conn).await?;
            qk_collect::docker::check_updates(&conn, &mut containers, !registry).await?;
            Ok::<_, qk_ssh::SshError>(containers)
        }
        .await
        .map_err(err);
        let _ = conn.close().await;
        r
    }
    .await;
    let result = match result {
        Ok(c) => {
            let a = if registry { assess_all(&c).await } else { vec![None; c.len()] };
            Ok((c, a))
        }
        Err(e) => Err(e),
    };
    let state = app.state::<AppState>();
    let mut s = store(&state);
    match result {
        Ok((containers, assessments)) => {
            let rows: Vec<qk_store::ContainerRow> = containers
                .into_iter()
                .zip(assessments)
                .map(|(c, a)| {
                    let mut row = qk_store::ContainerRow {
                        name: c.name,
                        image: c.image,
                        state: c.state,
                        status: c.status,
                        project: c.project,
                        service: c.service,
                        config_file: c.config_file,
                        update_available: c.update_available,
                        update_note: c.update_note,
                        update_kind: None,
                        latest_tag: None,
                        major_tag: None,
                        configured_image: c.configured_image,
                        latest_digest: None,
                        finished_at: c.finished_at,
                        stopped_days: None,
                        snoozed: false,
                    };
                    let a = a.and_then(|a| {
                        let known = |k: &Option<String>| k.as_deref().is_some_and(|k| k != "unknown");
                        match previous.get(&(row.name.clone(), row.image.clone())) {
                            Some(p) if a.kind == "unknown" && known(&p.update_kind) => {
                                row.update_available = p.update_available;
                                row.update_note = p.update_note.clone();
                                row.update_kind = p.update_kind.clone();
                                row.latest_tag = p.latest_tag.clone();
                                row.major_tag = p.major_tag.clone();
                                row.latest_digest = p.latest_digest.clone();
                                None
                            }
                            _ => Some(a),
                        }
                    });
                    if let Some(a) = a {
                        row.latest_digest = a.digest;
                        row.update_available = a.update_available;
                        row.update_note = a.note;
                        row.update_kind = Some(a.kind.to_string());
                        row.latest_tag = a.latest_tag;
                        row.major_tag = a.major_tag;
                    }
                    row
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

const KEV_ALLOWED_KEY: &str = "kev.allowed";

fn kev_cache(app: &AppHandle) -> CmdResult<std::path::PathBuf> {
    Ok(app.path().app_data_dir().map_err(err)?.join("cisa_kev.json"))
}

fn kev_allowed(state: &State<'_, AppState>) -> bool {
    store(state).get_setting(KEV_ALLOWED_KEY).ok().flatten().as_deref() == Some("1")
}

#[derive(Serialize)]
pub struct KevState {
    allowed: bool,
    summary: Option<qk_intel::Summary>,
}

#[tauri::command]
pub fn kev_state(app: AppHandle, state: State<'_, AppState>) -> CmdResult<KevState> {
    let summary = qk_intel::load_cache(&kev_cache(&app)?)
        .map_err(err)?
        .map(|c| qk_intel::summarize(&c, &qk_intel::today_utc()));
    Ok(KevState { allowed: kev_allowed(&state), summary })
}

/// Records the user's choice about downloading the CISA KEV feed from cisa.gov.
#[tauri::command]
pub fn kev_set_allowed(state: State<'_, AppState>, allowed: bool) -> CmdResult<bool> {
    let s = store(&state);
    s.set_setting(KEV_ALLOWED_KEY, if allowed { "1" } else { "0" }).map_err(err)?;
    let msg = if allowed { "Allowed CISA KEV downloads from cisa.gov" } else { "Turned off CISA KEV downloads" };
    s.log_activity("settings.kev", None, msg).map_err(err)?;
    Ok(allowed)
}

#[tauri::command]
pub async fn kev_refresh(app: AppHandle) -> CmdResult<qk_intel::Summary> {
    if !kev_allowed(&app.state::<AppState>()) {
        return Err("Allow CISA KEV downloads first.".into());
    }
    let path = kev_cache(&app)?;
    let catalog = tauri::async_runtime::spawn_blocking(move || {
        let bytes = qk_intel::download()?;
        qk_intel::save_cache(&path, &bytes)?;
        qk_intel::parse(&bytes)
    })
    .await
    .map_err(err)?
    .map_err(err)?;
    let summary = qk_intel::summarize(&catalog, &qk_intel::today_utc());
    store(&app.state::<AppState>())
        .log_activity(
            "kev.refresh",
            None,
            &format!("Downloaded CISA KEV {} ({} entries)", summary.catalog_version, summary.total),
        )
        .map_err(err)?;
    Ok(summary)
}

#[tauri::command]
pub fn kev_search(app: AppHandle, filter: qk_intel::Filter) -> CmdResult<Vec<qk_intel::Vulnerability>> {
    Ok(qk_intel::load_cache(&kev_cache(&app)?)
        .map_err(err)?
        .map(|c| qk_intel::filter(&c, &filter, 200))
        .unwrap_or_default())
}

/// Catalog entries whose product is installed on a saved host, from the package lists
/// and container images collected by earlier scans. Uses only local data.
#[tauri::command]
pub fn kev_affected(app: AppHandle, state: State<'_, AppState>) -> CmdResult<Vec<qk_intel::affected::Affected>> {
    let Some(catalog) = qk_intel::load_cache(&kev_cache(&app)?).map_err(err)? else {
        return Ok(Vec::new());
    };
    let s = store(&state);
    let packages: Vec<qk_intel::affected::HostPkg> = s
        .all_packages()
        .map_err(err)?
        .into_iter()
        .map(|p| qk_intel::affected::HostPkg {
            host_id: p.host_id,
            host: p.host,
            os_id: p.os_id,
            os_version: p.os_version,
            name: p.package.name,
            version: p.package.version,
            source: p.package.source,
            source_version: p.package.source_version,
        })
        .collect();
    let images: Vec<(i64, String, String)> = s
        .docker_status()
        .map_err(err)?
        .into_iter()
        .flat_map(|h| {
            let (id, name) = (h.host_id, h.name);
            h.containers.into_iter().map(move |c| (id, name.clone(), c.image))
        })
        .collect();
    let pending = s.pending_packages().map_err(err)?;
    let osv = qk_intel::osv::load_cache(&osv_cache(&app)?).map_err(err)?;
    Ok(qk_intel::affected::affected(&catalog, &packages, &images, &pending, osv.as_ref()))
}

const OSV_ALLOWED_KEY: &str = "osv.allowed";

fn osv_cache(app: &AppHandle) -> CmdResult<std::path::PathBuf> {
    Ok(app.path().app_data_dir().map_err(err)?.join("osv_fixed_versions.json"))
}

fn osv_allowed(state: &State<'_, AppState>) -> bool {
    store(state).get_setting(OSV_ALLOWED_KEY).ok().flatten().as_deref() == Some("1")
}

#[derive(Serialize)]
pub struct OsvState {
    allowed: bool,
    fetched_at: Option<String>,
    checked: usize,
}

#[tauri::command]
pub fn osv_state(app: AppHandle, state: State<'_, AppState>) -> CmdResult<OsvState> {
    let cache = qk_intel::osv::load_cache(&osv_cache(&app)?).map_err(err)?;
    Ok(OsvState {
        allowed: osv_allowed(&state),
        fetched_at: cache.as_ref().map(|c| c.fetched_at.clone()),
        checked: cache.map(|c| c.cves.len()).unwrap_or(0),
    })
}

/// Records the user's choice about looking up fixed versions at api.osv.dev.
#[tauri::command]
pub fn osv_set_allowed(state: State<'_, AppState>, allowed: bool) -> CmdResult<bool> {
    let s = store(&state);
    s.set_setting(OSV_ALLOWED_KEY, if allowed { "1" } else { "0" }).map_err(err)?;
    let msg = if allowed { "Allowed fixed version lookups at api.osv.dev" } else { "Turned off fixed version lookups" };
    s.log_activity("settings.osv", None, msg).map_err(err)?;
    Ok(allowed)
}

/// Looks up the Debian and Ubuntu fixed versions for the catalog CVEs QuietKeep can match.
/// Sends only public CVE IDs.
#[tauri::command]
pub async fn osv_refresh(app: AppHandle) -> CmdResult<usize> {
    if !osv_allowed(&app.state::<AppState>()) {
        return Err("Allow fixed version lookups first.".into());
    }
    let Some(catalog) = qk_intel::load_cache(&kev_cache(&app)?).map_err(err)? else {
        return Err("Download the CISA KEV catalog first.".into());
    };
    let path = osv_cache(&app)?;
    let cves = qk_intel::affected::trackable_cves(&catalog);
    let count = tauri::async_runtime::spawn_blocking(move || {
        let cache = qk_intel::osv::fetch(&cves, &qk_intel::today_utc())?;
        qk_intel::osv::save_cache(&path, &cache)?;
        Ok::<_, qk_intel::IntelError>(cache.cves.len())
    })
    .await
    .map_err(err)?
    .map_err(err)?;
    store(&app.state::<AppState>())
        .log_activity("osv.refresh", None, &format!("Looked up fixed versions for {count} CVEs at api.osv.dev"))
        .map_err(err)?;
    Ok(count)
}

fn record_telemetry(app: &AppHandle, id: i64, t: &qk_collect::telemetry::Telemetry) {
    let at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let sample = qk_store::MetricSample {
        at,
        load1: t.load1,
        cpus: t.cpus,
        mem_used_pct: t.mem_used_pct,
        disk_used_pct: t.disk_used_pct,
        uptime_s: t.uptime_s,
    };
    let _ = store(&app.state::<AppState>()).record_metrics(id, &sample, &t.kernel, &t.os_name);
}

/// Telemetry samples from the last `hours` hours (capped at the 7 day retention).
#[tauri::command]
pub fn metrics(state: State<'_, AppState>, hours: u32) -> CmdResult<Vec<qk_store::HostMetrics>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let window = (hours.min(168) as i64) * 3600;
    store(&state).metrics_since(now - window).map_err(err)
}

#[derive(Serialize)]
pub struct AccessPreview {
    steps: Vec<String>,
    public_key: String,
    rule: Option<String>,
}

#[tauri::command]
pub fn setup_access_preview(
    state: State<'_, AppState>,
    id: i64,
    use_agent: bool,
    install_sudoers: bool,
) -> CmdResult<AccessPreview> {
    let h = host(&state, id)?;
    let as_root = h.spec.username == "root";
    let install_sudoers = install_sudoers && !as_root;
    Ok(AccessPreview {
        steps: qk_collect::access::describe(use_agent, install_sudoers, as_root),
        public_key: qk_ssh::public_key_openssh(&state.identity).map_err(err)?,
        rule: install_sudoers.then(|| qk_collect::sudoers_rule(&h.spec.username, h.spec.os_type)),
    })
}

/// Logs in once with the user's ssh-agent or password to install QuietKeep's key (and optionally
/// the sudoers rule). Requires a trusted host key. The password is dropped when this returns.
#[tauri::command]
pub async fn setup_access(
    app: AppHandle,
    id: i64,
    use_agent: bool,
    password: String,
    install_sudoers: bool,
) -> CmdResult<String> {
    let state = app.state::<AppState>();
    let h = host(&state, id)?;
    let Some(fp) = h.host_key.clone() else {
        return Err("Verify this host's key first.".into());
    };
    let name = h.spec.name.clone();
    let as_root = h.spec.username == "root";
    let public_key = qk_ssh::public_key_openssh(&state.identity).map_err(err)?;
    let connected = if use_agent {
        qk_ssh::connect_with_agent(&target(&h), fp, SSH_TIMEOUT).await
    } else {
        qk_ssh::connect_with_password(&target(&h), password.clone(), fp, SSH_TIMEOUT).await
    };
    let conn = connected.map_err(|e| match e {
        SshError::AuthFailed(user) if use_agent => {
            format!("{name} refused every key in your ssh-agent for {user}. Check that your own key can log in to this host.")
        }
        SshError::AuthFailed(user) => format!("The password for {user} was refused, or password login is disabled on {name}."),
        other => other.to_string(),
    })?;
    let result = async {
        let key = qk_collect::access::install_key(&conn, &public_key).await.map_err(err)?;
        if !key.success {
            let detail = key.output_tail.lines().last().unwrap_or("");
            if detail.contains("Read-only file system") {
                return Err(format!(
                    "{name}'s disk is mounted read-only, so QuietKeep cannot add its key. Make the filesystem writable and try again."
                ));
            }
            return Err(format!("Could not add the key: {detail}"));
        }
        if install_sudoers && !as_root {
            let rule = qk_collect::sudoers_rule(&h.spec.username, h.spec.os_type);
            let r = qk_collect::access::install_sudoers(&conn, &rule, &password, as_root).await.map_err(err)?;
            if !r.success {
                return Err(format!(
                    "The key was added, but the sudoers rule was not installed: {}",
                    r.output_tail.lines().last().unwrap_or("sudo refused")
                ));
            }
        }
        Ok(())
    }
    .await;
    drop(password);
    let _ = conn.close().await;
    let sudo_note = if install_sudoers && !as_root { " and sudoers rule" } else { "" };
    match result {
        Ok(()) => {
            store(&app.state::<AppState>())
                .log_activity("host.access_setup", Some(id), &format!("Installed access key{sudo_note} on {name}"))
                .map_err(err)?;
            let check = connect_trusted(&app, &h).await?;
            let _ = check.close().await;
            Ok(format!("{name} is ready. QuietKeep can now log in with its own key."))
        }
        Err(e) => {
            store(&app.state::<AppState>())
                .log_activity("host.access_failed", Some(id), &format!("Access setup on {name} failed: {e}"))
                .map_err(err)?;
            Err(e)
        }
    }
}

/// True when the package was upgraded while this copy kept running: the executable on disk
/// was replaced, so `/proc/self/exe` points at a deleted file.
#[tauri::command]
pub fn update_pending() -> bool {
    std::fs::read_link("/proc/self/exe")
        .map(|p| p.to_string_lossy().ends_with(" (deleted)"))
        .unwrap_or(false)
}

#[tauri::command]
pub fn restart_app(app: AppHandle) {
    app.restart();
}

#[derive(Serialize)]
pub struct TagUpdatePreview {
    file: String,
    old_image: String,
    new_image: String,
    major: bool,
    commands: Vec<String>,
}

fn image_repository(image: &str) -> String {
    let base = image.split('@').next().unwrap_or(image);
    let slash = base.rfind('/');
    match base.rfind(':') {
        Some(c) if slash.is_none_or(|s| c > s) => base[..c].to_string(),
        _ => base.to_string(),
    }
}

fn image_tag(image: &str) -> String {
    qk_intel::registry::parse_ref(image).map(|r| r.tag).unwrap_or_default()
}

fn container_row(state: &State<'_, AppState>, id: i64, container: &str) -> CmdResult<qk_store::ContainerRow> {
    store(state)
        .docker_status()
        .map_err(err)?
        .into_iter()
        .find(|h| h.host_id == id)
        .and_then(|h| h.containers.into_iter().find(|c| c.name == container))
        .ok_or_else(|| "This container is not in the last scan. Scan the host again.".to_string())
}

fn compose_file_of(row: &qk_store::ContainerRow) -> CmdResult<String> {
    row.config_file.clone().ok_or_else(|| {
        "This container was not started with docker compose. Use Move to compose first.".to_string()
    })
}

/// Compose file, current image and new image for moving a container to a newer release.
fn tag_update_target(state: &State<'_, AppState>, id: i64, container: &str, major: bool) -> CmdResult<(String, String, String)> {
    let row = container_row(state, id, container)?;
    let file = compose_file_of(&row)?;
    let tag = if major { row.major_tag.clone() } else { row.latest_tag.clone() }
        .ok_or_else(|| "No newer release is known. Scan the host again.".to_string())?;
    if major && qk_intel::registry::is_database(&image_repository(&row.image)) {
        return Err("Database major upgrades need a data migration, so QuietKeep does not do them. Follow the image's upgrade guide.".into());
    }
    let new_image = format!("{}:{tag}", image_repository(&row.image));
    Ok((file, row.image, new_image))
}

fn preview_steps(file: &str, old: &str, new: &str, env: bool) -> Vec<String> {
    let mut steps = vec![
        format!("cp -p {file} {file}.quietkeep-<date>.bak"),
        format!("In {file}: image: {old}  becomes  image: {new}"),
    ];
    if env {
        steps.push(format!(
            "If the tag comes from a variable, the variable in the .env file next to {file} is changed instead, after its own backup"
        ));
    }
    steps.extend(qk_collect::docker::compose_update_commands(file).iter().map(|c| c.as_str().to_string()));
    steps
}

#[tauri::command]
pub fn docker_tag_preview(state: State<'_, AppState>, id: i64, container: String, major: bool) -> CmdResult<TagUpdatePreview> {
    let (file, old_image, new_image) = tag_update_target(&state, id, &container, major)?;
    let commands = preview_steps(&file, &old_image, &new_image, true);
    Ok(TagUpdatePreview { file, old_image, new_image, major, commands })
}

/// Backs up and edits the compose file (or its .env variable), then pulls and recreates the project.
async fn apply_image_change(
    app: &AppHandle,
    id: i64,
    container: &str,
    file: &str,
    old: &str,
    new: &str,
    env: Option<(String, String, String)>,
) -> CmdResult<String> {
    let h = host(&app.state::<AppState>(), id)?;
    let name = h.spec.name.clone();
    let conn = connect_trusted(app, &h).await?;
    let result = async {
        let edit = conn.run(&qk_collect::docker::set_image_command(file, old, new)).await.map_err(err)?;
        let backup = if edit.success() {
            String::from_utf8_lossy(&edit.stdout).trim().to_string()
        } else if edit.exit_status == Some(4) {
            let Some((repo, old_tag, new_tag)) = &env else {
                return Err(format!("The line image: {old} was not found in {file}, so change it by hand."));
            };
            let e = conn
                .run(&qk_collect::docker::set_env_tag_command(file, repo, old_tag, new_tag))
                .await
                .map_err(err)?;
            if !e.success() {
                return Err(match e.exit_status {
                    Some(3) => format!("QuietKeep cannot write the .env file next to {file}. Check its owner and permissions."),
                    _ => format!("The line image: {old} was not found in {file} and no matching .env variable was found, so change it by hand."),
                });
            }
            String::from_utf8_lossy(&e.stdout).trim().to_string()
        } else if edit.exit_status == Some(3) {
            return Err(format!("QuietKeep cannot write {file}. Check its owner and permissions."));
        } else {
            return Err(format!("Changing {file} failed: {}", String::from_utf8_lossy(&edit.stdout).trim()));
        };
        let r = qk_collect::docker::update_compose(&conn, file).await.map_err(err)?;
        if !r.success {
            return Err(format!(
                "The file now uses {new} (backup {backup}), but the update failed: {}",
                r.output_tail.lines().last().unwrap_or("")
            ));
        }
        Ok(format!("Updated {container} on {name} to {new}. The previous file is saved as {backup}."))
    }
    .await;
    let _ = conn.close().await;
    let (kind, msg) = match &result {
        Ok(m) => ("docker.update", m.clone()),
        Err(m) => ("docker.update_failed", m.clone()),
    };
    store(&app.state::<AppState>()).log_activity(kind, Some(id), &msg).map_err(err)?;
    let _ = docker_one(app, h).await;
    result
}

#[tauri::command]
pub async fn docker_update_tag(app: AppHandle, id: i64, container: String, major: bool) -> CmdResult<String> {
    let (file, old, new) = tag_update_target(&app.state::<AppState>(), id, &container, major)?;
    let env = Some((image_repository(&old), image_tag(&old), image_tag(&new)));
    apply_image_change(&app, id, &container, &file, &old, &new, env).await
}

/// Compose file, pinned image and the same image pinned to the tag's newest build.
fn pin_target(state: &State<'_, AppState>, id: i64, container: &str) -> CmdResult<(String, String, String)> {
    let row = container_row(state, id, container)?;
    let file = compose_file_of(&row)?;
    let old = row
        .configured_image
        .clone()
        .filter(|i| i.contains("@sha256:"))
        .ok_or_else(|| "This container is not pinned to a digest.".to_string())?;
    let digest = row.latest_digest.clone().ok_or_else(|| "The newest build is not known yet. Scan the host again.".to_string())?;
    let new = format!("{}@{digest}", old.split('@').next().unwrap_or(&old));
    if new == old {
        return Err("The pin already points to the newest build.".into());
    }
    Ok((file, old, new))
}

#[tauri::command]
pub fn docker_pin_preview(state: State<'_, AppState>, id: i64, container: String) -> CmdResult<TagUpdatePreview> {
    let (file, old_image, new_image) = pin_target(&state, id, &container)?;
    let commands = preview_steps(&file, &old_image, &new_image, false);
    Ok(TagUpdatePreview { file, old_image, new_image, major: false, commands })
}

#[tauri::command]
pub async fn docker_update_pin(app: AppHandle, id: i64, container: String) -> CmdResult<String> {
    let (file, old, new) = pin_target(&app.state::<AppState>(), id, &container)?;
    apply_image_change(&app, id, &container, &file, &old, &new, None).await
}

#[derive(Serialize)]
pub struct MovePreview {
    file: String,
    yaml: String,
    unsupported: Vec<String>,
    steps: Vec<String>,
}

async fn move_plan(app: &AppHandle, id: i64, container: &str) -> CmdResult<(Host, qk_collect::docker::ComposePlan)> {
    let h = host(&app.state::<AppState>(), id)?;
    let conn = connect_trusted(app, &h).await?;
    let r = qk_collect::docker::inspect(&conn, container).await.map_err(err);
    let _ = conn.close().await;
    let (c, i) = r?.ok_or_else(|| format!("{container} was not found on {}.", h.spec.name))?;
    if c["Config"]["Labels"]["com.docker.compose.project"].is_string() {
        return Err("This container is already managed by docker compose.".into());
    }
    Ok((h, qk_collect::docker::compose_from_inspect(&c, &i)))
}

#[tauri::command]
pub async fn docker_move_preview(app: AppHandle, id: i64, container: String) -> CmdResult<MovePreview> {
    let (_, plan) = move_plan(&app, id, &container).await?;
    let file = format!("~/{container}/compose.yaml");
    let steps = vec![
        format!("Write {file}, readable only by you"),
        format!("docker compose -f {file} pull"),
        format!("docker stop {container}, then rename it to {container}-quietkeep-old"),
        format!("docker compose -f {file} up -d"),
        "If the new container does not start, the original is renamed back and started again".to_string(),
    ];
    Ok(MovePreview { file, yaml: plan.masked, unsupported: plan.unsupported, steps })
}

#[tauri::command]
pub async fn docker_move_to_compose(app: AppHandle, id: i64, container: String) -> CmdResult<String> {
    let (h, plan) = move_plan(&app, id, &container).await?;
    if !plan.unsupported.is_empty() {
        return Err(format!("QuietKeep cannot copy these settings: {}.", plan.unsupported.join(", ")));
    }
    let name = h.spec.name.clone();
    let conn = connect_trusted(&app, &h).await?;
    let r = conn
        .run_with_stdin(&qk_collect::docker::move_to_compose_command(&container, &plan.restart), Some(plan.yaml.as_bytes()))
        .await
        .map_err(err);
    let _ = conn.close().await;
    let result = match r {
        Ok(o) if o.success() => {
            let out = String::from_utf8_lossy(&o.stdout).to_string();
            let mut lines = out.lines().rev();
            let old = lines.next().unwrap_or_default().to_string();
            let file = lines.next().unwrap_or_default().to_string();
            Ok(format!("{container} on {name} now runs from {file}. The original container is stopped and kept as {old} for rollback."))
        }
        Ok(o) => Err(format!(
            "Moving {container} to compose failed: {}",
            String::from_utf8_lossy(&o.stdout).lines().last().unwrap_or("")
        )),
        Err(e) => Err(e),
    };
    let (kind, msg) = match &result {
        Ok(m) => ("docker.move", m.clone()),
        Err(m) => ("docker.move_failed", m.clone()),
    };
    store(&app.state::<AppState>()).log_activity(kind, Some(id), &msg).map_err(err)?;
    let _ = docker_one(&app, h).await;
    result
}

/// Removes a stopped `*-old` copy that was kept so an update or move could be undone. Named
/// volumes are left alone, so the running container keeps its data.
#[tauri::command]
pub async fn docker_remove_rollback(app: AppHandle, id: i64, container: String) -> CmdResult<String> {
    let row = container_row(&app.state::<AppState>(), id, &container)?;
    if !row.name.ends_with("-old") || row.state == "running" {
        return Err("Only stopped rollback copies can be removed here.".into());
    }
    let h = host(&app.state::<AppState>(), id)?;
    let name = h.spec.name.clone();
    let conn = connect_trusted(&app, &h).await?;
    let r = conn.run(&Command::new("docker").args(["rm", &container])).await.map_err(err);
    let _ = conn.close().await;
    let result = match r {
        Ok(o) if o.success() => Ok(format!("Removed the rollback copy {container} from {name}.")),
        Ok(o) => Err(format!("Removing {container} failed: {}", String::from_utf8_lossy(&o.stderr).trim())),
        Err(e) => Err(e),
    };
    let msg = match &result {
        Ok(m) | Err(m) => m.clone(),
    };
    store(&app.state::<AppState>()).log_activity("docker.remove_rollback", Some(id), &msg).map_err(err)?;
    let _ = docker_one(&app, h).await;
    result
}

/// Hides or shows again the major release notice for a container. Only the major tag
/// currently reported for that container can be snoozed.
#[tauri::command]
pub fn docker_snooze_major(state: State<'_, AppState>, id: i64, container: String, snooze: bool) -> CmdResult<()> {
    let row = container_row(&state, id, &container)?;
    let major = row.major_tag.filter(|_| snooze);
    if snooze && major.is_none() {
        return Err("There is no major release to snooze for this container.".into());
    }
    let mut s = store(&state);
    s.set_major_snooze(id, &container, major.as_deref()).map_err(err)?;
    let msg = match &major {
        Some(m) => format!("Snoozed the major release {m} notice for {container}."),
        None => format!("Showing the major release notice for {container} again."),
    };
    s.log_activity("docker.snooze", Some(id), &msg).map_err(err)
}

/// Lists images on a host that no container uses. Read only.
#[tauri::command]
pub async fn docker_unused_images(app: AppHandle, id: i64) -> CmdResult<Vec<qk_collect::docker::UnusedImage>> {
    let h = host(&app.state::<AppState>(), id)?;
    let conn = connect_trusted(&app, &h).await?;
    let r = qk_collect::docker::unused_images(&conn).await.map_err(err);
    let _ = conn.close().await;
    r?.map_err(|e| format!("Listing images failed: {e}"))
}

/// Removes the selected images with `docker image rm`. Every ID must be a full image ID
/// that is still unused when checked again here, and nothing is forced.
#[tauri::command]
pub async fn docker_remove_images(app: AppHandle, id: i64, images: Vec<String>) -> CmdResult<String> {
    if images.is_empty() || images.len() > 500 || !images.iter().all(|i| qk_collect::docker::valid_image_id(i)) {
        return Err("Select one or more images to remove.".into());
    }
    let h = host(&app.state::<AppState>(), id)?;
    let name = h.spec.name.clone();
    let conn = connect_trusted(&app, &h).await?;
    let unused = match qk_collect::docker::unused_images(&conn).await {
        Ok(Ok(u)) => u.into_iter().map(|i| i.id).collect::<HashSet<_>>(),
        Ok(Err(e)) => {
            let _ = conn.close().await;
            return Err(format!("Listing images failed: {e}"));
        }
        Err(e) => {
            let _ = conn.close().await;
            return Err(err(e));
        }
    };
    if let Some(busy) = images.iter().find(|i| !unused.contains(*i)) {
        let _ = conn.close().await;
        return Err(format!("{busy} is now used by a container or no longer exists. Refresh the list."));
    }
    let mut cmd = Command::new("docker").args(["image", "rm"]);
    for i in &images {
        cmd = cmd.arg(i);
    }
    let r = conn.run(&cmd).await.map_err(err);
    let _ = conn.close().await;
    let result = match r {
        Ok(o) if o.success() => Ok(format!("Removed {} unused images from {name}.", images.len())),
        Ok(o) => Err(format!("Removing images on {name} failed: {}", String::from_utf8_lossy(&o.stderr).trim())),
        Err(e) => Err(e),
    };
    let msg = match &result {
        Ok(m) | Err(m) => m.clone(),
    };
    store(&app.state::<AppState>()).log_activity("docker.remove_images", Some(id), &msg).map_err(err)?;
    result
}

fn valid_cve_id(id: &str) -> bool {
    let mut parts = id.splitn(3, '-');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some("CVE"), Some(y), Some(n))
            if y.len() == 4
                && y.bytes().all(|b| b.is_ascii_digit())
                && (4..=8).contains(&n.len())
                && n.bytes().all(|b| b.is_ascii_digit())
    )
}

/// Opens a public CVE page in the default browser. Only fixed NVD and CVE.org
/// addresses built from a validated CVE ID can be opened.
#[tauri::command]
pub fn open_cve_page(cve: String, site: String) -> CmdResult<()> {
    if !valid_cve_id(&cve) {
        return Err("That is not a valid CVE ID.".into());
    }
    let url = match site.as_str() {
        "nvd" => format!("https://nvd.nist.gov/vuln/detail/{cve}"),
        "cve" => format!("https://www.cve.org/CVERecord?id={cve}"),
        "debian" => format!("https://security-tracker.debian.org/tracker/{cve}"),
        "ubuntu" => format!("https://ubuntu.com/security/{cve}"),
        _ => return Err("Unknown site.".into()),
    };
    std::process::Command::new("xdg-open")
        .arg(&url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("Could not open the browser: {e}"))
}

#[cfg(test)]
mod cve_tests {
    use super::valid_cve_id;

    #[test]
    fn cve_ids_are_validated() {
        assert!(valid_cve_id("CVE-2024-3094"));
        assert!(valid_cve_id("CVE-2026-123158"));
        assert!(!valid_cve_id("CVE-2024-30"));
        assert!(!valid_cve_id("CVE-2024-3094&x=1"));
        assert!(!valid_cve_id("cve-2024-3094"));
        assert!(!valid_cve_id("CVE-24-3094"));
    }
}
