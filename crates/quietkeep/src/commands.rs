use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use qk_core::host::HostSpec;
use qk_core::host_csv::{self, ImportReport};
use qk_ssh::{Command, PrivateKey, SshError, Target, TrustPolicy};
use qk_store::{Activity, Host, Store};
use serde::Serialize;
use tauri::{AppHandle, State};
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

fn store<'a>(state: &'a State<'_, AppState>) -> std::sync::MutexGuard<'a, Store> {
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
