use std::collections::HashSet;
use std::fs::File;
use std::sync::Mutex;

use qk_core::host::HostSpec;
use qk_core::host_csv::{self, ImportReport};
use qk_store::{Activity, Host, Store};
use serde::Serialize;
use tauri::{AppHandle, State};
use tauri_plugin_dialog::{DialogExt, FilePath};

pub struct AppState {
    pub store: Mutex<Store>,
}

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
