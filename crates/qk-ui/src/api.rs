use serde::{Deserialize, Serialize};
use wasm_bindgen::JsValue;

use crate::tauri::invoke;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HostSpec {
    pub name: String,
    pub address: String,
    pub username: String,
    pub os_type: String,
    pub is_patch_target: bool,
    pub has_docker: bool,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Host {
    pub id: i64,
    #[serde(flatten)]
    pub spec: HostSpec,
    #[serde(default)]
    pub host_key: Option<String>,
    pub host_key_trusted: bool,
    #[serde(default)]
    pub access_ok: bool,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct HostKeyProbe {
    pub fingerprint: String,
    pub algorithm: String,
    pub changed_from: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct RowError {
    pub line: u64,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ImportReport {
    pub hosts: Vec<HostSpec>,
    pub duplicates: Vec<String>,
    pub errors: Vec<RowError>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Activity {
    pub at: i64,
    pub kind: String,
    pub message: String,
}

fn args<T: Serialize>(value: &T) -> JsValue {
    serde_wasm_bindgen::to_value(value).unwrap_or(JsValue::UNDEFINED)
}

pub async fn list_hosts() -> Result<Vec<Host>, String> {
    invoke("list_hosts", JsValue::UNDEFINED).await
}

pub async fn delete_host(id: i64) -> Result<bool, String> {
    #[derive(Serialize)]
    struct A {
        id: i64,
    }
    invoke("delete_host", args(&A { id })).await
}

pub async fn recent_activity() -> Result<Vec<Activity>, String> {
    invoke("recent_activity", JsValue::UNDEFINED).await
}

pub async fn pick_import_csv() -> Result<Option<ImportReport>, String> {
    invoke("pick_import_csv", JsValue::UNDEFINED).await
}

pub async fn commit_import(hosts: Vec<HostSpec>) -> Result<usize, String> {
    #[derive(Serialize)]
    struct A {
        hosts: Vec<HostSpec>,
    }
    invoke("commit_import", args(&A { hosts })).await
}

pub async fn export_hosts_csv() -> Result<Option<usize>, String> {
    invoke("export_hosts_csv", JsValue::UNDEFINED).await
}

#[derive(Serialize)]
struct IdArg {
    id: i64,
}

pub async fn probe_host_key(id: i64) -> Result<HostKeyProbe, String> {
    invoke("probe_host_key", args(&IdArg { id })).await
}

pub async fn trust_host_key(id: i64, fingerprint: String) -> Result<bool, String> {
    #[derive(Serialize)]
    struct A {
        id: i64,
        fingerprint: String,
    }
    invoke("trust_host_key", args(&A { id, fingerprint })).await
}

pub async fn test_connection(id: i64) -> Result<String, String> {
    invoke("test_connection", args(&IdArg { id })).await
}

pub async fn client_public_key() -> Result<String, String> {
    invoke("client_public_key", JsValue::UNDEFINED).await
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct PatchStatus {
    pub host_id: i64,
    pub name: String,
    pub os_type: String,
    pub is_patch_target: bool,
    pub host_key_trusted: bool,
    pub last_scan_at: Option<i64>,
    pub pending: u32,
    pub security: u32,
    pub reboot_required: bool,
    pub scan_error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct PackageUpdate {
    pub name: String,
    pub current_version: Option<String>,
    pub available_version: String,
    pub source: Option<String>,
    pub security: bool,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ScanSummary {
    pub scanned: u32,
    pub failed: u32,
    pub skipped: u32,
}

pub async fn patch_status() -> Result<Vec<PatchStatus>, String> {
    invoke("patch_status", JsValue::UNDEFINED).await
}

pub async fn pending_updates(id: i64) -> Result<Vec<PackageUpdate>, String> {
    invoke("pending_updates", args(&IdArg { id })).await
}

pub async fn scan_host(id: i64) -> Result<bool, String> {
    invoke("scan_host", args(&IdArg { id })).await
}

pub async fn scan_all() -> Result<ScanSummary, String> {
    invoke("scan_all", JsValue::UNDEFINED).await
}

pub async fn get_scan_interval() -> Result<u32, String> {
    invoke("get_scan_interval", JsValue::UNDEFINED).await
}

pub async fn set_scan_interval(minutes: u32) -> Result<u32, String> {
    #[derive(Serialize)]
    struct A {
        minutes: u32,
    }
    invoke("set_scan_interval", args(&A { minutes })).await
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct PrivilegeCheck {
    pub allowed: bool,
    pub commands: Vec<String>,
    pub rule: String,
    pub sudoers_path: String,
}

#[derive(Serialize)]
struct ActionArg {
    id: i64,
    action: &'static str,
}

pub async fn check_privileged(id: i64, action: &'static str) -> Result<PrivilegeCheck, String> {
    invoke("check_privileged", args(&ActionArg { id, action })).await
}

pub async fn run_action(id: i64, action: &'static str) -> Result<String, String> {
    invoke("run_action", args(&ActionArg { id, action })).await
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct ContainerRow {
    pub name: String,
    pub image: String,
    pub state: String,
    pub status: String,
    pub project: Option<String>,
    pub service: Option<String>,
    pub config_file: Option<String>,
    pub update_available: Option<bool>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct DockerHost {
    pub host_id: i64,
    pub name: String,
    pub host_key_trusted: bool,
    pub docker_scan_at: Option<i64>,
    pub docker_error: Option<String>,
    pub containers: Vec<ContainerRow>,
}

#[derive(Serialize)]
struct ProjectArg {
    id: i64,
    project: String,
}

pub async fn docker_status() -> Result<Vec<DockerHost>, String> {
    invoke("docker_status", JsValue::UNDEFINED).await
}

pub async fn scan_docker(id: i64) -> Result<bool, String> {
    invoke("scan_docker", args(&IdArg { id })).await
}

pub async fn scan_docker_all() -> Result<ScanSummary, String> {
    invoke("scan_docker_all", JsValue::UNDEFINED).await
}

pub async fn compose_update_preview(id: i64, project: String) -> Result<Vec<String>, String> {
    invoke("compose_update_preview", args(&ProjectArg { id, project })).await
}

pub async fn update_compose(id: i64, project: String) -> Result<String, String> {
    invoke("update_compose", args(&ProjectArg { id, project })).await
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct KevSummary {
    pub catalog_version: String,
    pub date_released: String,
    pub total: usize,
    pub ransomware: usize,
    pub linux_related: usize,
    pub added_last_30_days: usize,
    pub top_vendors: Vec<(String, usize)>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct KevState {
    pub allowed: bool,
    pub summary: Option<KevSummary>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vulnerability {
    #[serde(rename = "cveID")]
    pub cve_id: String,
    pub vendor_project: String,
    pub product: String,
    pub vulnerability_name: String,
    pub date_added: String,
    pub short_description: String,
    pub required_action: String,
    pub due_date: String,
    pub known_ransomware_campaign_use: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct KevFilter {
    pub search: String,
    pub linux_only: bool,
    pub ransomware_only: bool,
}

pub async fn kev_state() -> Result<KevState, String> {
    invoke("kev_state", JsValue::UNDEFINED).await
}

pub async fn kev_set_allowed(allowed: bool) -> Result<bool, String> {
    #[derive(Serialize)]
    struct A {
        allowed: bool,
    }
    invoke("kev_set_allowed", args(&A { allowed })).await
}

pub async fn kev_refresh() -> Result<KevSummary, String> {
    invoke("kev_refresh", JsValue::UNDEFINED).await
}

pub async fn kev_search(filter: KevFilter) -> Result<Vec<Vulnerability>, String> {
    #[derive(Serialize)]
    struct A {
        filter: KevFilter,
    }
    invoke("kev_search", args(&A { filter })).await
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct MetricSample {
    pub at: i64,
    pub load1: f64,
    pub cpus: u32,
    pub mem_used_pct: f64,
    pub disk_used_pct: f64,
    pub uptime_s: i64,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct HostMetrics {
    pub host_id: i64,
    pub name: String,
    pub kernel: Option<String>,
    pub os_name: Option<String>,
    pub samples: Vec<MetricSample>,
}

pub async fn metrics(hours: u32) -> Result<Vec<HostMetrics>, String> {
    #[derive(Serialize)]
    struct A {
        hours: u32,
    }
    invoke("metrics", args(&A { hours })).await
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct AccessPreview {
    pub steps: Vec<String>,
    pub public_key: String,
    pub rule: Option<String>,
}

pub async fn setup_access_preview(id: i64, use_agent: bool, install_sudoers: bool) -> Result<AccessPreview, String> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct A {
        id: i64,
        use_agent: bool,
        install_sudoers: bool,
    }
    invoke("setup_access_preview", args(&A { id, use_agent, install_sudoers })).await
}

pub async fn setup_access(id: i64, use_agent: bool, password: String, install_sudoers: bool) -> Result<String, String> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct A {
        id: i64,
        use_agent: bool,
        password: String,
        install_sudoers: bool,
    }
    invoke("setup_access", args(&A { id, use_agent, password, install_sudoers })).await
}

pub async fn update_pending() -> Result<bool, String> {
    invoke("update_pending", JsValue::UNDEFINED).await
}

pub async fn restart_app() -> Result<(), String> {
    invoke("restart_app", JsValue::UNDEFINED).await
}
