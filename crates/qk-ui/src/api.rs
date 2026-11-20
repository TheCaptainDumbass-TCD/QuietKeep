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
    #[serde(default)]
    pub os_name: Option<String>,
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

pub async fn add_host(spec: HostSpec) -> Result<i64, String> {
    #[derive(Serialize)]
    struct A {
        spec: HostSpec,
    }
    invoke("add_host", args(&A { spec })).await
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
    #[serde(default)]
    pub held: u32,
    #[serde(default)]
    pub os_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct PackageUpdate {
    pub name: String,
    pub current_version: Option<String>,
    pub available_version: String,
    pub source: Option<String>,
    pub security: bool,
    #[serde(default)]
    pub held: Option<String>,
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
    #[serde(default)]
    pub update_note: Option<String>,
    #[serde(default)]
    pub update_kind: Option<String>,
    #[serde(default)]
    pub latest_tag: Option<String>,
    #[serde(default)]
    pub major_tag: Option<String>,
    #[serde(default)]
    pub stopped_days: Option<i64>,
    #[serde(default)]
    pub snoozed: bool,
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

pub async fn open_cve_page(cve: String, site: &'static str) -> Result<(), String> {
    #[derive(Serialize)]
    struct A {
        cve: String,
        site: &'static str,
    }
    invoke("open_cve_page", args(&A { cve, site })).await
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct HostMatch {
    pub host_id: i64,
    pub host: String,
    pub source: String,
    pub version: String,
    #[serde(default)]
    pub update_pending: bool,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub fixed_version: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct OsvState {
    pub allowed: bool,
    pub fetched_at: Option<String>,
    pub checked: usize,
}

pub async fn osv_state() -> Result<OsvState, String> {
    invoke("osv_state", JsValue::UNDEFINED).await
}

pub async fn osv_set_allowed(allowed: bool) -> Result<bool, String> {
    #[derive(Serialize)]
    struct A {
        allowed: bool,
    }
    invoke("osv_set_allowed", args(&A { allowed })).await
}

pub async fn osv_refresh() -> Result<usize, String> {
    invoke("osv_refresh", JsValue::UNDEFINED).await
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Affected {
    pub cve_id: String,
    pub vendor_project: String,
    pub product: String,
    pub vulnerability_name: String,
    pub date_added: String,
    pub known_ransomware: bool,
    pub hosts: Vec<HostMatch>,
}

pub async fn kev_affected() -> Result<Vec<Affected>, String> {
    invoke("kev_affected", JsValue::UNDEFINED).await
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

pub async fn registry_state() -> Result<Option<bool>, String> {
    invoke("registry_state", JsValue::UNDEFINED).await
}

pub async fn registry_set_allowed(allowed: bool) -> Result<bool, String> {
    #[derive(Serialize)]
    struct A {
        allowed: bool,
    }
    invoke("registry_set_allowed", args(&A { allowed })).await
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct TagUpdatePreview {
    pub file: String,
    pub old_image: String,
    pub new_image: String,
    pub major: bool,
    pub commands: Vec<String>,
}

#[derive(Serialize)]
struct TagArg {
    id: i64,
    container: String,
    major: bool,
}

pub async fn docker_tag_preview(id: i64, container: String, major: bool) -> Result<TagUpdatePreview, String> {
    invoke("docker_tag_preview", args(&TagArg { id, container, major })).await
}

pub async fn docker_update_tag(id: i64, container: String, major: bool) -> Result<String, String> {
    invoke("docker_update_tag", args(&TagArg { id, container, major })).await
}

#[derive(Serialize)]
struct ContainerArg {
    id: i64,
    container: String,
}

pub async fn docker_pin_preview(id: i64, container: String) -> Result<TagUpdatePreview, String> {
    invoke("docker_pin_preview", args(&ContainerArg { id, container })).await
}

pub async fn docker_update_pin(id: i64, container: String) -> Result<String, String> {
    invoke("docker_update_pin", args(&ContainerArg { id, container })).await
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct MovePreview {
    pub file: String,
    pub yaml: String,
    pub unsupported: Vec<String>,
    pub steps: Vec<String>,
}

pub async fn docker_move_preview(id: i64, container: String) -> Result<MovePreview, String> {
    invoke("docker_move_preview", args(&ContainerArg { id, container })).await
}

pub async fn docker_move_to_compose(id: i64, container: String) -> Result<String, String> {
    invoke("docker_move_to_compose", args(&ContainerArg { id, container })).await
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct UnusedImage {
    pub id: String,
    pub repository: String,
    pub tag: String,
    pub size: String,
    pub created: String,
}

pub async fn docker_unused_images(id: i64) -> Result<Vec<UnusedImage>, String> {
    #[derive(Serialize)]
    struct A {
        id: i64,
    }
    invoke("docker_unused_images", args(&A { id })).await
}

pub async fn docker_remove_images(id: i64, images: Vec<String>) -> Result<String, String> {
    #[derive(Serialize)]
    struct A {
        id: i64,
        images: Vec<String>,
    }
    invoke("docker_remove_images", args(&A { id, images })).await
}

pub async fn docker_snooze_major(id: i64, container: String, snooze: bool) -> Result<(), String> {
    #[derive(Serialize)]
    struct A {
        id: i64,
        container: String,
        snooze: bool,
    }
    invoke("docker_snooze_major", args(&A { id, container, snooze })).await
}

pub async fn docker_remove_rollback(id: i64, container: String) -> Result<String, String> {
    invoke("docker_remove_rollback", args(&ContainerArg { id, container })).await
}
