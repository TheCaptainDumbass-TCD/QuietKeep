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
