use serde::de::DeserializeOwned;
use serde::Deserialize;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(catch, js_namespace = ["window", "__TAURI__", "core"], js_name = invoke)]
    async fn invoke_raw(cmd: &str, args: JsValue) -> Result<JsValue, JsValue>;
}

pub async fn invoke<T: DeserializeOwned>(cmd: &str, args: JsValue) -> Result<T, String> {
    let value = invoke_raw(cmd, args)
        .await
        .map_err(|e| e.as_string().unwrap_or_else(|| format!("{e:?}")))?;
    serde_wasm_bindgen::from_value(value).map_err(|e| e.to_string())
}

#[derive(Clone, Deserialize)]
pub struct AppInfo {
    pub name: String,
    pub version: String,
    pub commit: String,
    pub identifier: String,
    pub platform: String,
    pub data_dir: String,
    pub schema_version: i64,
}

pub async fn app_info() -> Result<AppInfo, String> {
    invoke("app_info", JsValue::UNDEFINED).await
}
