//! Background scans while QuietKeep runs (window open or in the tray). Off unless the user enables them.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tauri::{AppHandle, Manager};

use crate::commands::{scan_interval, scan_trusted, store, AppState};

const LAST_AUTO_SCAN_KEY: &str = "scan.last_auto_at";
const TICK: Duration = Duration::from_secs(60);

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub fn start(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::time::sleep(TICK).await;
            let state = app.state::<AppState>();
            let interval = scan_interval(&state) as i64 * 60;
            if interval == 0 {
                continue;
            }
            let last = store(&state)
                .get_setting(LAST_AUTO_SCAN_KEY)
                .ok()
                .flatten()
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(0);
            if now() - last < interval {
                continue;
            }
            let _ = store(&state).set_setting(LAST_AUTO_SCAN_KEY, &now().to_string());
            let _ = scan_trusted(&app, true).await;
        }
    });
}

pub fn update_tray_tooltip(app: &AppHandle) {
    let Ok(status) = store(&app.state::<AppState>()).patch_status() else { return };
    let pending: u32 = status.iter().map(|s| s.pending).sum();
    let security: u32 = status.iter().map(|s| s.security).sum();
    let reboot = status.iter().filter(|s| s.reboot_required).count();
    if let Some(tray) = app.tray_by_id("quietkeep") {
        let _ = tray.set_tooltip(Some(format!(
            "QuietKeep: {pending} updates ({security} security), {reboot} need reboot"
        )));
    }
}
