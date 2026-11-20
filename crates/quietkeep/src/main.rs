#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod scheduler;

use std::sync::Mutex;

use commands::AppState;
use qk_store::Store;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, WindowEvent};

const MAIN_WINDOW: &str = "main";

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "Open QuietKeep", true, None::<&str>)?;
    let scan = MenuItem::with_id(app, "scan", "Scan trusted hosts now", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &scan, &quit])?;

    let mut tray = TrayIconBuilder::with_id("quietkeep")
        .tooltip("QuietKeep")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => show_main_window(app),
            "scan" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = commands::scan_trusted(&app).await;
                });
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main_window(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.build(app)?;
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            show_main_window(app);
        }))
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            std::fs::create_dir_all(&dir)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
            }
            let store = Store::open(&dir.join("quietkeep.db"))?;
            let identity = qk_ssh::load_or_create_identity(&dir.join("identity_ed25519"))?;
            app.manage(AppState {
                store: Mutex::new(store),
                identity: std::sync::Arc::new(identity),
                pending_keys: Mutex::new(Default::default()),
            });
            build_tray(app.handle())?;
            scheduler::update_tray_tooltip(app.handle());
            scheduler::start(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == MAIN_WINDOW {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::list_hosts,
            commands::add_host,
            commands::delete_host,
            commands::recent_activity,
            commands::pick_import_csv,
            commands::commit_import,
            commands::export_hosts_csv,
            commands::probe_host_key,
            commands::trust_host_key,
            commands::test_connection,
            commands::client_public_key,
            commands::patch_status,
            commands::pending_updates,
            commands::scan_host,
            commands::scan_all,
            commands::get_scan_interval,
            commands::set_scan_interval,
            commands::check_privileged,
            commands::run_action,
        ])
        .run(tauri::generate_context!())
        .expect("failed to start QuietKeep");
}
