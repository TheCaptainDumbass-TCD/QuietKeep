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
            // The keyring is queried on its own thread so a slow or prompting keyring cannot
            // stall the GTK main thread.
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = tx.send(qk_auth::passphrase());
            });
            let passphrase = match rx.recv_timeout(std::time::Duration::from_secs(30)) {
                Ok(Ok(p)) => Some(p),
                Ok(Err(e)) => {
                    eprintln!("quietkeep: {e}; the SSH key stays unencrypted with mode 0600");
                    None
                }
                Err(_) => {
                    eprintln!("quietkeep: the desktop keyring did not answer within 30 seconds");
                    None
                }
            };
            let identity = qk_ssh::load_or_create_identity(&dir.join("identity_ed25519"), passphrase.as_deref())?;
            app.manage(AppState {
                store: Mutex::new(store),
                key_protection: if identity.encrypted {
                    "Encrypted, passphrase in the desktop keyring".into()
                } else {
                    "Not encrypted (no desktop keyring found). File readable only by you".into()
                },
                identity: std::sync::Arc::new(identity.key),
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
            commands::docker_status,
            commands::scan_docker,
            commands::scan_docker_all,
            commands::compose_update_preview,
            commands::update_compose,
            commands::kev_state,
            commands::kev_set_allowed,
            commands::open_cve_page,
            commands::registry_state,
            commands::registry_set_allowed,
            commands::docker_tag_preview,
            commands::docker_update_tag,
            commands::docker_pin_preview,
            commands::docker_update_pin,
            commands::docker_move_preview,
            commands::docker_move_to_compose,
            commands::docker_remove_rollback,
            commands::docker_snooze_major,
            commands::kev_affected,
            commands::osv_state,
            commands::osv_set_allowed,
            commands::osv_refresh,
            commands::docker_unused_images,
            commands::docker_remove_images,
            commands::kev_refresh,
            commands::kev_search,
            commands::metrics,
            commands::setup_access_preview,
            commands::setup_access,
            commands::update_pending,
            commands::restart_app,
        ])
        .run(tauri::generate_context!())
        .expect("failed to start QuietKeep");
}
