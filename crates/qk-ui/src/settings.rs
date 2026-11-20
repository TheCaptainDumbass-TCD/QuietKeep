use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::{api, tauri};

const INTERVALS: [(u32, &str); 5] = [
    (0, "Off"),
    (60, "Every hour"),
    (360, "Every 6 hours"),
    (720, "Every 12 hours"),
    (1440, "Every 24 hours"),
];

#[component]
pub fn SettingsPanel(refresh: Callback<()>) -> impl IntoView {
    let interval = RwSignal::new(0u32);
    let notice = RwSignal::new(None::<String>);
    let info = RwSignal::new(None::<tauri::AppInfo>);
    let public_key = RwSignal::new(String::new());
    spawn_local(async move {
        if let Ok(i) = tauri::app_info().await {
            info.set(Some(i));
        }
        if let Ok(k) = api::client_public_key().await {
            public_key.set(k);
        }
    });
    spawn_local(async move {
        if let Ok(v) = api::get_scan_interval().await {
            interval.set(v);
        }
    });
    let change = move |ev: leptos::ev::Event| {
        let Ok(minutes) = event_target_value(&ev).parse::<u32>() else { return };
        spawn_local(async move {
            match api::set_scan_interval(minutes).await {
                Ok(v) => {
                    interval.set(v);
                    notice.set(Some("Saved.".into()));
                }
                Err(e) => notice.set(Some(e)),
            }
            refresh.run(());
        })
    };

    view! {
        <section class="card">
            <h2>"Scheduled scans"</h2>
            <p class="muted">
                "QuietKeep scans hosts with trusted keys in the background while it is open or in the tray. "
                "Scans are read-only and never apply updates."
            </p>
            <div class="field">
                <label for="scan-interval">"Scan interval"</label>
                <select id="scan-interval" on:change=change prop:value=move || interval.get().to_string()>
                    {INTERVALS
                        .into_iter()
                        .map(|(v, label)| view! { <option value=v.to_string()>{label}</option> })
                        .collect_view()}
                </select>
                <span class="muted">{move || notice.get().unwrap_or_default()}</span>
            </div>
        </section>
        <crate::layout::PanelLayoutCard />
        <section class="card">
            <h2>"About QuietKeep"</h2>
            {move || info.get().map(|i| view! {
                <table class="table about">
                    <tbody>
                        <tr><th>"Version"</th><td class="mono">{format!("{} {}", i.name, i.version)}</td></tr>
                        <tr><th>"Build"</th><td class="mono">{i.commit}</td></tr>
                        <tr><th>"Platform"</th><td class="mono">{i.platform}</td></tr>
                        <tr><th>"App ID"</th><td class="mono">{i.identifier}</td></tr>
                        <tr><th>"Data folder"</th><td class="mono">{i.data_dir}</td></tr>
                        <tr><th>"Database schema"</th><td class="mono">{i.schema_version.to_string()}</td></tr>
                        <tr><th>"License"</th><td>"GPL-3.0-or-later. Copyright (C) 2026 Dennis Ayotte"</td></tr>
                    </tbody>
                </table>
            })}
            <p class="muted">
                "QuietKeep runs entirely on this computer. It opens no network port, sends no telemetry and only connects to the hosts you add. "
                "Downloads from cisa.gov happen only after you allow them."
            </p>
            <h3>"Access key"</h3>
            <p class="muted small">"Add this public key to ~/.ssh/authorized_keys on each host QuietKeep manages."</p>
            <textarea class="keybox mono" readonly rows="3">{move || public_key.get()}</textarea>
        </section>
    }
}
