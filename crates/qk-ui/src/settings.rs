use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::api;

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
    }
}
