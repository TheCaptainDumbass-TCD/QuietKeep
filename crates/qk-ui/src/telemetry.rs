use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::api::{self, HostMetrics, MetricSample};

const W: f64 = 140.0;
const H: f64 = 30.0;

fn points(samples: &[MetricSample], value: fn(&MetricSample) -> f64, max: f64) -> String {
    let (Some(first), Some(last)) = (samples.first(), samples.last()) else { return String::new() };
    let span = (last.at - first.at).max(1) as f64;
    samples
        .iter()
        .map(|s| {
            let x = if samples.len() == 1 { W } else { (s.at - first.at) as f64 / span * W };
            let y = H - (value(s) / max).clamp(0.0, 1.0) * (H - 2.0) - 1.0;
            format!("{x:.1},{y:.1}")
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn spark(samples: &[MetricSample], value: fn(&MetricSample) -> f64, max: f64, class: &'static str) -> impl IntoView {
    let pts = points(samples, value, max);
    let latest = samples.last().map(value).unwrap_or(0.0);
    let level = if latest / max >= 0.9 { "bad" } else if latest / max >= 0.75 { "warn" } else { "ok" };
    view! {
        <svg class=format!("spark {class} {level}") viewBox=format!("0 0 {W} {H}") preserveAspectRatio="none">
            <polyline points=pts fill="none" stroke-width="1.5" vector-effect="non-scaling-stroke" />
        </svg>
    }
}

fn uptime(s: i64) -> String {
    match s {
        s if s >= 86_400 => format!("{}d {}h", s / 86_400, s % 86_400 / 3600),
        s if s >= 3600 => format!("{}h {}m", s / 3600, s % 3600 / 60),
        s => format!("{}m", s / 60),
    }
}

#[component]
pub fn TelemetryCard() -> impl IntoView {
    let hours = RwSignal::new(24u32);
    let data = RwSignal::new(Vec::<HostMetrics>::new());
    let load = move || {
        let h = hours.get_untracked();
        spawn_local(async move {
            if let Ok(d) = api::metrics(h).await {
                data.set(d);
            }
        })
    };
    load();
    let pick = move |h: u32| {
        hours.set(h);
        load();
    };

    view! {
        <section class="card">
            <div class="toolbar">
                <h2>"Host telemetry"</h2>
                <span class="spacer"></span>
                <button class=move || if hours.get() == 24 { "btn small primary" } else { "btn small" } on:click=move |_| pick(24)>"24 hours"</button>
                <button class=move || if hours.get() == 168 { "btn small primary" } else { "btn small" } on:click=move |_| pick(168)>"7 days"</button>
            </div>
            <Show when=move || data.with(|d| !d.is_empty())
                fallback=|| view! { <p class="muted">"No telemetry yet. It is collected with each patch scan of a trusted host."</p> }>
                <table class="table telemetry">
                    <thead><tr>
                        <th>"Host"</th><th>"OS"</th><th>"Uptime"</th>
                        <th>"Load per CPU"</th><th>"Memory"</th><th>"Root disk"</th>
                    </tr></thead>
                    <tbody>
                        <For each=move || data.get() key=|h| (h.host_id, h.samples.len(), h.samples.last().map(|s| s.at)) let:h>
                            {
                                let last = h.samples.last().cloned().unwrap();
                                let per_cpu = |s: &MetricSample| s.load1 / s.cpus.max(1) as f64;
                                view! {
                                    <tr>
                                        <td>{h.name.clone()}</td>
                                        <td class="muted" title=h.kernel.clone().unwrap_or_default()>{h.os_name.clone().unwrap_or_default()}</td>
                                        <td class="mono">{uptime(last.uptime_s)}</td>
                                        <td><div class="metric">{spark(&h.samples, per_cpu, 1.0, "load")}<span class="mono">{format!("{:.2}", per_cpu(&last))}</span></div></td>
                                        <td><div class="metric">{spark(&h.samples, |s| s.mem_used_pct, 100.0, "mem")}<span class="mono">{format!("{:.0}%", last.mem_used_pct)}</span></div></td>
                                        <td><div class="metric">{spark(&h.samples, |s| s.disk_used_pct, 100.0, "disk")}<span class="mono">{format!("{:.0}%", last.disk_used_pct)}</span></div></td>
                                    </tr>
                                }
                            }
                        </For>
                    </tbody>
                </table>
            </Show>
        </section>
    }
}
