use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::api::{self, DockerHost};
use crate::patches::ago;

#[derive(Clone)]
struct UpdateDialog {
    id: i64,
    host: String,
    project: String,
    commands: Vec<String>,
}

#[component]
pub fn DockerPanel(refresh: Callback<()>) -> impl IntoView {
    let hosts = RwSignal::new(Vec::<DockerHost>::new());
    let notice = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let dialog = RwSignal::new(None::<UpdateDialog>);

    let load = move || {
        spawn_local(async move {
            match api::docker_status().await {
                Ok(v) => hosts.set(v),
                Err(e) => notice.set(Some(e)),
            }
        })
    };
    load();

    let scan_all = move |_| {
        busy.set(true);
        notice.set(Some("Scanning Docker hosts...".into()));
        spawn_local(async move {
            match api::scan_docker_all().await {
                Ok(s) => notice.set(Some(format!(
                    "Scanned {} hosts. {} failed, {} skipped because their key is not verified.",
                    s.scanned, s.failed, s.skipped
                ))),
                Err(e) => notice.set(Some(e)),
            }
            busy.set(false);
            load();
            refresh.run(());
        })
    };
    let scan_one = move |id: i64, name: String| {
        busy.set(true);
        spawn_local(async move {
            match api::scan_docker(id).await {
                Ok(_) => notice.set(Some(format!("Scanned {name}."))),
                Err(e) => notice.set(Some(format!("{name}: {e}"))),
            }
            busy.set(false);
            load();
            refresh.run(());
        })
    };
    let open_update = move |id: i64, host: String, project: String| {
        spawn_local(async move {
            match api::compose_update_preview(id, project.clone()).await {
                Ok(commands) => dialog.set(Some(UpdateDialog { id, host, project, commands })),
                Err(e) => notice.set(Some(e)),
            }
        })
    };
    let confirm_update = move |_| {
        let Some(d) = dialog.get_untracked() else { return };
        dialog.set(None);
        busy.set(true);
        notice.set(Some(format!("Updating {} on {}...", d.project, d.host)));
        spawn_local(async move {
            match api::update_compose(d.id, d.project).await {
                Ok(m) | Err(m) => notice.set(Some(m)),
            }
            busy.set(false);
            load();
            refresh.run(());
        })
    };

    let count = move |f: fn(&api::ContainerRow) -> bool| {
        hosts.with(|h| h.iter().flat_map(|h| h.containers.iter()).filter(|c| f(c)).count())
    };

    view! {
        <div class="stats">
            <div class="stat"><div class="stat-value">{move || hosts.with(|h| h.len())}</div><div class="stat-label">"Docker hosts"</div></div>
            <div class="stat"><div class="stat-value">{move || count(|_| true)}</div><div class="stat-label">"Containers"</div></div>
            <div class="stat"><div class="stat-value">{move || count(|c| c.state == "running")}</div><div class="stat-label">"Running"</div></div>
            <div class="stat"><div class="stat-value">{move || count(|c| c.update_available == Some(true))}</div><div class="stat-label">"Image updates"</div></div>
        </div>
        <div class="toolbar">
            <button class="btn primary" on:click=scan_all disabled=move || busy.get()>"Scan Docker hosts"</button>
            <crate::patches::StatusLine notice=notice working=Signal::derive(move || busy.get()) />
        </div>
        <p class="muted small">"Scans are read-only. They compare local image digests with the registry without pulling. Mark Docker hosts in your host list."</p>
        <For each=move || hosts.get() key=|h| (h.host_id, h.docker_scan_at, h.containers.len()) let:h>
            {
                let id = h.host_id;
                let trusted = h.host_key_trusted;
                let host_name = h.name.clone();
                let name_scan = h.name.clone();
                let status = match (&h.docker_error, h.docker_scan_at, trusted) {
                    (_, _, false) => view! { <span class="muted">"Verify key in Hosts"</span> }.into_any(),
                    (Some(e), _, _) => view! { <span class="pill bad" title=e.clone()>"Scan failed"</span> }.into_any(),
                    (None, None, _) => view! { <span class="muted">"Not scanned"</span> }.into_any(),
                    _ => view! { <span class="muted">{format!("Scanned {}", ago(h.docker_scan_at))}</span> }.into_any(),
                };
                view! {
                    <section class="card docker-host">
                        <div class="toolbar host-head">
                            <h2>{h.name.clone()}</h2>
                            {status}
                            <span class="spacer"></span>
                            <button class="btn small primary" disabled=move || !trusted || busy.get()
                                on:click=move |_| scan_one(id, name_scan.clone())>"Scan"</button>
                        </div>
                        <Show when={let empty = h.containers.is_empty(); move || !empty}>
                            <table class="table docker-table">
                                <colgroup><col class="c-name"/><col class="c-image"/><col class="c-project"/><col class="c-state"/><col class="c-update"/><col class="c-action"/></colgroup>
                                <thead><tr><th>"Container"</th><th>"Image"</th><th>"Project"</th><th>"State"</th><th>"Image update"</th><th></th></tr></thead>
                                <tbody>
                                    {h.containers.clone().into_iter().map(|c| {
                                        let host = host_name.clone();
                                        let note = c.update_note.clone();
                                        let pinned = note.as_deref().is_some_and(|n| n.starts_with("Pinned"));
                                        let update = match c.update_available {
                                            Some(true) => view! { <span class="pill warn">"Available"</span> }.into_any(),
                                            Some(false) => view! { <span class="pill ok">"Current"</span> }.into_any(),
                                            None if pinned => view! { <span class="pill held" title=note.clone().unwrap_or_default()>"Pinned"</span> }.into_any(),
                                            None => view! {
                                                <span class="muted unknown" title=note.clone().unwrap_or_else(|| "Scan again to check this image.".into())>"Unknown"</span>
                                            }.into_any(),
                                        };
                                        let action = match (c.project.clone(), c.update_available, c.config_file.is_some()) {
                                            (Some(p), Some(true), true) => view! {
                                                <button class="btn small" disabled=move || busy.get()
                                                    on:click=move |_| open_update(id, host.clone(), p.clone())>"Update project"</button>
                                            }.into_any(),
                                            _ => ().into_any(),
                                        };
                                        view! {
                                            <tr>
                                                <td class="mono">{c.name}</td>
                                                <td class="mono">{c.image}</td>
                                                <td>{c.project.unwrap_or_else(|| "-".into())}</td>
                                                <td title=c.status>{c.state}</td>
                                                <td>{update}</td>
                                                <td class="actions">{action}</td>
                                            </tr>
                                        }
                                    }).collect_view()}
                                </tbody>
                            </table>
                        </Show>
                    </section>
                }
            }
        </For>

        <Show when=move || dialog.with(|d| d.is_some())>
            <div class="modal-backdrop">
                <div class="modal wide">
                    {move || dialog.get().map(|d| view! {
                        <h2>{format!("Update {} on {}?", d.project, d.host)}</h2>
                        <p>"QuietKeep will pull new images and recreate changed containers with exactly these commands:"</p>
                        {d.commands.iter().map(|c| view! { <p class="fingerprint mono">{c.clone()}</p> }).collect_view()}
                        <div class="modal-actions">
                            <button class="btn" on:click=move |_| dialog.set(None)>"Cancel"</button>
                            <button class="btn danger" on:click=confirm_update>"Update"</button>
                        </div>
                    })}
                </div>
            </div>
        </Show>
    }
}
