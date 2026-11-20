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

#[derive(Clone)]
struct TagDialog {
    id: i64,
    host: String,
    container: String,
    pin: bool,
    preview: api::TagUpdatePreview,
}

#[derive(Clone)]
struct MoveDialog {
    id: i64,
    host: String,
    container: String,
    preview: api::MovePreview,
}

/// Database images whose data format can change between major versions.
fn is_database(image: &str) -> bool {
    let name = image.split('@').next().unwrap_or(image);
    let name = name.rsplit('/').next().unwrap_or(name);
    let name = name.split(':').next().unwrap_or(name);
    name.contains("postgres") || name.contains("postgis") || ["mysql", "mariadb", "mongo", "timescaledb"].contains(&name)
}

#[component]
pub fn DockerPanel(refresh: Callback<()>) -> impl IntoView {
    let hosts = RwSignal::new(Vec::<DockerHost>::new());
    let notice = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let dialog = RwSignal::new(None::<UpdateDialog>);
    let tag_dialog = RwSignal::new(None::<TagDialog>);
    let move_dialog = RwSignal::new(None::<MoveDialog>);
    let registry = RwSignal::new(None::<bool>);
    spawn_local(async move {
        if let Ok(r) = api::registry_state().await {
            registry.set(r);
        }
    });

    let load = move || {
        spawn_local(async move {
            match api::docker_status().await {
                Ok(v) => hosts.set(v),
                Err(e) => notice.set(Some(e)),
            }
        })
    };
    load();

    let scan_all = move |_: ()| {
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

    let set_registry = move |allowed: bool| {
        spawn_local(async move {
            match api::registry_set_allowed(allowed).await {
                Ok(a) => {
                    registry.set(Some(a));
                    if a {
                        scan_all(());
                    }
                }
                Err(e) => notice.set(Some(e)),
            }
        })
    };
    let open_tag = move |id: i64, host: String, container: String, major: bool| {
        spawn_local(async move {
            match api::docker_tag_preview(id, container.clone(), major).await {
                Ok(preview) => tag_dialog.set(Some(TagDialog { id, host, container, pin: false, preview })),
                Err(e) => notice.set(Some(e)),
            }
        })
    };
    let open_pin = move |id: i64, host: String, container: String| {
        spawn_local(async move {
            match api::docker_pin_preview(id, container.clone()).await {
                Ok(preview) => tag_dialog.set(Some(TagDialog { id, host, container, pin: true, preview })),
                Err(e) => notice.set(Some(e)),
            }
        })
    };
    let open_move = move |id: i64, host: String, container: String| {
        notice.set(Some(format!("Reading the settings of {container} on {host}...")));
        busy.set(true);
        spawn_local(async move {
            let r = api::docker_move_preview(id, container.clone()).await;
            busy.set(false);
            match r {
                Ok(preview) => {
                    notice.set(None);
                    move_dialog.set(Some(MoveDialog { id, host, container, preview }));
                }
                Err(e) => notice.set(Some(e)),
            }
        })
    };
    let confirm_move = move |_| {
        let Some(d) = move_dialog.get_untracked() else { return };
        move_dialog.set(None);
        busy.set(true);
        notice.set(Some(format!("Moving {} on {} to docker compose...", d.container, d.host)));
        spawn_local(async move {
            match api::docker_move_to_compose(d.id, d.container).await {
                Ok(m) | Err(m) => notice.set(Some(m)),
            }
            busy.set(false);
            load();
            refresh.run(());
        })
    };
    let confirm_tag = move |_| {
        let Some(d) = tag_dialog.get_untracked() else { return };
        tag_dialog.set(None);
        busy.set(true);
        notice.set(Some(format!("Updating {} on {} to {}...", d.container, d.host, d.preview.new_image)));
        spawn_local(async move {
            let r = if d.pin {
                api::docker_update_pin(d.id, d.container).await
            } else {
                api::docker_update_tag(d.id, d.container, d.preview.major).await
            };
            match r {
                Ok(m) | Err(m) => notice.set(Some(m)),
            }
            busy.set(false);
            load();
            refresh.run(());
        })
    };

    let remove_dialog = RwSignal::new(None::<(i64, String, String)>);
    let confirm_remove = move |_| {
        let Some((id, host, container)) = remove_dialog.get_untracked() else { return };
        remove_dialog.set(None);
        busy.set(true);
        notice.set(Some(format!("Removing {container} from {host}...")));
        spawn_local(async move {
            match api::docker_remove_rollback(id, container).await {
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
            <button class="btn primary" on:click=move |_| scan_all(()) disabled=move || busy.get()>"Scan Docker hosts"</button>
            <crate::patches::StatusLine notice=notice working=Signal::derive(move || busy.get()) />
        </div>
        <p class="muted small">"Scans are read-only and never pull images. Mark Docker hosts in your host list."
            <Show when=move || registry.get() == Some(true)>
                " Release checks are on. "
                <button class="btn small" on:click=move |_| set_registry(false)>"Turn off release checks"</button>
            </Show>
        </p>
        <Show when=move || registry.get() != Some(true)>
            <section class="card permission-card">
                <h3>"Check for new releases?"</h3>
                <p>"To find newer versions of your images, QuietKeep reads tag lists and digests from the registries they come from, such as Docker Hub, ghcr.io and codeberg.org. It never logs in or pulls anything. Without this, QuietKeep can only ask each host's docker buildx whether the same tag was rebuilt, so new releases are missed."</p>
                <div class="modal-actions">
                    <Show when=move || registry.get().is_none()>
                        <button class="btn" on:click=move |_| set_registry(false)>"Not now"</button>
                    </Show>
                    <button class="btn primary" on:click=move |_| set_registry(true)>"Allow release checks"</button>
                </div>
            </section>
        </Show>
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
                                    {h.containers.clone().into_iter().filter(|c| !(c.name.ends_with("-old") && c.state != "running")).map(|c| {
                                        let host = host_name.clone();
                                        let note = c.update_note.clone().unwrap_or_default();
                                        let kind = c.update_kind.clone().unwrap_or_default();
                                        let latest = c.latest_tag.clone().unwrap_or_default();
                                        let major = c.major_tag.clone().unwrap_or_default();
                                        let compose = c.config_file.is_some();
                                        let rollback = c.name.ends_with("-old") && c.state != "running";
                                        let update = match (kind.as_str(), c.update_available) {
                                            _ if rollback => view! { <span class="pill held" title="A stopped copy kept so an update or move can be undone. Remove it with docker rm once the new container works.">"Kept for rollback"</span> }.into_any(),
                                            ("release", _) => view! { <span class="pill warn" title=note.clone()>{format!("{latest} available")}</span> }.into_any(),
                                            ("rebuild", _) => view! { <span class="pill warn" title="The same tag now points to a newer build">"New build"</span> }.into_any(),
                                            ("major", _) => view! { <span class="pill held" title=note.clone()>{format!("Major {major} available")}</span> }.into_any(),
                                            ("pinned-current", _) => view! { <span class="pill held" title=note.clone()>"Pinned, up to date"</span> }.into_any(),
                                            ("pinned-behind", _) => view! { <span class="pill bad" title=note.clone()>"Pinned, behind"</span> }.into_any(),
                                            (_, Some(true)) => view! { <span class="pill warn">"Available"</span> }.into_any(),
                                            (_, Some(false)) => view! { <span class="pill ok">"Current"</span> }.into_any(),
                                            (_, None) if note.starts_with("Pinned") => view! { <span class="pill held" title=note.clone()>"Pinned"</span> }.into_any(),
                                            (_, None) => {
                                                let tip = if note.is_empty() { "Scan again to check this image.".to_string() } else { note.clone() };
                                                view! { <span class="muted unknown" title=tip>"Unknown"</span> }.into_any()
                                            }
                                        };
                                        let cname = c.name.clone();
                                        let host_t = host.clone();
                                        let database = is_database(&c.image);
                                        let running = c.state == "running";
                                        let action = match (kind.as_str(), c.project.clone(), compose) {
                                            _ if rollback => ().into_any(),
                                            ("pinned-behind", _, true) => view! {
                                                <button class="btn small warn" disabled=move || busy.get()
                                                    title="Point the pin at the newest build of the same tag"
                                                    on:click=move |_| open_pin(id, host_t.clone(), cname.clone())>"Move pin"</button>
                                            }.into_any(),
                                            (_, None, false) if running => view! {
                                                <button class="btn small" disabled=move || busy.get()
                                                    title="Create a compose file from this container's settings so QuietKeep can update it"
                                                    on:click=move |_| open_move(id, host_t.clone(), cname.clone())>"Move to compose"</button>
                                            }.into_any(),
                                            ("release", _, true) => {
                                                let label = format!("Update to {latest}");
                                                view! {
                                                    <button class="btn small warn" disabled=move || busy.get()
                                                        on:click=move |_| open_tag(id, host_t.clone(), cname.clone(), false)>{label}</button>
                                                }.into_any()
                                            }
                                            ("major", _, true) if !database => {
                                                let label = format!("Upgrade to {major}");
                                                view! {
                                                    <button class="btn small" disabled=move || busy.get() title="Major release: read its release notes first"
                                                        on:click=move |_| open_tag(id, host_t.clone(), cname.clone(), true)>{label}</button>
                                                }.into_any()
                                            }
                                            ("release" | "major", _, false) => view! {
                                                <span class="muted unknown" title="Not started with docker compose, so QuietKeep cannot change its image. Pull the new image and recreate the container by hand.">"Update by hand"</span>
                                            }.into_any(),
                                            ("rebuild" | "", Some(p), true) if c.update_available == Some(true) => view! {
                                                <button class="btn small warn" disabled=move || busy.get()
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
                            {
                                let olds: Vec<api::ContainerRow> = h.containers.iter().filter(|c| c.name.ends_with("-old") && c.state != "running").cloned().collect();
                                let hn = host_name.clone();
                                (!olds.is_empty()).then(move || view! {
                                    <div class="rollback-list">
                                        {olds.into_iter().map(|c| {
                                            let days = c.stopped_days.unwrap_or(0);
                                            let due = days >= 30;
                                            let cname = c.name.clone();
                                            let hn = hn.clone();
                                            let text = format!("Rollback copy {} ({}), stopped {} days ago.", c.name, c.image, days);
                                            view! {
                                                <div class={if due { "rollback due" } else { "rollback" }}>
                                                    <span>{text}</span>
                                                    {due.then(|| view! { <span>" Kept for 30 days. Remove it?"</span> })}
                                                    <button class={if due { "btn small warn" } else { "btn small" }} disabled=move || busy.get()
                                                        on:click=move |_| remove_dialog.set(Some((id, hn.clone(), cname.clone())))>"Remove"</button>
                                                </div>
                                            }
                                        }).collect_view()}
                                    </div>
                                })
                            }
                        </Show>
                    </section>
                }
            }
        </For>

        <Show when=move || tag_dialog.with(|d| d.is_some())>
            <div class="modal-backdrop">
                <div class="modal wide">
                    {move || tag_dialog.get().map(|d| view! {
                        <h2>{if d.pin { format!("Move the pin of {} on {}?", d.container, d.host) } else { format!("Update {} on {}?", d.container, d.host) }}</h2>
                        <p>{format!("QuietKeep will back up {}, change this one line and then pull and recreate the project:", d.preview.file)}</p>
                        <p class="fingerprint mono">{format!("image: {}", d.preview.old_image)}</p>
                        <p class="fingerprint mono">{format!("image: {}", d.preview.new_image)}</p>
                        {d.preview.major.then(|| view! {
                            <p class="error">"This is a new major release. Read its release notes first, because major releases can change settings or data."</p>
                        })}
                        <p class="muted">"Exact steps:"</p>
                        {d.preview.commands.iter().map(|c| view! { <p class="fingerprint mono">{c.clone()}</p> }).collect_view()}
                        <div class="modal-actions">
                            <button class="btn" on:click=move |_| tag_dialog.set(None)>"Cancel"</button>
                            <button class="btn warn" on:click=confirm_tag>{if d.pin { "Move pin".to_string() } else { format!("Update to {}", d.preview.new_image) }}</button>
                        </div>
                    })}
                </div>
            </div>
        </Show>
        <Show when=move || remove_dialog.with(|d| d.is_some())>
            <div class="modal-backdrop">
                <div class="modal">
                    {move || remove_dialog.get().map(|(_, host, container)| view! {
                        <h2>{format!("Remove {container} from {host}?")}</h2>
                        <p>"This deletes the stopped rollback copy, so you can no longer switch back to it. Data volumes are not touched, and the running container keeps all its data."</p>
                        <div class="modal-actions">
                            <button class="btn" on:click=move |_| remove_dialog.set(None)>"Cancel"</button>
                            <button class="btn danger" on:click=confirm_remove>"Remove rollback copy"</button>
                        </div>
                    })}
                </div>
            </div>
        </Show>
        <Show when=move || move_dialog.with(|d| d.is_some())>
            <div class="modal-backdrop">
                <div class="modal wide">
                    {move || move_dialog.get().map(|d| {
                        let blocked = !d.preview.unsupported.is_empty();
                        view! {
                            <h2>{format!("Move {} on {} to docker compose?", d.container, d.host)}</h2>
                            <p>{format!("QuietKeep will create {} from the container's current settings. Values of environment variables are hidden here but kept in the file.", d.preview.file)}</p>
                            <pre class="fingerprint mono yaml">{d.preview.yaml.clone()}</pre>
                            {blocked.then(|| view! {
                                <p class="error">{format!("QuietKeep cannot copy these settings, so move this container by hand: {}.", d.preview.unsupported.join(", "))}</p>
                            })}
                            <p class="muted">"Exact steps:"</p>
                            {d.preview.steps.iter().map(|c| view! { <p class="fingerprint mono">{c.clone()}</p> }).collect_view()}
                            <div class="modal-actions">
                                <button class="btn" on:click=move |_| move_dialog.set(None)>"Cancel"</button>
                                <button class="btn warn" disabled=blocked on:click=confirm_move>"Move to compose"</button>
                            </div>
                        }
                    })}
                </div>
            </div>
        </Show>
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
