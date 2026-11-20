use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::api::{self, Host, ImportReport};

#[component]
pub fn HostsPanel(hosts: RwSignal<Vec<Host>>, refresh: Callback<()>) -> impl IntoView {
    let preview = RwSignal::new(None::<ImportReport>);
    let notice = RwSignal::new(None::<String>);
    let pending_delete = RwSignal::new(None::<Host>);

    let start_import = move |_| {
        spawn_local(async move {
            match api::pick_import_csv().await {
                Ok(report) => preview.set(report),
                Err(e) => notice.set(Some(format!("Import failed: {e}"))),
            }
        })
    };
    let confirm_import = move |_| {
        let Some(report) = preview.get_untracked() else { return };
        preview.set(None);
        spawn_local(async move {
            match api::commit_import(report.hosts).await {
                Ok(n) => notice.set(Some(format!("Imported {n} hosts."))),
                Err(e) => notice.set(Some(format!("Import failed: {e}"))),
            }
            refresh.run(());
        })
    };
    let export = move |_| {
        spawn_local(async move {
            match api::export_hosts_csv().await {
                Ok(Some(n)) => notice.set(Some(format!("Exported {n} hosts."))),
                Ok(None) => {}
                Err(e) => notice.set(Some(format!("Export failed: {e}"))),
            }
        })
    };
    let confirm_delete = move |_| {
        let Some(host) = pending_delete.get_untracked() else { return };
        pending_delete.set(None);
        spawn_local(async move {
            if let Err(e) = api::delete_host(host.id).await {
                notice.set(Some(format!("Delete failed: {e}")));
            }
            refresh.run(());
        })
    };

    view! {
        <div class="toolbar">
            <button class="btn primary" on:click=start_import>"Import CSV"</button>
            <button class="btn" on:click=export disabled=move || hosts.with(|h| h.is_empty())>
                "Export CSV"
            </button>
            <span class="muted">{move || notice.get().unwrap_or_default()}</span>
        </div>

        <Show
            when=move || hosts.with(|h| !h.is_empty())
            fallback=|| view! {
                <section class="card">
                    <p class="muted">"No hosts yet. Import a CSV exported from QuietKeep to get started."</p>
                </section>
            }
        >
            <table class="table">
                <thead>
                    <tr>
                        <th>"Name"</th>
                        <th>"Address"</th>
                        <th>"User"</th>
                        <th>"OS"</th>
                        <th>"Patching"</th>
                        <th>"Docker"</th>
                        <th>"Host key"</th>
                        <th></th>
                    </tr>
                </thead>
                <tbody>
                    <For each=move || hosts.get() key=|h| h.id let:host>
                        {
                            let h = host.clone();
                            view! {
                                <tr>
                                    <td>{host.spec.name.clone()}</td>
                                    <td class="mono">{host.spec.address.clone()}</td>
                                    <td class="mono">{host.spec.username.clone()}</td>
                                    <td>{host.spec.os_type.clone()}</td>
                                    <td>{if host.spec.is_patch_target { "Yes" } else { "Monitor only" }}</td>
                                    <td>{if host.spec.has_docker { "Yes" } else { "No" }}</td>
                                    <td>
                                        {if host.host_key_trusted {
                                            view! { <span class="pill ok">"Trusted"</span> }
                                        } else {
                                            view! { <span class="pill warn">"Not verified"</span> }
                                        }}
                                    </td>
                                    <td>
                                        <button class="btn small" on:click=move |_| pending_delete.set(Some(h.clone()))>
                                            "Remove"
                                        </button>
                                    </td>
                                </tr>
                            }
                        }
                    </For>
                </tbody>
            </table>
        </Show>

        <Show when=move || preview.with(|p| p.is_some())>
            <div class="modal-backdrop">
                <div class="modal">
                    <h2>"Import hosts"</h2>
                    {move || preview.get().map(|r| {
                        let count = r.hosts.len();
                        view! {
                            <p>{format!("{} new hosts ready to import.", count)}</p>
                            <Show when={let d = r.duplicates.len(); move || d > 0}>
                                <p class="muted">{format!("{} already exist and will be skipped.", r.duplicates.len())}</p>
                            </Show>
                            <Show when={let e = r.errors.len(); move || e > 0}>
                                <p class="error">{format!("{} rows have errors and will be skipped:", r.errors.len())}</p>
                                <ul class="errors">
                                    {r.errors.iter().map(|e| view! { <li>{format!("Line {}: {}", e.line, e.message)}</li> }).collect_view()}
                                </ul>
                            </Show>
                            <p class="muted">"Imported hosts start unverified. QuietKeep asks you to confirm each host key on first connection."</p>
                            <div class="modal-actions">
                                <button class="btn" on:click=move |_| preview.set(None)>"Cancel"</button>
                                <button class="btn primary" disabled=count == 0 on:click=confirm_import>
                                    {format!("Import {count} hosts")}
                                </button>
                            </div>
                        }
                    })}
                </div>
            </div>
        </Show>

        <Show when=move || pending_delete.with(|p| p.is_some())>
            <div class="modal-backdrop">
                <div class="modal">
                    <h2>"Remove host"</h2>
                    <p>{move || pending_delete.get().map(|h| format!("Remove {} from QuietKeep? Its history stays in the activity log.", h.spec.name))}</p>
                    <div class="modal-actions">
                        <button class="btn" on:click=move |_| pending_delete.set(None)>"Cancel"</button>
                        <button class="btn danger" on:click=confirm_delete>"Remove"</button>
                    </div>
                </div>
            </div>
        </Show>
    }
}
