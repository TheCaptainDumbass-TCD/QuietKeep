use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::api::{self, Host, HostKeyProbe, ImportReport};

#[component]
pub fn HostsPanel(hosts: RwSignal<Vec<Host>>, refresh: Callback<()>) -> impl IntoView {
    let preview = RwSignal::new(None::<ImportReport>);
    let notice = RwSignal::new(None::<String>);
    let pending_delete = RwSignal::new(None::<Host>);
    let probe = RwSignal::new(None::<(Host, HostKeyProbe)>);
    let access_key = RwSignal::new(None::<String>);
    let busy = RwSignal::new(None::<i64>);

    let verify = move |h: Host| {
        busy.set(Some(h.id));
        spawn_local(async move {
            match api::probe_host_key(h.id).await {
                Ok(p) => probe.set(Some((h, p))),
                Err(e) => notice.set(Some(format!("{}: {e}", h.spec.name))),
            }
            busy.set(None);
        })
    };
    let confirm_trust = move |_| {
        let Some((h, p)) = probe.get_untracked() else { return };
        probe.set(None);
        spawn_local(async move {
            match api::trust_host_key(h.id, p.fingerprint).await {
                Ok(_) => notice.set(Some(format!("Trusted the host key for {}.", h.spec.name))),
                Err(e) => notice.set(Some(format!("{}: {e}", h.spec.name))),
            }
            refresh.run(());
        })
    };
    let test = move |h: Host| {
        busy.set(Some(h.id));
        spawn_local(async move {
            match api::test_connection(h.id).await {
                Ok(system) => notice.set(Some(format!("{}: connected ({system}).", h.spec.name))),
                Err(e) => notice.set(Some(format!("{}: {e}", h.spec.name))),
            }
            busy.set(None);
            refresh.run(());
        })
    };
    let show_access_key = move |_| {
        spawn_local(async move {
            match api::client_public_key().await {
                Ok(k) => access_key.set(Some(k)),
                Err(e) => notice.set(Some(format!("Could not read the access key: {e}"))),
            }
        })
    };

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
            <button class="btn" on:click=show_access_key>"Access key"</button>
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
                    <For each=move || hosts.get() key=|h| (h.id, h.host_key.clone()) let:host>
                        {
                            let h = host.clone();
                            let h_ssh = host.clone();
                            let id = host.id;
                            let trusted = host.host_key_trusted;
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
                                    <td class="actions">
                                        {if trusted {
                                            view! {
                                                <button class="btn small" disabled=move || busy.get() == Some(id)
                                                    on:click=move |_| test(h_ssh.clone())>"Test"</button>
                                            }.into_any()
                                        } else {
                                            view! {
                                                <button class="btn small primary" disabled=move || busy.get() == Some(id)
                                                    on:click=move |_| verify(h_ssh.clone())>"Verify key"</button>
                                            }.into_any()
                                        }}
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

        <Show when=move || probe.with(|p| p.is_some())>
            <div class="modal-backdrop">
                <div class="modal">
                    <h2>"Verify host key"</h2>
                    {move || probe.get().map(|(h, p)| view! {
                        <p>{format!("{} ({}) presented this SSH host key:", h.spec.name, h.spec.address)}</p>
                        <p class="fingerprint mono">{format!("{} {}", p.algorithm, p.fingerprint).trim().to_string()}</p>
                        {p.changed_from.map(|old| view! {
                            <p class="error">{format!(
                                "This key is different from the one you trusted before ({old}). Only continue if you rebuilt or reinstalled this host."
                            )}</p>
                        })}
                        <p class="muted">"To confirm it, run this on the host and compare the fingerprint:"</p>
                        <p class="fingerprint mono">"for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf \"$f\"; done"</p>
                    })}
                    <div class="modal-actions">
                        <button class="btn" on:click=move |_| probe.set(None)>"Cancel"</button>
                        <button class="btn primary" on:click=confirm_trust>"Trust this key"</button>
                    </div>
                </div>
            </div>
        </Show>

        <Show when=move || access_key.with(|k| k.is_some())>
            <div class="modal-backdrop">
                <div class="modal">
                    <h2>"QuietKeep access key"</h2>
                    <p>"QuietKeep signs in with its own key, never your personal keys. Add this line to ~/.ssh/authorized_keys for the host user on each system you want it to manage."</p>
                    <textarea class="keybox mono" readonly rows="3">{move || access_key.get().unwrap_or_default()}</textarea>
                    <div class="modal-actions">
                        <button class="btn primary" on:click=move |_| access_key.set(None)>"Done"</button>
                    </div>
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
