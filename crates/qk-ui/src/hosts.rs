use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::api::{self, Host, HostKeyProbe, ImportReport};

#[derive(Clone)]
struct BulkItem {
    host: Host,
    fingerprint: Option<String>,
    status: String,
    ok: Option<bool>,
}

#[component]
pub fn HostsPanel(hosts: RwSignal<Vec<Host>>, refresh: Callback<()>) -> impl IntoView {
    let preview = RwSignal::new(None::<ImportReport>);
    let notice = RwSignal::new(None::<String>);
    let pending_delete = RwSignal::new(None::<Host>);
    let delete_typed = RwSignal::new(String::new());
    let probe = RwSignal::new(None::<(Host, HostKeyProbe)>);
    let access_key = RwSignal::new(None::<String>);
    let busy = RwSignal::new(None::<i64>);
    let setup = RwSignal::new(None::<(Host, api::AccessPreview)>);
    let setup_password = RwSignal::new(String::new());
    let setup_sudoers = RwSignal::new(true);
    let setup_agent = RwSignal::new(true);
    let setup_busy = RwSignal::new(false);
    let setup_error = RwSignal::new(None::<String>);
    let bulk = RwSignal::new(None::<Vec<BulkItem>>);
    let bulk_password = RwSignal::new(String::new());
    let bulk_sudoers = RwSignal::new(true);
    let bulk_busy = RwSignal::new(false);
    let bulk_done = RwSignal::new(false);
    let set_item = move |i: usize, status: String, ok: Option<bool>, fp: Option<String>| {
        bulk.update(|b| {
            if let Some(it) = b.as_mut().and_then(|b| b.get_mut(i)) {
                it.status = status;
                it.ok = ok;
                if fp.is_some() {
                    it.fingerprint = fp;
                }
            }
        })
    };
    let open_bulk = move |_| {
        let targets: Vec<Host> = hosts.get_untracked().into_iter().filter(|h| !h.access_ok).collect();
        if targets.is_empty() {
            notice.set(Some("Every host is already set up.".into()));
            return;
        }
        bulk_password.set(String::new());
        bulk_done.set(false);
        bulk.set(Some(
            targets
                .iter()
                .map(|h| BulkItem {
                    host: h.clone(),
                    fingerprint: h.host_key.clone(),
                    status: if h.host_key_trusted { "Key already trusted".into() } else { "Checking host key...".into() },
                    ok: None,
                })
                .collect(),
        ));
        for (i, h) in targets.into_iter().enumerate() {
            if h.host_key_trusted {
                continue;
            }
            spawn_local(async move {
                match api::probe_host_key(h.id).await {
                    Ok(p) => set_item(i, "Ready".into(), None, Some(format!("{} {}", p.algorithm, p.fingerprint))),
                    Err(e) => set_item(i, format!("Unreachable: {e}"), Some(false), None),
                }
            });
        }
    };
    let run_bulk = move |_| {
        let Some(items) = bulk.get_untracked() else { return };
        let password = bulk_password.get_untracked();
        let sudoers = bulk_sudoers.get_untracked();
        bulk_busy.set(true);
        spawn_local(async move {
            for (i, it) in items.into_iter().enumerate() {
                if it.ok == Some(false) {
                    continue;
                }
                let Some(fp) = it.fingerprint.clone() else { continue };
                set_item(i, "Setting up...".into(), None, None);
                if !it.host.host_key_trusted {
                    let raw = fp.split_whitespace().last().unwrap_or("").to_string();
                    if let Err(e) = api::trust_host_key(it.host.id, raw).await {
                        set_item(i, e, Some(false), None);
                        continue;
                    }
                }
                match api::setup_access(it.host.id, true, password.clone(), sudoers).await {
                    Ok(_) => set_item(i, "Ready".into(), Some(true), None),
                    Err(e) => set_item(i, e, Some(false), None),
                }
            }
            bulk_busy.set(false);
            bulk_done.set(true);
            refresh.run(());
        });
    };
    let load_setup = move |h: Host| {
        let sudoers = setup_sudoers.get_untracked();
        let agent = setup_agent.get_untracked();
        spawn_local(async move {
            match api::setup_access_preview(h.id, agent, sudoers).await {
                Ok(p) => setup.set(Some((h, p))),
                Err(e) => notice.set(Some(format!("{}: {e}", h.spec.name))),
            }
        })
    };
    let open_setup = move |h: Host| {
        setup_password.set(String::new());
        setup_error.set(None);
        load_setup(h);
    };
    let run_setup = move |_| {
        let Some((h, _)) = setup.get_untracked() else { return };
        let password = setup_password.get_untracked();
        let agent = setup_agent.get_untracked();
        if password.is_empty() && !agent {
            setup_error.set(Some("Enter the password for this host.".into()));
            return;
        }
        setup_busy.set(true);
        setup_error.set(None);
        spawn_local(async move {
            let result = api::setup_access(h.id, agent, password, setup_sudoers.get_untracked()).await;
            setup_password.set(String::new());
            setup_busy.set(false);
            match result {
                Ok(msg) => {
                    setup.set(None);
                    notice.set(Some(msg));
                }
                Err(e) => setup_error.set(Some(e)),
            }
            refresh.run(());
        })
    };

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
            match api::trust_host_key(h.id, p.fingerprint.clone()).await {
                Ok(_) => {
                    notice.set(Some(format!("Trusted the host key for {}.", h.spec.name)));
                    let mut trusted = h.clone();
                    trusted.host_key = Some(p.fingerprint.clone());
                    open_setup(trusted);
                }
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
            <button class="btn primary" on:click=open_bulk disabled=move || hosts.with(|h| h.iter().all(|h| h.access_ok))>
                "Set up all hosts"
            </button>
            <button class="btn" on:click=show_access_key>"Show public key"</button>
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
                    <For each=move || hosts.get() key=|h| (h.id, h.host_key.clone(), h.access_ok) let:host>
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
                                        {if trusted && h_ssh.access_ok {
                                            view! {
                                                <button class="btn small" disabled=move || busy.get() == Some(id)
                                                    on:click={let h = h_ssh.clone(); move |_| test(h.clone())}>"Test"</button>
                                                <button class="btn small" disabled=true title="QuietKeep's key works on this host">"Access ready"</button>
                                            }.into_any()
                                        } else if trusted {
                                            view! {
                                                <button class="btn small" disabled=move || busy.get() == Some(id)
                                                    on:click={let h = h_ssh.clone(); move |_| test(h.clone())}>"Test"</button>
                                                <button class="btn small primary" disabled=move || busy.get() == Some(id)
                                                    on:click={let h = h_ssh.clone(); move |_| open_setup(h.clone())}>"Set up access"</button>
                                            }.into_any()
                                        } else {
                                            view! {
                                                <button class="btn small primary" disabled=move || busy.get() == Some(id)
                                                    title="Checks the host's SSH fingerprint first, then installs QuietKeep's key"
                                                    on:click=move |_| verify(h_ssh.clone())>"Set up access"</button>
                                            }.into_any()
                                        }}
                                        <button class="btn small subtle" on:click=move |_| { delete_typed.set(String::new()); pending_delete.set(Some(h.clone())); }>
                                            "Delete host"
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
                    <h2>"Set up access"</h2>
                    {move || probe.get().map(|(h, p)| view! {
                        <p>{format!("{} ({}) presented this SSH host key:", h.spec.name, h.spec.address)}</p>
                        <p class="fingerprint mono">{format!("{} {}", p.algorithm, p.fingerprint).trim().to_string()}</p>
                        {p.changed_from.map(|old| view! {
                            <p class="error">{format!(
                                "This key is different from the one you trusted before ({old}). Only continue if you rebuilt or reinstalled this host."
                            )}</p>
                        })}
                        <p>"Click Trust and set up access. QuietKeep then logs in once with your own SSH key and installs its key for you."</p>
                        <details class="muted">
                            <summary>"Optional: check the fingerprint yourself"</summary>
                            <p>"Run this on the host and compare:"</p>
                            <p class="fingerprint mono">"for f in /etc/ssh/ssh_host_*_key.pub; do ssh-keygen -lf \"$f\"; done"</p>
                        </details>
                    })}
                    <div class="modal-actions">
                        <button class="btn" on:click=move |_| probe.set(None)>"Cancel"</button>
                        <button class="btn primary" on:click=confirm_trust>"Trust and set up access"</button>
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

        <Show when=move || bulk.with(|b| b.is_some())>
            <div class="modal-backdrop">
                <div class="modal wide">
                    <h2>"Set up all hosts"</h2>
                    <p>"QuietKeep logs in to each host once with your own SSH key (ssh-agent), adds its key and fixes ~/.ssh permissions. Trusting a host also pins the fingerprint shown below."</p>
                    <label class="check">
                        <input type="checkbox" prop:checked=move || bulk_sudoers.get()
                            on:change=move |ev| bulk_sudoers.set(event_target_checked(&ev)) />
                        " Also allow patching and rebooting (installs the sudoers rule)"
                    </label>
                    <Show when=move || bulk_sudoers.get()>
                        <input class="search" type="password" autocomplete="off"
                            placeholder="sudo password, used for every host and not saved (leave empty if sudo needs none)"
                            prop:value=move || bulk_password.get()
                            on:input=move |ev| bulk_password.set(event_target_value(&ev)) />
                    </Show>
                    <table class="table">
                        <thead><tr><th>"Host"</th><th>"Fingerprint"</th><th>"Status"</th></tr></thead>
                        <tbody>
                            {move || bulk.get().unwrap_or_default().into_iter().map(|it| {
                                let class = match it.ok { Some(true) => "ok", Some(false) => "error", None => "muted" };
                                view! {
                                    <tr>
                                        <td>{it.host.spec.name.clone()}</td>
                                        <td class="mono small">{it.fingerprint.clone().unwrap_or_default()}</td>
                                        <td class=class>{it.status.clone()}</td>
                                    </tr>
                                }
                            }).collect_view()}
                        </tbody>
                    </table>
                    <div class="modal-actions">
                        <button class="btn" disabled=move || bulk_busy.get() on:click=move |_| bulk.set(None)>
                            {move || if bulk_done.get() { "Close" } else { "Cancel" }}
                        </button>
                        <Show when=move || !bulk_done.get()>
                            <button class="btn primary" disabled=move || bulk_busy.get() on:click=run_bulk>
                                {move || {
                                    let n = bulk.with(|b| b.as_ref().map(|b| b.iter().filter(|i| i.ok != Some(false) && i.fingerprint.is_some()).count()).unwrap_or(0));
                                    format!("Trust and set up {n} hosts")
                                }}
                            </button>
                        </Show>
                    </div>
                </div>
            </div>
        </Show>
        <Show when=move || pending_delete.with(|p| p.is_some())>
            <div class="modal-backdrop">
                <div class="modal">
                    <h2>"Remove host"</h2>
                    <p>{move || pending_delete.get().map(|h| format!("Remove {} from QuietKeep? Its trusted key and scan results are deleted. History stays in the activity log. Type the host name to confirm.", h.spec.name))}</p>
                    <input class="search" type="text" autocomplete="off" placeholder="Host name"
                        prop:value=move || delete_typed.get()
                        on:input=move |ev| delete_typed.set(event_target_value(&ev)) />
                    <div class="modal-actions">
                        <button class="btn" on:click=move |_| pending_delete.set(None)>"Cancel"</button>
                        <button class="btn danger"
                            disabled=move || pending_delete.with(|h| h.as_ref().map(|h| h.spec.name != delete_typed.get()).unwrap_or(true))
                            on:click=confirm_delete>"Delete host"</button>
                    </div>
                </div>
            </div>
        </Show>
        <Show when=move || setup.with(|s| s.is_some())>
            <div class="modal-backdrop">
                <div class="modal wide">
                    {move || setup.get().map(|(h, p)| {
                        let is_root = h.spec.username == "root";
                        view! {
                            <h2>{format!("Set up access on {}", h.spec.name)}</h2>
                            <div class="field">
                                <span>"Log in with"</span>
                                <label class="check">
                                    <input type="radio" name="setup-method" prop:checked=move || setup_agent.get()
                                        on:change={let h = h.clone(); move |_| { setup_agent.set(true); load_setup(h.clone()); }} />
                                    "My SSH key (ssh-agent)"
                                </label>
                                <label class="check">
                                    <input type="radio" name="setup-method" prop:checked=move || !setup_agent.get()
                                        on:change={let h = h.clone(); move |_| { setup_agent.set(false); load_setup(h.clone()); }} />
                                    "Password"
                                </label>
                            </div>
                            <p>{format!("For {}@{}, QuietKeep will:", h.spec.username, h.spec.address)}</p>
                            <ol class="steps">{p.steps.iter().map(|s| view! { <li>{s.clone()}</li> }).collect_view()}</ol>
                            <Show when=move || !setup_agent.get() || (setup_sudoers.get() && !is_root)>
                                <input class="search" type="password" autocomplete="off"
                                    placeholder=move || if setup_agent.get() { "sudo password (leave empty if sudo needs none)" } else { "SSH password" }
                                    prop:value=move || setup_password.get()
                                    on:input=move |ev| setup_password.set(event_target_value(&ev)) />
                            </Show>
                            <Show when=move || !is_root>
                                <label class="check">
                                    <input type="checkbox" prop:checked=move || setup_sudoers.get()
                                        on:change={let h = h.clone(); move |ev| { setup_sudoers.set(event_target_checked(&ev)); load_setup(h.clone()); }} />
                                    " Also allow patching and rebooting (installs the sudoers rule)"
                                </label>
                            </Show>
                            {p.rule.clone().map(|r| view! { <textarea class="keybox mono" readonly rows="6">{r}</textarea> })}
                            <p class="muted small">{format!("Key to install: {}", p.public_key)}</p>
                            {move || setup_error.get().map(|e| view! { <p class="pill bad">{e}</p> })}
                            <div class="modal-actions">
                                <button class="btn" on:click=move |_| { setup_password.set(String::new()); setup.set(None); }>"Cancel"</button>
                                <button class="btn primary" disabled=move || setup_busy.get() on:click=run_setup>
                                    {move || if setup_busy.get() { "Setting up..." } else { "Set up access" }}
                                </button>
                            </div>
                        }
                    })}
                </div>
            </div>
        </Show>
    }
}
