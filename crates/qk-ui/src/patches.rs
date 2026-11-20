use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::api::{self, PackageUpdate, PatchStatus, PrivilegeCheck};

#[derive(Clone)]
struct ActionDialog {
    id: i64,
    name: String,
    action: &'static str,
    check: PrivilegeCheck,
}

pub(crate) fn ago(ts: Option<i64>) -> String {
    let Some(ts) = ts else { return "Never".into() };
    let secs = ((js_sys::Date::now() / 1000.0) as i64 - ts).max(0);
    match secs {
        0..=59 => "Just now".into(),
        60..=3599 => format!("{} min ago", secs / 60),
        3600..=86399 => format!("{} h ago", secs / 3600),
        _ => format!("{} d ago", secs / 86400),
    }
}

#[component]
pub fn PatchesPanel(refresh: Callback<()>) -> impl IntoView {
    let rows = RwSignal::new(Vec::<PatchStatus>::new());
    let notice = RwSignal::new(None::<String>);
    let scanning = RwSignal::new(Vec::<i64>::new());
    let all_busy = RwSignal::new(false);
    let details = RwSignal::new(None::<(String, Vec<PackageUpdate>)>);
    let dialog = RwSignal::new(None::<ActionDialog>);
    let running = RwSignal::new(None::<i64>);

    let load = move || {
        spawn_local(async move {
            match api::patch_status().await {
                Ok(r) => rows.set(r),
                Err(e) => notice.set(Some(e)),
            }
        })
    };
    load();

    let scan_one = move |id: i64, name: String| {
        scanning.update(|s| s.push(id));
        spawn_local(async move {
            match api::scan_host(id).await {
                Ok(_) => notice.set(Some(format!("Scanned {name}."))),
                Err(e) => notice.set(Some(format!("{name}: {e}"))),
            }
            scanning.update(|s| s.retain(|x| *x != id));
            load();
            refresh.run(());
        })
    };
    let scan_all = move |_| {
        all_busy.set(true);
        notice.set(Some("Scanning trusted hosts...".into()));
        spawn_local(async move {
            match api::scan_all().await {
                Ok(s) => notice.set(Some(format!(
                    "Scanned {} hosts. {} failed, {} skipped because their key is not verified.",
                    s.scanned, s.failed, s.skipped
                ))),
                Err(e) => notice.set(Some(e)),
            }
            all_busy.set(false);
            load();
            refresh.run(());
        })
    };
    let show = move |id: i64, name: String| {
        spawn_local(async move {
            match api::pending_updates(id).await {
                Ok(u) => details.set(Some((name, u))),
                Err(e) => notice.set(Some(e)),
            }
        })
    };

    let open_action = move |id: i64, name: String, action: &'static str| {
        running.set(Some(id));
        spawn_local(async move {
            match api::check_privileged(id, action).await {
                Ok(check) => dialog.set(Some(ActionDialog { id, name, action, check })),
                Err(e) => notice.set(Some(format!("{name}: {e}"))),
            }
            running.set(None);
        })
    };
    let recheck = move |_| {
        let Some(d) = dialog.get_untracked() else { return };
        dialog.set(None);
        open_action(d.id, d.name, d.action);
    };
    let confirm_action = move |_| {
        let Some(d) = dialog.get_untracked() else { return };
        dialog.set(None);
        running.set(Some(d.id));
        notice.set(Some(if d.action == "patch" {
            format!("Applying updates on {}...", d.name)
        } else {
            format!("Rebooting {}...", d.name)
        }));
        spawn_local(async move {
            match api::run_action(d.id, d.action).await {
                Ok(msg) => notice.set(Some(msg)),
                Err(e) => notice.set(Some(e)),
            }
            running.set(None);
            load();
            refresh.run(());
        })
    };

    let total = move |f: fn(&PatchStatus) -> u32| rows.with(|r| r.iter().map(f).sum::<u32>());

    view! {
        <div class="stats">
            <div class="stat"><div class="stat-value">{move || total(|r| r.pending)}</div><div class="stat-label">"Pending updates"</div></div>
            <div class="stat"><div class="stat-value">{move || total(|r| r.security)}</div><div class="stat-label">"Security updates"</div></div>
            <div class="stat"><div class="stat-value">{move || total(|r| r.reboot_required as u32)}</div><div class="stat-label">"Reboot required"</div></div>
            <div class="stat"><div class="stat-value">{move || total(|r| r.scan_error.is_some() as u32)}</div><div class="stat-label">"Failed scans"</div></div>
        </div>

        <div class="toolbar">
            <button class="btn primary" on:click=scan_all disabled=move || all_busy.get()>"Scan trusted hosts"</button>
            <span class="muted">{move || notice.get().unwrap_or_default()}</span>
        </div>
        <p class="muted small">"Scans are read-only. They list pending updates and check whether a reboot is needed, without sudo."</p>

        <table class="table">
            <thead>
                <tr>
                    <th>"Host"</th>
                    <th>"OS"</th>
                    <th>"Pending"</th>
                    <th>"Security"</th>
                    <th>"Reboot"</th>
                    <th>"Last scan"</th>
                    <th>"Status"</th>
                    <th></th>
                </tr>
            </thead>
            <tbody>
                <For
                    each=move || rows.get()
                    key=|r| (r.host_id, r.last_scan_at, r.pending, r.security, r.reboot_required, r.scan_error.clone(), r.host_key_trusted)
                    let:r
                >
                    {
                        let id = r.host_id;
                        let (name_scan, name_show) = (r.name.clone(), r.name.clone());
                        let (name_patch, name_reboot) = (r.name.clone(), r.name.clone());
                        let reboot_required = r.reboot_required;
                        let pending = r.pending;
                        let trusted = r.host_key_trusted;
                        let status = if !trusted {
                            view! { <span class="muted">"Verify key in Hosts"</span> }.into_any()
                        } else if let Some(e) = r.scan_error.clone() {
                            view! { <span class="pill bad" title=e>"Scan failed"</span> }.into_any()
                        } else if r.last_scan_at.is_none() {
                            view! { <span class="muted">"Not scanned"</span> }.into_any()
                        } else {
                            view! { <span class="pill ok">"OK"</span> }.into_any()
                        };
                        view! {
                            <tr>
                                <td>{r.name.clone()}</td>
                                <td>{r.os_type.clone()}</td>
                                <td>{r.pending}</td>
                                <td>{if r.security > 0 {
                                    view! { <span class="pill warn">{r.security}</span> }.into_any()
                                } else {
                                    view! { <span class="muted">"0"</span> }.into_any()
                                }}</td>
                                <td>{if r.reboot_required {
                                    view! { <span class="pill warn">"Required"</span> }.into_any()
                                } else {
                                    view! { <span class="muted">"No"</span> }.into_any()
                                }}</td>
                                <td class="muted">{ago(r.last_scan_at)}</td>
                                <td>{status}</td>
                                <td class="actions">
                                    <button class="btn small" disabled=pending == 0
                                        title={if pending == 0 { "No pending updates" } else { "Show pending packages" }}
                                        on:click=move |_| show(id, name_show.clone())>"Details"</button>
                                    <button class="btn small primary"
                                        disabled=move || !trusted || all_busy.get() || scanning.with(|s| s.contains(&id))
                                        on:click=move |_| scan_one(id, name_scan.clone())>"Scan"</button>
                                    <button class={if pending > 0 { "btn small warn" } else { "btn small" }}
                                        disabled=move || !trusted || pending == 0 || running.get().is_some()
                                        title={if pending == 0 { "Nothing to patch" } else { "Apply pending updates" }}
                                        on:click=move |_| open_action(id, name_patch.clone(), "patch")>"Patch"</button>
                                    <button class={if reboot_required { "btn small warn" } else { "btn small" }}
                                        disabled=move || !trusted || !reboot_required || running.get().is_some()
                                        title={if reboot_required { "This host needs a reboot" } else { "No reboot needed" }}
                                        on:click=move |_| open_action(id, name_reboot.clone(), "reboot")>"Reboot"</button>
                                </td>
                            </tr>
                        }
                    }
                </For>
            </tbody>
        </table>

        <Show when=move || dialog.with(|d| d.is_some())>
            <div class="modal-backdrop">
                <div class="modal wide">
                    {move || dialog.get().map(|d| {
                        let verb = if d.action == "patch" { "Apply updates on" } else { "Reboot" };
                        if d.check.allowed {
                            view! {
                                <h2>{format!("{verb} {}?", d.name)}</h2>
                                <p>"QuietKeep will run exactly these commands as root:"</p>
                                {d.check.commands.iter().map(|c| view! { <p class="fingerprint mono">{c.clone()}</p> }).collect_view()}
                                <div class="modal-actions">
                                    <button class="btn" on:click=move |_| dialog.set(None)>"Cancel"</button>
                                    <button class="btn danger" on:click=confirm_action>{verb}</button>
                                </div>
                            }.into_any()
                        } else {
                            view! {
                                <h2>{format!("Allow QuietKeep on {}", d.name)}</h2>
                                <p>{format!(
                                    "{} does not allow QuietKeep to run these commands yet. On the host, run sudo visudo -f {} and paste this rule. It allows only these exact commands.",
                                    d.name, d.check.sudoers_path
                                )}</p>
                                <textarea class="keybox mono" readonly rows="8">{d.check.rule.clone()}</textarea>
                                <div class="modal-actions">
                                    <button class="btn" on:click=move |_| dialog.set(None)>"Close"</button>
                                    <button class="btn primary" on:click=recheck>"Check again"</button>
                                </div>
                            }.into_any()
                        }
                    })}
                </div>
            </div>
        </Show>

        <Show when=move || details.with(|d| d.is_some())>
            <div class="modal-backdrop">
                <div class="modal wide">
                    {move || details.get().map(|(name, ups)| view! {
                        <h2>{format!("Pending updates on {name}")}</h2>
                        <div class="scroll">
                            <table class="table">
                                <thead>
                                    <tr><th>"Package"</th><th>"Installed"</th><th>"Available"</th><th>"Source"</th><th></th></tr>
                                </thead>
                                <tbody>
                                    {ups.into_iter().map(|u| view! {
                                        <tr>
                                            <td class="mono">{u.name}</td>
                                            <td class="mono">{u.current_version.unwrap_or_default()}</td>
                                            <td class="mono">{u.available_version}</td>
                                            <td>{u.source.unwrap_or_default()}</td>
                                            <td>{u.security.then(|| view! { <span class="pill warn">"Security"</span> })}</td>
                                        </tr>
                                    }).collect_view()}
                                </tbody>
                            </table>
                        </div>
                    })}
                    <div class="modal-actions">
                        <button class="btn primary" on:click=move |_| details.set(None)>"Close"</button>
                    </div>
                </div>
            </div>
        </Show>
    }
}
