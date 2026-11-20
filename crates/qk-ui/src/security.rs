use leptos::prelude::*;
use leptos::task::spawn_local;

use crate::api::{self, KevFilter, KevState, Vulnerability};

#[component]
pub fn SecurityPanel(refresh: Callback<()>) -> impl IntoView {
    let state = RwSignal::new(None::<KevState>);
    let results = RwSignal::new(Vec::<Vulnerability>::new());
    let search = RwSignal::new(String::new());
    let linux_only = RwSignal::new(true);
    let ransomware_only = RwSignal::new(false);
    let notice = RwSignal::new(None::<String>);
    let busy = RwSignal::new(false);
    let asking = RwSignal::new(false);
    let selected = RwSignal::new(None::<Vulnerability>);
    let affected = RwSignal::new(Vec::<api::Affected>::new());
    let show_unchecked = RwSignal::new(false);
    let osv = RwSignal::new(None::<api::OsvState>);
    let osv_asking = RwSignal::new(false);
    let osv_busy = RwSignal::new(false);
    let expanded = RwSignal::new(None::<String>);
    let show_cve = move |cve: String| {
        let filter = KevFilter { search: cve.clone(), linux_only: false, ransomware_only: false };
        spawn_local(async move {
            match api::kev_search(filter).await {
                Ok(v) => selected.set(v.into_iter().find(|v| v.cve_id == cve)),
                Err(e) => notice.set(Some(e)),
            }
        })
    };

    let run_search = move || {
        let filter = KevFilter {
            search: search.get_untracked(),
            linux_only: linux_only.get_untracked(),
            ransomware_only: ransomware_only.get_untracked(),
        };
        spawn_local(async move {
            match api::kev_search(filter).await {
                Ok(v) => results.set(v),
                Err(e) => notice.set(Some(e)),
            }
        })
    };
    let load = move || {
        spawn_local(async move {
            match api::kev_state().await {
                Ok(s) => {
                    state.set(Some(s));
                    run_search();
                    if let Ok(o) = api::osv_state().await {
                        osv.set(Some(o));
                    }
                    match api::kev_affected().await {
                        Ok(a) => affected.set(a),
                        Err(e) => notice.set(Some(e)),
                    }
                }
                Err(e) => notice.set(Some(e)),
            }
        })
    };
    load();

    let osv_download = move || {
        osv_busy.set(true);
        notice.set(Some("Looking up fixed versions in the Debian and Ubuntu security trackers...".into()));
        spawn_local(async move {
            match api::osv_refresh().await {
                Ok(n) => notice.set(Some(format!("Checked fixed versions for {n} CVEs."))),
                Err(e) => notice.set(Some(e)),
            }
            osv_busy.set(false);
            load();
        })
    };
    let osv_click = move |_| {
        if osv.with(|o| o.as_ref().is_some_and(|o| o.allowed)) {
            osv_download();
        } else {
            osv_asking.set(true);
        }
    };
    let osv_allow = move |_| {
        osv_asking.set(false);
        spawn_local(async move {
            match api::osv_set_allowed(true).await {
                Ok(_) => osv_download(),
                Err(e) => notice.set(Some(e)),
            }
        })
    };
    let download = move || {
        busy.set(true);
        notice.set(Some("Downloading the CISA KEV catalog...".into()));
        spawn_local(async move {
            match api::kev_refresh().await {
                Ok(s) => notice.set(Some(format!("Catalog {} downloaded.", s.catalog_version))),
                Err(e) => notice.set(Some(e)),
            }
            busy.set(false);
            load();
            refresh.run(());
        })
    };
    let refresh_click = move |_| {
        if state.with(|s| s.as_ref().is_some_and(|s| s.allowed)) {
            download();
        } else {
            asking.set(true);
        }
    };
    let allow = move |_| {
        asking.set(false);
        spawn_local(async move {
            match api::kev_set_allowed(true).await {
                Ok(_) => download(),
                Err(e) => notice.set(Some(e)),
            }
        })
    };
    let revoke = move |_| {
        spawn_local(async move {
            let _ = api::kev_set_allowed(false).await;
            load();
            refresh.run(());
        })
    };

    let stat = move |f: fn(&api::KevSummary) -> usize| {
        state.with(|s| s.as_ref().and_then(|s| s.summary.as_ref()).map(f).map(|n| n.to_string()).unwrap_or_else(|| "-".into()))
    };

    view! {
        <div class="stats">
            <div class="stat"><div class="stat-value">{move || stat(|s| s.total)}</div><div class="stat-label">"Known exploited"</div></div>
            <div class="stat"><div class="stat-value">{move || stat(|s| s.linux_related)}</div><div class="stat-label">"Linux and homelab related"</div></div>
            <div class="stat"><div class="stat-value">{move || stat(|s| s.ransomware)}</div><div class="stat-label">"Used by ransomware"</div></div>
            <div class="stat"><div class="stat-value">{move || stat(|s| s.added_last_30_days)}</div><div class="stat-label">"Added in last 30 days"</div></div>
        </div>
        <div class="toolbar">
            <button class="btn primary" on:click=refresh_click disabled=move || busy.get()>
                {move || if state.with(|s| s.as_ref().is_some_and(|s| s.summary.is_some())) { "Update catalog" } else { "Download catalog" }}
            </button>
            <span class="muted">{move || notice.get().unwrap_or_else(|| {
                state.with(|s| match s.as_ref().and_then(|s| s.summary.as_ref()) {
                    Some(sum) => format!("Catalog {} released {}", sum.catalog_version, sum.date_released.get(..10).unwrap_or("")),
                    None => "No catalog downloaded yet.".into(),
                })
            })}</span>
            <span class="spacer"></span>
            <Show when=move || state.with(|s| s.as_ref().is_some_and(|s| s.allowed))>
                <button class="btn small" on:click=revoke>"Stop downloads"</button>
            </Show>
        </div>
        <section class="card">
            <h2>"Affecting your hosts"</h2>
            <p class="muted">"Known exploited vulnerabilities in software installed on the hosts saved in QuietKeep, from the package lists and container images of their last patch scan. "
               "With fixed versions checked, Debian and Ubuntu hosts are listed only when their installed version is older than the fix."</p>
            <div class="toolbar">
                <button class="btn" on:click=osv_click
                    disabled=move || osv_busy.get() || !state.with(|s| s.as_ref().is_some_and(|s| s.summary.is_some()))
                    title=move || if state.with(|s| s.as_ref().is_some_and(|s| s.summary.is_some())) { "Look up which package version fixes each CVE" } else { "Download the catalog first" }>
                    {move || if osv.with(|o| o.as_ref().is_some_and(|o| o.fetched_at.is_some())) { "Update fixed versions" } else { "Check fixed versions" }}
                </button>
                <span class="muted">{move || osv.with(|o| match o.as_ref().and_then(|o| o.fetched_at.clone().map(|f| (f, o.checked))) {
                    Some((f, n)) => format!("Fixed versions for {n} CVEs checked {f}"),
                    None => "Fixed versions not checked yet, so every match is shown.".to_string(),
                })}</span>
                <span class="spacer"></span>
                <label title="Hosts QuietKeep cannot version check, such as Kali, Arch, Proxmox kernels and container images">
                    <input type="checkbox" prop:checked=move || show_unchecked.get()
                        on:change=move |ev| show_unchecked.set(event_target_checked(&ev)) />
                    " Show matches without version data"</label>
            </div>
            <Show when=move || osv_asking.get()>
                <div class="modal-backdrop">
                    <div class="modal">
                        <h2>"Check fixed versions"</h2>
                        <p>"QuietKeep will ask api.osv.dev, the public OSV database, for the Debian and Ubuntu security tracker records of the catalog CVEs it can match. "
                           "Only public CVE IDs are sent. Nothing about your hosts or packages leaves this computer."</p>
                        <p class="muted">"The comparison with your installed versions happens locally. You can turn this off later in the same place."</p>
                        <div class="modal-actions">
                            <button class="btn" on:click=move |_| osv_asking.set(false)>"Cancel"</button>
                            <button class="btn primary" on:click=osv_allow>"Allow and check"</button>
                        </div>
                    </div>
                </div>
            </Show>
            {move || {
                let has_catalog = state.with(|s| s.as_ref().is_some_and(|s| s.summary.is_some()));
                let checked = osv.with(|o| o.as_ref().is_some_and(|o| o.fetched_at.is_some()));
                let unchecked_too = show_unchecked.get() || !checked;
                let all_empty = affected.with(|a| a.is_empty());
                let list: Vec<api::Affected> = affected
                    .get()
                    .into_iter()
                    .filter_map(|mut a| {
                        if !unchecked_too {
                            a.hosts.retain(|h| h.status != "unchecked");
                        }
                        (!a.hosts.is_empty()).then_some(a)
                    })
                    .collect();
                if !has_catalog {
                    view! { <p class="muted">"Download the catalog to check your hosts."</p> }.into_any()
                } else if list.is_empty() && !all_empty {
                    view! { <p class="ok-text">"No saved host has a version older than the fix for any matched known exploited vulnerability."</p> }.into_any()
                } else if list.is_empty() {
                    view! { <p class="muted">"No matches. Hosts are checked after a patch scan collects their installed packages, so scan any host that is new or not scanned since 0.12.0."</p> }.into_any()
                } else {
                    let mut groups: Vec<(String, Vec<api::Affected>)> = Vec::new();
                    for a in list {
                        let key = format!("{} {}", a.vendor_project, a.product);
                        match groups.iter_mut().find(|(k, _)| *k == key) {
                            Some((_, g)) => g.push(a),
                            None => groups.push((key, vec![a])),
                        }
                    }
                    view! {
                        <table class="table">
                            <thead><tr><th>"Product"</th><th>"CVEs"</th><th>"Hosts"</th><th>"Status"</th><th>"Ransomware"</th></tr></thead>
                            <tbody>
                                {groups.into_iter().map(|(key, cves)| {
                                    let mut hosts: Vec<api::HostMatch> = Vec::new();
                                    for h in cves.iter().flat_map(|a| a.hosts.iter()) {
                                        if !hosts.iter().any(|x| x.host_id == h.host_id) {
                                            hosts.push(h.clone());
                                        }
                                    }
                                    let names = hosts.iter().map(|h| h.host.clone()).collect::<Vec<_>>().join(", ");
                                    let detail = hosts.iter().map(|h| format!("{}: {} {}", h.host, h.source, h.version)).collect::<Vec<_>>().join("\n");
                                    let host_status = |st: &str| {
                                        let mut ids: Vec<i64> = cves.iter().flat_map(|a| a.hosts.iter()).filter(|h| h.status == st).map(|h| h.host_id).collect();
                                        ids.sort_unstable();
                                        ids.dedup();
                                        ids.len()
                                    };
                                    let (patch, nofix, unchecked) = (host_status("patch"), host_status("nofix"), host_status("unchecked"));
                                    let ransomware = cves.iter().filter(|a| a.known_ransomware).count();
                                    let count = cves.len();
                                    let k1 = key.clone();
                                    let k2 = key.clone();
                                    view! {
                                        <tr class="clickable" title="Click to list the CVEs" on:click=move |_| expanded.update(|e| *e = if e.as_deref() == Some(k1.as_str()) { None } else { Some(k1.clone()) })>
                                            <td>{let k3 = key.clone(); move || if expanded.with(|e| e.as_deref() == Some(k3.as_str())) { "\u{25BE} " } else { "\u{25B8} " }}{key.clone()}</td>
                                            <td>{count}</td>
                                            <td title=detail>{names}</td>
                                            <td>
                                                {(patch > 0).then(|| view! { <span class="pill warn" title="The installed version is older than the fixed version. Patch these hosts.">{format!("Patch {patch} hosts")}</span> })}
                                                {(nofix > 0).then(|| view! { <span class="pill bad" title="The tracker lists the package as affected and no fix is released yet">{format!("No fix yet on {nofix}")}</span> })}
                                                {(unchecked > 0).then(|| view! { <span class="pill held" title="No tracker data for these hosts, so only the product is known to be installed">{format!("Not version checked on {unchecked}")}</span> })}
                                            </td>
                                            <td>{if ransomware > 0 {
                                                view! { <span class="pill bad">{format!("{ransomware} known")}</span> }.into_any()
                                            } else {
                                                view! { <span class="muted">"Unknown"</span> }.into_any()
                                            }}</td>
                                        </tr>
                                        <Show when=move || expanded.with(|e| e.as_deref() == Some(k2.as_str()))>
                                            {cves.clone().into_iter().map(|a| {
                                                let cve = a.cve_id.clone();
                                                let per_host = a.hosts.iter().map(|h| match (h.status.as_str(), &h.fixed_version) {
                                                    ("patch", Some(f)) => format!("{}: {} {}, fixed in {f}{}", h.host, h.source, h.version, if h.update_pending { ", update ready" } else { "" }),
                                                    ("nofix", _) => format!("{}: {} {}, no fix yet", h.host, h.source, h.version),
                                                    _ => format!("{}: {} {}, not version checked", h.host, h.source, h.version),
                                                }).collect::<Vec<_>>().join("; ");
                                                view! {
                                                    <tr class="clickable sub" title="Click for details" on:click=move |_| show_cve(cve.clone())>
                                                        <td class="mono">{a.cve_id.clone()}</td>
                                                        <td colspan="3">{a.vulnerability_name.clone()}<br/><span class="muted">{per_host}</span></td>
                                                        <td class="muted">{a.date_added.clone()}</td>
                                                    </tr>
                                                }
                                            }).collect_view()}
                                        </Show>
                                    }
                                }).collect_view()}
                            </tbody>
                        </table>
                    }.into_any()
                }
            }}
        </section>
        <div class="toolbar">
            <input class="search" type="search" placeholder="Search CVE, vendor, product"
                prop:value=move || search.get()
                on:input=move |ev| { search.set(event_target_value(&ev)); run_search(); } />
            <label><input type="checkbox" prop:checked=move || linux_only.get()
                on:change=move |ev| { linux_only.set(event_target_checked(&ev)); run_search(); } />" Linux and homelab only"</label>
            <label><input type="checkbox" prop:checked=move || ransomware_only.get()
                on:change=move |ev| { ransomware_only.set(event_target_checked(&ev)); run_search(); } />" Ransomware only"</label>
        </div>
        <table class="table">
            <thead><tr><th>"CVE"</th><th>"Vendor"</th><th>"Product"</th><th>"Name"</th><th>"Added"</th><th>"Due"</th><th>"Ransomware"</th></tr></thead>
            <tbody>
                <For each=move || results.get() key=|v| v.cve_id.clone() let:v>
                    <tr class="clickable" title="Click for details" on:click={
                        let v = v.clone();
                        move |_| selected.set(Some(v.clone()))
                    }>
                        <td class="mono">{v.cve_id.clone()}</td>
                        <td>{v.vendor_project.clone()}</td>
                        <td>{v.product.clone()}</td>
                        <td>{v.vulnerability_name.clone()}</td>
                        <td class="muted">{v.date_added.clone()}</td>
                        <td class="muted">{v.due_date.clone()}</td>
                        <td>{if v.known_ransomware_campaign_use.eq_ignore_ascii_case("known") {
                            view! { <span class="pill bad">"Known"</span> }.into_any()
                        } else {
                            view! { <span class="muted">"Unknown"</span> }.into_any()
                        }}</td>
                    </tr>
                </For>
            </tbody>
        </table>

        {move || selected.get().map(|v| {
            let id = v.cve_id.clone();
            let open = move |site: &'static str| {
                let cve = id.clone();
                move |_| {
                    let cve = cve.clone();
                    spawn_local(async move {
                        if let Err(e) = api::open_cve_page(cve, site).await {
                            notice.set(Some(e));
                        }
                    })
                }
            };
            view! {
                <div class="modal-backdrop" on:click=move |_| selected.set(None)>
                    <div class="modal wide" on:click=|ev| ev.stop_propagation()>
                        <h2 class="mono">{v.cve_id.clone()}</h2>
                        <p><strong>{v.vulnerability_name.clone()}</strong></p>
                        <p class="muted">{format!("{} {}", v.vendor_project, v.product)}</p>
                        <p>{v.short_description.clone()}</p>
                        <p><strong>"Required action: "</strong>{v.required_action.clone()}</p>
                        <p class="muted">{format!("Added {}. Federal due date {}. Ransomware use: {}.",
                            v.date_added, v.due_date, v.known_ransomware_campaign_use)}</p>
                        <div class="modal-actions">
                            <button class="btn" on:click=open("nvd") title="Opens nvd.nist.gov in your browser">"Open on NVD"</button>
                            <button class="btn" on:click=open("cve") title="Opens cve.org in your browser">"Open on CVE.org"</button>
                            <button class="btn primary" on:click=move |_| selected.set(None)>"Close"</button>
                        </div>
                    </div>
                </div>
            }
        })}

        <Show when=move || asking.get()>
            <div class="modal-backdrop">
                <div class="modal">
                    <h2>"Download from cisa.gov?"</h2>
                    <p>"QuietKeep will download the public CISA Known Exploited Vulnerabilities catalog over HTTPS from www.cisa.gov. "
                       "Nothing about your hosts is sent. The catalog is saved locally and stays usable offline."</p>
                    <div class="modal-actions">
                        <button class="btn" on:click=move |_| asking.set(false)>"Not now"</button>
                        <button class="btn primary" on:click=allow>"Allow and download"</button>
                    </div>
                </div>
            </div>
        </Show>
    }
}
