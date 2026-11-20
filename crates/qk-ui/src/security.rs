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
                }
                Err(e) => notice.set(Some(e)),
            }
        })
    };
    load();

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
