use leptos::prelude::*;

use crate::api::{Activity, Host};

#[component]
pub fn Dashboard(hosts: RwSignal<Vec<Host>>, activity: RwSignal<Vec<Activity>>) -> impl IntoView {
    let count = move |f: fn(&Host) -> bool| hosts.with(|h| h.iter().filter(|x| f(x)).count());
    let os_counts = move || {
        let mut counts: Vec<(String, usize)> = Vec::new();
        hosts.with(|hs| {
            for h in hs {
                match counts.iter_mut().find(|(k, _)| *k == h.spec.os_type) {
                    Some((_, n)) => *n += 1,
                    None => counts.push((h.spec.os_type.clone(), 1)),
                }
            }
        });
        counts.sort_by_key(|c| std::cmp::Reverse(c.1));
        counts
    };

    view! {
        <div class="stats">
            <div class="stat"><div class="stat-value">{move || hosts.with(|h| h.len())}</div><div class="stat-label">"Hosts"</div></div>
            <div class="stat"><div class="stat-value">{move || count(|h| h.spec.is_patch_target)}</div><div class="stat-label">"Patch targets"</div></div>
            <div class="stat"><div class="stat-value">{move || count(|h| h.spec.has_docker)}</div><div class="stat-label">"Docker hosts"</div></div>
            <div class="stat"><div class="stat-value">{move || count(|h| !h.host_key_trusted)}</div><div class="stat-label">"Unverified keys"</div></div>
        </div>
        <div class="grid-2">
            <section class="card">
                <h2>"Hosts by package manager"</h2>
                {move || {
                    let rows = os_counts();
                    let max = rows.first().map(|r| r.1).unwrap_or(1).max(1);
                    if rows.is_empty() {
                        view! { <p class="muted">"No hosts yet."</p> }.into_any()
                    } else {
                        rows.into_iter().map(|(os, n)| {
                            let width = format!("width: {}%", n * 100 / max);
                            view! {
                                <div class="bar-row">
                                    <span class="bar-label">{os}</span>
                                    <span class="bar"><span class="bar-fill" style=width></span></span>
                                    <span class="bar-value">{n}</span>
                                </div>
                            }
                        }).collect_view().into_any()
                    }
                }}
            </section>
            <section class="card">
                <h2>"Recent activity"</h2>
                <Show when=move || activity.with(|a| !a.is_empty()) fallback=|| view! { <p class="muted">"Nothing yet."</p> }>
                    <ul class="activity">
                        <For each={move || activity.get().into_iter().take(10).collect::<Vec<_>>()} key={|a: &Activity| (a.at, a.message.clone())} let:item>
                            <li>{item.message}</li>
                        </For>
                    </ul>
                </Show>
            </section>
        </div>
    }
}
