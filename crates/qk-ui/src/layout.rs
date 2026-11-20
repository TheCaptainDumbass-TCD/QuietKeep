//! Sidebar panel order and visibility, stored in local storage.

use leptos::prelude::*;

use crate::Panel;

const STORAGE_KEY: &str = "quietkeep.panels";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Entry {
    pub panel: Panel,
    pub visible: bool,
}

/// Dashboard and Settings stay visible so the layout can always be changed back.
pub fn can_hide(p: Panel) -> bool {
    !matches!(p, Panel::Dashboard | Panel::Settings)
}

pub fn default_layout() -> Vec<Entry> {
    Panel::ALL.into_iter().map(|panel| Entry { panel, visible: true }).collect()
}

/// Parses "hosts,!docker,..." and appends any panels missing from the stored value.
pub fn parse(stored: &str) -> Vec<Entry> {
    let mut out: Vec<Entry> = Vec::new();
    for item in stored.split(',') {
        let (hidden, key) = match item.strip_prefix('!') {
            Some(k) => (true, k),
            None => (false, item),
        };
        if let Some(panel) = Panel::ALL.into_iter().find(|p| p.key() == key) {
            if !out.iter().any(|e| e.panel == panel) {
                out.push(Entry { panel, visible: !hidden || !can_hide(panel) });
            }
        }
    }
    for panel in Panel::ALL {
        if !out.iter().any(|e| e.panel == panel) {
            out.push(Entry { panel, visible: true });
        }
    }
    out
}

pub fn serialize(layout: &[Entry]) -> String {
    layout
        .iter()
        .map(|e| if e.visible { e.panel.key().to_string() } else { format!("!{}", e.panel.key()) })
        .collect::<Vec<_>>()
        .join(",")
}

fn storage() -> Option<web_sys::Storage> {
    web_sys::window().and_then(|w| w.local_storage().ok().flatten())
}

pub fn load() -> Vec<Entry> {
    storage()
        .and_then(|s| s.get_item(STORAGE_KEY).ok().flatten())
        .map(|v| parse(&v))
        .unwrap_or_else(default_layout)
}

pub fn save(layout: &[Entry]) {
    if let Some(s) = storage() {
        let _ = s.set_item(STORAGE_KEY, &serialize(layout));
    }
}

#[component]
pub fn PanelLayoutCard() -> impl IntoView {
    let layout = expect_context::<RwSignal<Vec<Entry>>>();
    let shift = move |i: usize, up: bool| {
        layout.update(|l| {
            let j = if up { i.checked_sub(1) } else { Some(i + 1).filter(|j| *j < l.len()) };
            if let Some(j) = j {
                l.swap(i, j);
            }
        })
    };
    view! {
        <section class="card">
            <h2>"Panels"</h2>
            <p class="muted">"Choose which panels appear in the sidebar and in what order. Dashboard and Settings are always shown."</p>
            <table class="table panels">
                <tbody>
                    {move || {
                        let rows = layout.get();
                        let n = rows.len();
                        rows.into_iter().enumerate().map(|(i, e)| {
                            let hideable = can_hide(e.panel);
                            view! {
                                <tr>
                                    <td>
                                        <label class="check">
                                            <input type="checkbox" prop:checked=e.visible disabled=!hideable
                                                on:change=move |ev| {
                                                    let on = event_target_checked(&ev);
                                                    layout.update(|l| l[i].visible = on || !hideable);
                                                } />
                                            {e.panel.label()}
                                        </label>
                                    </td>
                                    <td class="actions">
                                        <button class="btn small" disabled=i == 0 on:click=move |_| shift(i, true)>"Up"</button>
                                        <button class="btn small" disabled=i + 1 == n on:click=move |_| shift(i, false)>"Down"</button>
                                    </td>
                                </tr>
                            }
                        }).collect_view()
                    }}
                </tbody>
            </table>
            <button class="btn" on:click=move |_| layout.set(default_layout())>"Reset to default"</button>
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_fills_missing() {
        let l = parse("security,!docker,hosts,bogus,!settings");
        assert_eq!(l[0].panel, Panel::Security);
        assert!(!l[1].visible);
        assert_eq!(l.len(), Panel::ALL.len());
        assert!(l.iter().find(|e| e.panel == Panel::Settings).unwrap().visible);
        assert_eq!(parse(&serialize(&l)), l);
    }
}
