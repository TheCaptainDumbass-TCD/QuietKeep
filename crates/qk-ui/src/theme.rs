use leptos::prelude::*;

const STORAGE_KEY: &str = "quietkeep.theme";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Theme {
    System,
    Light,
    Dark,
}

impl Theme {
    const ALL: [Theme; 3] = [Theme::System, Theme::Light, Theme::Dark];

    fn key(self) -> &'static str {
        match self {
            Theme::System => "system",
            Theme::Light => "light",
            Theme::Dark => "dark",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Theme::System => "System",
            Theme::Light => "Light",
            Theme::Dark => "Dark",
        }
    }

    pub fn load() -> Theme {
        let stored = web_sys::window()
            .and_then(|w| w.local_storage().ok().flatten())
            .and_then(|s| s.get_item(STORAGE_KEY).ok().flatten());
        Theme::ALL
            .into_iter()
            .find(|t| Some(t.key()) == stored.as_deref())
            .unwrap_or(Theme::System)
    }

    /// Sets `data-theme` on <html>; "system" defers to prefers-color-scheme in CSS.
    pub fn apply(self) {
        let Some(window) = web_sys::window() else { return };
        if let Some(root) = window.document().and_then(|d| d.document_element()) {
            let _ = root.set_attribute("data-theme", self.key());
        }
        if let Ok(Some(storage)) = window.local_storage() {
            let _ = storage.set_item(STORAGE_KEY, self.key());
        }
    }
}

#[component]
pub fn ThemeSwitcher(theme: RwSignal<Theme>) -> impl IntoView {
    view! {
        <div class="theme-switcher" role="radiogroup" aria-label="Theme">
            {Theme::ALL
                .into_iter()
                .map(|t| {
                    view! {
                        <button
                            role="radio"
                            aria-checked=move || (theme.get() == t).to_string()
                            class:active=move || theme.get() == t
                            on:click=move |_| theme.set(t)
                        >
                            {t.label()}
                        </button>
                    }
                })
                .collect_view()}
        </div>
    }
}
