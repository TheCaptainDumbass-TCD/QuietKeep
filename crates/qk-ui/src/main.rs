mod api;
mod dashboard;
mod hosts;
mod docker;
mod patches;
mod security;
mod settings;
mod tauri;
mod theme;

use leptos::prelude::*;
use leptos::task::spawn_local;

use dashboard::Dashboard;
use hosts::HostsPanel;
use docker::DockerPanel;
use patches::PatchesPanel;
use security::SecurityPanel;
use settings::SettingsPanel;
use theme::{Theme, ThemeSwitcher};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Panel {
    Dashboard,
    Hosts,
    Patches,
    Docker,
    Security,
    Settings,
}

impl Panel {
    const ALL: [Panel; 6] = [
        Panel::Dashboard,
        Panel::Hosts,
        Panel::Patches,
        Panel::Docker,
        Panel::Security,
        Panel::Settings,
    ];

    fn label(self) -> &'static str {
        match self {
            Panel::Dashboard => "Dashboard",
            Panel::Hosts => "Hosts",
            Panel::Patches => "Patches",
            Panel::Docker => "Docker",
            Panel::Security => "Security",
            Panel::Settings => "Settings",
        }
    }
}

#[component]
fn App() -> impl IntoView {
    let theme = RwSignal::new(Theme::load());
    Effect::new(move |_| theme.get().apply());

    let panel = RwSignal::new(Panel::Dashboard);
    let version = RwSignal::new(String::new());
    spawn_local(async move {
        if let Ok(info) = tauri::app_info().await {
            version.set(info.version);
        }
    });

    let hosts = RwSignal::new(Vec::new());
    let activity = RwSignal::new(Vec::new());
    let refresh = Callback::new(move |_| {
        spawn_local(async move {
            if let Ok(h) = api::list_hosts().await {
                hosts.set(h);
            }
            if let Ok(a) = api::recent_activity().await {
                activity.set(a);
            }
        })
    });
    refresh.run(());

    view! {
        <div class="shell">
            <aside class="sidebar">
                <div class="brand">"QuietKeep"</div>
                <nav>
                    {Panel::ALL
                        .into_iter()
                        .map(|p| {
                            view! {
                                <button
                                    class="nav-item"
                                    class:active=move || panel.get() == p
                                    on:click=move |_| panel.set(p)
                                >
                                    {p.label()}
                                </button>
                            }
                        })
                        .collect_view()}
                </nav>
                <div class="sidebar-footer">
                    <ThemeSwitcher theme=theme />
                    <div class="version">{move || format!("v{}", version.get())}</div>
                </div>
            </aside>
            <main class="content">
                <h1>{move || panel.get().label()}</h1>
                {move || match panel.get() {
                    Panel::Dashboard => view! { <Dashboard hosts activity /> }.into_any(),
                    Panel::Hosts => view! { <HostsPanel hosts refresh /> }.into_any(),
                    Panel::Patches => view! { <PatchesPanel refresh /> }.into_any(),
                    Panel::Docker => view! { <DockerPanel refresh /> }.into_any(),
                    Panel::Security => view! { <SecurityPanel refresh /> }.into_any(),
                    Panel::Settings => view! { <SettingsPanel refresh /> }.into_any(),
                }}
            </main>
        </div>
    }
}

fn main() {
    leptos::mount::mount_to_body(App);
}
