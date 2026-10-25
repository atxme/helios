//! Orion in the Windows notification area.
//!
//! # What the menu is for
//!
//! The window is hidden on close, not quit: the tunnel and its key-negotiation
//! liveness link keep running, and the notification area becomes the only
//! surface Orion offers. So the menu is not a set of shortcuts to the window —
//! it is a small client of its own: it states the tunnel's condition, lists the
//! profiles, and connects or disconnects without ever showing the window.
//!
//! # Why the whole menu is rebuilt
//!
//! The state and the profile list both change while the menu exists. Mutating
//! items in place would mean holding a handle on each one and keeping the list
//! of profile items in sync by hand — a second model, next to the one the
//! vault already holds, that would drift the day a profile is renamed. Building
//! the menu from a [`TrayModel`](crate::tray::TrayModel) read on the spot has no such second copy: what
//! the menu shows is what the state said at the moment it was built.
//!
//! # Limite connue
//!
//! There is no notification-area presence outside Windows. Linux would need
//! `libayatana-appindicator` at build **and** run time, on a platform where
//! Orion ships as a development build only ([`crate::main`] refuses a
//! Windows build without a real backend, but not a Linux one). The rest of
//! this module — labels, model, menu identifiers — is portable and tested
//! everywhere; only the wiring below is Windows-only.

// Outside Windows nothing consumes the model below — the menu that does is
// Windows-only. It is compiled and tested everywhere all the same: it holds the
// wording of the five tunnel states, and a rule that only ever compiles on the
// target platform is a rule the regression never checks.
#![cfg_attr(not(target_os = "windows"), allow(dead_code))]

use aether::TunnelState;

/// Identifier of the tray icon, used to find it back when the menu is rebuilt.
pub const TRAY_ID: &str = "orion-notification-area";

const STATUS_ID: &str = "orion-tray-status";
const EMPTY_ID: &str = "orion-tray-empty";
const OPEN_ID: &str = "orion-tray-open";
const PROFILES_ID: &str = "orion-tray-profiles";
const IMPORT_ID: &str = "orion-tray-import";
const LOGS_ID: &str = "orion-tray-logs";
const ABOUT_ID: &str = "orion-tray-about";
const QUIT_ID: &str = "orion-tray-quit";

/// Prefix of the per-profile items.
///
/// A profile name is user input and lands in a menu identifier, next to the
/// fixed ones. The colon is what keeps the two apart: no fixed identifier
/// contains one, so a profile called `orion-tray-quit` produces
/// `orion-tray-profile:orion-tray-quit` and cannot be mistaken for the item
/// that shuts Orion down.
const PROFILE_PREFIX: &str = "orion-tray-profile:";

/// Menu identifier of the item that toggles `name`.
pub fn profile_menu_id(name: &str) -> String {
    format!("{PROFILE_PREFIX}{name}")
}

/// The profile a menu identifier designates, if it designates one.
pub fn profile_from_menu_id(id: &str) -> Option<&str> {
    id.strip_prefix(PROFILE_PREFIX)
}

/// What the menu shows, read from the application state each time it is built.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrayModel {
    /// State of the tunnel, as the connection view reports it.
    pub state: TunnelState,
    /// Profile names, in the order the vault holds them.
    pub profiles: Vec<String>,
    /// The profile a connection would apply to — the selected one, or the
    /// first if nothing is selected, which is the fallback the connection
    /// view already applies.
    pub active: Option<String>,
}

/// The menu's model from what the engine answered.
///
/// `state` is `None` when the answer could not be read, and `config` is `None`
/// when the profile list could not be had. Either way the menu shows a failed
/// tunnel with nothing to offer: it never claims to be connected on a guess.
/// Otherwise the active profile is the selected one, or the first, which is
/// the fallback a connection applies.
pub fn model_from_engine(
    state: Option<TunnelState>,
    config: Option<(Vec<String>, Option<String>)>,
) -> TrayModel {
    let (Some(state), Some((profiles, selected))) = (state, config) else {
        return TrayModel {
            state: TunnelState::Failed,
            profiles: Vec::new(),
            active: None,
        };
    };
    let active = selected
        .filter(|name| profiles.iter().any(|profile| profile == name))
        .or_else(|| profiles.first().cloned());
    TrayModel {
        state,
        profiles,
        active,
    }
}

/// State wording.
///
/// The same words as `apps/orion/src/components/state.ts`, and the duplication
/// is deliberate: a native menu is not a webview, and routing these five labels
/// through the frontend would make the menu depend on a window that is hidden
/// precisely when the menu is the only thing left.
fn state_label(state: TunnelState) -> &'static str {
    match state {
        TunnelState::Up => "Connecté",
        TunnelState::Connecting => "Connexion…",
        TunnelState::CaptivePortal => "Portail captif",
        TunnelState::Failed => "Échec",
        TunnelState::Down => "Déconnecté",
    }
}

/// Vivid state tints of `components/state.ts` — graphics only, and the dot
/// is a graphic.
fn state_color(state: TunnelState) -> [u8; 3] {
    match state {
        TunnelState::Up => [0x12, 0xB9, 0x81],
        TunnelState::Connecting | TunnelState::CaptivePortal => [0xF5, 0xB3, 0x01],
        TunnelState::Failed => [0xEF, 0x44, 0x44],
        TunnelState::Down => [0x94, 0xA8, 0xA1],
    }
}

impl TrayModel {
    /// First line of the menu, the one that cannot be clicked.
    pub fn status_label(&self) -> String {
        format!("État : {}", state_label(self.state))
    }

    /// Hover text of the icon itself.
    ///
    /// It carries the profile name, which the status line does not: the
    /// tooltip is what the user reads **without** opening the menu, and
    /// "Connecté" alone leaves out the one thing a machine with several
    /// profiles needs — which one.
    pub fn tooltip(&self) -> String {
        match (self.carries_traffic(), self.active.as_deref()) {
            (true, Some(name)) => format!("Orion — {} ({name})", state_label(self.state)),
            _ => format!("Orion — {}", state_label(self.state)),
        }
    }

    /// Is this profile the one the current connection is about?
    ///
    /// `Failed` counts: the adapter stays mounted on failure (ADR-001 §3 bis)
    /// and the profile is still the one in force, so its item must offer to
    /// take the tunnel down rather than to mount a second one.
    pub fn is_engaged(&self, name: &str) -> bool {
        self.carries_traffic() && self.active.as_deref() == Some(name)
    }

    /// Does a tunnel exist, in whatever condition?
    fn carries_traffic(&self) -> bool {
        !matches!(self.state, TunnelState::Down)
    }
}

/// Renders the state dot drawn to the left of the status line.
///
/// Windows takes a bitmap, not a shape, so the circle is rasterised here.
/// Coverage is sampled on a 4×4 grid per pixel: an aliased 14-pixel disc reads
/// as a lozenge, and the dot is the one element of the menu the eye lands on
/// before reading anything.
#[cfg(target_os = "windows")]
fn status_dot(color: [u8; 3]) -> tauri::image::Image<'static> {
    const SIZE: u32 = 16;
    const SAMPLES: u32 = 4;
    /// Leaves a pixel of air around the disc: menu icons are drawn tight
    /// against the label, and a disc touching its own edge looks clipped.
    const RADIUS: f32 = 6.0;

    let centre = SIZE as f32 / 2.0;
    let mut rgba = Vec::with_capacity((SIZE * SIZE * 4) as usize);
    for y in 0..SIZE {
        for x in 0..SIZE {
            let mut covered = 0u32;
            for sub_y in 0..SAMPLES {
                for sub_x in 0..SAMPLES {
                    let sample_x = x as f32 + (sub_x as f32 + 0.5) / SAMPLES as f32 - centre;
                    let sample_y = y as f32 + (sub_y as f32 + 0.5) / SAMPLES as f32 - centre;
                    if sample_x * sample_x + sample_y * sample_y <= RADIUS * RADIUS {
                        covered += 1;
                    }
                }
            }
            let alpha = (covered * 255 / (SAMPLES * SAMPLES)) as u8;
            rgba.extend_from_slice(&[color[0], color[1], color[2], alpha]);
        }
    }
    tauri::image::Image::new_owned(rgba, SIZE, SIZE)
}

#[cfg(target_os = "windows")]
mod windows {
    use super::{
        model_from_engine, profile_from_menu_id, profile_menu_id, state_color, status_dot,
        TrayModel, ABOUT_ID, EMPTY_ID, IMPORT_ID, LOGS_ID, OPEN_ID, PROFILES_ID, QUIT_ID,
        STATUS_ID, TRAY_ID,
    };
    use crate::AppState;
    use aether::TunnelState;
    use orion_core::ClientEvent;
    use orion_engine::{EngineCommand, EngineReply};
    use tauri::{
        image::Image,
        menu::{CheckMenuItem, IconMenuItem, IsMenuItem, Menu, MenuItem, PredefinedMenuItem},
        tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
        AppHandle, Emitter, Manager,
    };

    /// Installs the icon and its menu.
    ///
    /// The menu built here is the empty one: the profile list lives behind an
    /// async lock, and `setup` is not the place to wait on it. The refresh that
    /// follows fills it in — a fraction of a second before anyone can open it.
    pub fn install(app: &mut tauri::App) -> anyhow::Result<()> {
        let icon = Image::from_bytes(include_bytes!("../icons/32x32.png"))
            .map_err(|error| anyhow::anyhow!("Orion's tray icon is unavailable: {error}"))?;
        let model = TrayModel::default();

        TrayIconBuilder::with_id(TRAY_ID)
            .icon(icon)
            .tooltip(model.tooltip())
            .menu(&build_menu(app.handle(), &model)?)
            .show_menu_on_left_click(false)
            .on_menu_event(|app, event| on_menu_event(app, event.id().0.as_str()))
            .on_tray_icon_event(|tray, event| {
                if matches!(
                    event,
                    TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    }
                ) {
                    if let Err(error) = crate::reveal_main_window(tray.app_handle()) {
                        tracing::warn!(%error, "unable to reveal Orion from the notification area");
                    }
                }
            })
            .build(app)?;

        refresh(app.handle());
        Ok(())
    }

    /// Rebuilds the menu from the current state. Never blocks the caller.
    pub fn refresh(app: &AppHandle) {
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            let model = read_model(&app).await;
            let Some(tray) = app.tray_by_id(TRAY_ID) else {
                return;
            };
            match build_menu(&app, &model) {
                Ok(menu) => {
                    if let Err(error) = tray.set_menu(Some(menu)) {
                        tracing::warn!(%error, "unable to refresh the notification-area menu");
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "unable to build the notification-area menu")
                }
            }
            if let Err(error) = tray.set_tooltip(Some(model.tooltip())) {
                tracing::warn!(%error, "unable to refresh the notification-area tooltip");
            }
        });
    }

    /// Reads the state the menu displays, through the engine's session.
    async fn read_model(app: &AppHandle) -> TrayModel {
        let state = app.state::<AppState>();
        let tunnel = match state.client.call(EngineCommand::GetState).await {
            Ok(EngineReply::State(text)) => TunnelState::parse(&text),
            Ok(_) => None,
            Err(error) => {
                tracing::warn!(%error, "état du tunnel illisible pour le menu");
                None
            }
        };
        let config = match state.client.call(EngineCommand::GetConfig).await {
            Ok(EngineReply::Config(view)) => Some((
                view.profiles
                    .iter()
                    .map(|profile| profile.name.clone())
                    .collect::<Vec<String>>(),
                view.selected,
            )),
            Ok(_) => None,
            Err(error) => {
                tracing::warn!(%error, "profils illisibles pour le menu");
                None
            }
        };
        model_from_engine(tunnel, config)
    }

    fn build_menu(app: &AppHandle, model: &TrayModel) -> anyhow::Result<Menu<tauri::Wry>> {
        // Disabled, both ways: the line is a statement, not an action. Enabling
        // it would put a clickable entry at the top of the menu that does
        // nothing.
        //
        // The dot is the one element of the menu that goes through a bitmap,
        // and a menu that refuses to build takes the whole start-up with it. If
        // that path fails, the line stays and only its dot is lost.
        let status: Box<dyn IsMenuItem<tauri::Wry>> = match IconMenuItem::with_id(
            app,
            STATUS_ID,
            model.status_label(),
            false,
            Some(status_dot(state_color(model.state))),
            None::<&str>,
        ) {
            Ok(item) => Box::new(item),
            Err(error) => {
                tracing::warn!(%error, "notification-area status dot unavailable");
                Box::new(MenuItem::with_id(
                    app,
                    STATUS_ID,
                    model.status_label(),
                    false,
                    None::<&str>,
                )?)
            }
        };

        let profiles: Vec<CheckMenuItem<tauri::Wry>> = model
            .profiles
            .iter()
            .map(|name| {
                CheckMenuItem::with_id(
                    app,
                    profile_menu_id(name),
                    name,
                    true,
                    model.is_engaged(name),
                    None::<&str>,
                )
            })
            .collect::<tauri::Result<_>>()?;
        // An empty list is a state of its own, and an empty block would leave
        // two separators against each other with nothing to say why.
        let empty = MenuItem::with_id(app, EMPTY_ID, "Aucun profil importé", false, None::<&str>)?;

        let open = MenuItem::with_id(app, OPEN_ID, "Ouvrir Orion", true, None::<&str>)?;
        let manage =
            MenuItem::with_id(app, PROFILES_ID, "Gestion des profils…", true, None::<&str>)?;
        let import = MenuItem::with_id(
            app,
            IMPORT_ID,
            "Importer un profil à partir d'un fichier…",
            true,
            None::<&str>,
        )?;
        let logs = MenuItem::with_id(app, LOGS_ID, "Journal d'Orion…", true, None::<&str>)?;
        let about = MenuItem::with_id(app, ABOUT_ID, "À propos d'Orion…", true, None::<&str>)?;
        let quit = MenuItem::with_id(app, QUIT_ID, "Quitter", true, None::<&str>)?;
        // Three separators rather than one placed three times: a menu item
        // belongs to a single position, and a handle inserted twice appears
        // once. They are declared here, before the list that borrows them —
        // locals are dropped in reverse order, and a separator declared after
        // the list would not outlive it.
        let separators = [
            PredefinedMenuItem::separator(app)?,
            PredefinedMenuItem::separator(app)?,
            PredefinedMenuItem::separator(app)?,
        ];

        let mut items: Vec<&dyn IsMenuItem<tauri::Wry>> = vec![status.as_ref()];
        items.push(&separators[0]);
        if profiles.is_empty() {
            items.push(&empty);
        } else {
            items.extend(
                profiles
                    .iter()
                    .map(|item| item as &dyn IsMenuItem<tauri::Wry>),
            );
        }
        items.push(&separators[1]);
        items.push(&open);
        items.push(&manage);
        items.push(&import);
        items.push(&logs);
        items.push(&separators[2]);
        items.push(&about);
        items.push(&quit);

        Ok(Menu::with_items(app, &items)?)
    }

    /// Routes a click.
    ///
    /// Every entry that opens a view also reveals the window: the menu is
    /// reachable while Orion is hidden, and a view change nobody can see is
    /// indistinguishable from an item that does nothing.
    fn on_menu_event(app: &AppHandle, id: &str) {
        match id {
            OPEN_ID => reveal(app, None),
            PROFILES_ID => reveal(app, Some("profiles")),
            IMPORT_ID => reveal(app, Some("import")),
            LOGS_ID => reveal(app, Some("logs")),
            ABOUT_ID => reveal(app, Some("about")),
            QUIT_ID => app.exit(0),
            other => {
                if let Some(name) = profile_from_menu_id(other) {
                    toggle_profile(app, name.to_string());
                }
            }
        }
    }

    fn reveal(app: &AppHandle, view: Option<&str>) {
        if let Err(error) = crate::reveal_main_window(app) {
            tracing::warn!(%error, "unable to reveal Orion from the notification area");
        }
        if let Some(view) = view {
            let _ = app.emit("helios://tray-view", view);
        }
    }

    /// Connects to `name`, or disconnects if that is the tunnel in force.
    ///
    /// The same gesture both ways, as WireGuard does with its tunnels: the
    /// checkbox states what is mounted, and clicking it changes that.
    fn toggle_profile(app: &AppHandle, name: String) {
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            let engaged = {
                let model = read_model(&app).await;
                model.is_engaged(&name)
            };
            if engaged {
                if let Err(error) = crate::stop_connection(&app).await {
                    tracing::warn!(%error, "unable to disconnect from the notification area");
                }
            } else if let Err(error) = crate::select_and_connect(&app, &name).await {
                // The window is probably hidden — this is the one path where a
                // refusal has no screen to land on. It is shown as an error the
                // interface will display, revealed at once, and written to the
                // log for the case where even that fails.
                tracing::warn!(%error, profil = %name, "connexion refusée depuis la zone de notification");
                let _ = app.emit(
                    "helios://event",
                    &ClientEvent::Error {
                        message: format!("Connexion à « {name} » impossible : {error}"),
                    },
                );
                reveal(&app, Some("connect"));
            }
            // The state events already trigger a refresh, but a refusal
            // produces none: without this the checkbox would stay where the
            // click left it, claiming a tunnel that was never mounted.
            refresh(&app);
        });
    }
}

#[cfg(target_os = "windows")]
pub use windows::install;

/// Rebuilds the notification-area menu from the current state.
///
/// A no-op outside Windows, so that the call sites — a state change, a saved
/// profile, a deleted one — read the same on every platform.
#[cfg(target_os = "windows")]
pub fn refresh(app: &tauri::AppHandle) {
    windows::refresh(app);
}

#[cfg(not(target_os = "windows"))]
pub fn refresh(_app: &tauri::AppHandle) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn model(state: TunnelState, profiles: &[&str], active: Option<&str>) -> TrayModel {
        TrayModel {
            state,
            profiles: profiles.iter().map(|name| name.to_string()).collect(),
            active: active.map(|name| name.to_string()),
        }
    }

    #[test]
    fn an_engine_that_cannot_answer_shows_a_failed_tunnel_with_nothing_to_offer() {
        let names = Some((vec!["bureau".to_string()], Some("bureau".to_string())));

        let unreadable_state = model_from_engine(None, names.clone());
        assert_eq!(unreadable_state.state, TunnelState::Failed);
        assert!(unreadable_state.profiles.is_empty());
        assert_eq!(unreadable_state.active, None);

        let failed_config = model_from_engine(Some(TunnelState::Up), None);
        assert_eq!(failed_config.state, TunnelState::Failed);
        assert!(failed_config.profiles.is_empty());
        assert_eq!(failed_config.active, None);
    }

    #[test]
    fn the_active_profile_is_the_selected_one_or_the_first() {
        let names = |selected: Option<&str>| {
            Some((
                vec!["alpha".to_string(), "bravo".to_string()],
                selected.map(str::to_string),
            ))
        };

        let selected = model_from_engine(Some(TunnelState::Down), names(Some("bravo")));
        assert_eq!(selected.active.as_deref(), Some("bravo"));

        let unknown = model_from_engine(Some(TunnelState::Down), names(Some("absent")));
        assert_eq!(unknown.active.as_deref(), Some("alpha"));

        let nothing = model_from_engine(Some(TunnelState::Down), Some((Vec::new(), None)));
        assert_eq!(nothing.active, None);
    }

    #[test]
    fn the_status_line_names_the_state_in_the_words_of_the_interface() {
        assert_eq!(
            model(TunnelState::Up, &[], None).status_label(),
            "État : Connecté"
        );
        assert_eq!(
            model(TunnelState::Down, &[], None).status_label(),
            "État : Déconnecté"
        );
        assert_eq!(
            model(TunnelState::Failed, &[], None).status_label(),
            "État : Échec"
        );
    }

    /// Without the name, a machine holding several profiles reads "Connecté"
    /// and still does not know to what.
    #[test]
    fn the_tooltip_names_the_profile_only_while_a_tunnel_exists() {
        assert_eq!(
            model(TunnelState::Up, &["bureau"], Some("bureau")).tooltip(),
            "Orion — Connecté (bureau)"
        );
        assert_eq!(
            model(TunnelState::Down, &["bureau"], Some("bureau")).tooltip(),
            "Orion — Déconnecté"
        );
    }

    /// A failed tunnel keeps its adapter mounted (ADR-001 §3 bis): the profile
    /// is still the one in force, and its item must offer to take it down.
    #[test]
    fn a_profile_is_engaged_as_long_as_the_adapter_is_not_released() {
        for state in [
            TunnelState::Up,
            TunnelState::Connecting,
            TunnelState::Failed,
            TunnelState::CaptivePortal,
        ] {
            assert!(model(state, &["bureau"], Some("bureau")).is_engaged("bureau"));
        }
        assert!(!model(TunnelState::Down, &["bureau"], Some("bureau")).is_engaged("bureau"));
        assert!(!model(TunnelState::Up, &["bureau", "labo"], Some("bureau")).is_engaged("labo"));
    }

    /// A profile name is user input placed in a menu identifier next to the
    /// fixed ones. It must never be able to impersonate one.
    #[test]
    fn a_profile_name_cannot_impersonate_a_command() {
        let hostile = profile_menu_id(QUIT_ID);
        assert_ne!(hostile, QUIT_ID);
        assert_eq!(profile_from_menu_id(&hostile), Some(QUIT_ID));
        for fixed in [OPEN_ID, PROFILES_ID, IMPORT_ID, LOGS_ID, ABOUT_ID, QUIT_ID] {
            assert_eq!(profile_from_menu_id(fixed), None);
        }
    }

    #[test]
    fn a_profile_identifier_survives_the_round_trip() {
        for name in ["bureau", "poste windows", "café:test", "l'agence"] {
            assert_eq!(profile_from_menu_id(&profile_menu_id(name)), Some(name));
        }
    }
}
