//! Interface graphique egui du client Helios VPN.
//!
//! Fenêtre compacte (~380×320 px) affichant l'état du tunnel, les métriques
//! réseau en temps réel, et les options split-tunnel / portail captif.
//! Sur Windows, la fermeture minimise dans le systray.

use std::sync::mpsc;
use std::time::{Duration, Instant};

use egui::{Color32, FontId, RichText, Ui};
use helios_core::TunnelState;
use tokio::sync::mpsc::Sender as AsyncSender;

use crate::api::{ApiCommand, AppStatus};

// ─── Palette de couleurs ──────────────────────────────────────────────────────

const COL_UP: Color32      = Color32::from_rgb(40, 228, 160);
const COL_TRANSIT: Color32 = Color32::from_rgb(255, 179, 71);
const COL_FAIL: Color32    = Color32::from_rgb(255, 87, 87);
const COL_DOWN: Color32    = Color32::from_rgb(130, 130, 130);
const COL_LABEL: Color32   = Color32::from_rgb(150, 150, 165);

// ─── App ──────────────────────────────────────────────────────────────────────

pub struct HeliosApp {
    status_rx:        mpsc::Receiver<AppStatus>,
    cmd_tx:           AsyncSender<ApiCommand>,
    status:           AppStatus,
    connected_since:  Option<Instant>,
    url_buf:          String,
    url_editing:      bool,
    split_tunnel_buf: String,

    #[cfg(feature = "tray")]
    _tray:   tray_icon::TrayIcon,
    #[cfg(feature = "tray")]
    quit_id: tray_icon::menu::MenuId,
}

impl HeliosApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        status_rx: mpsc::Receiver<AppStatus>,
        cmd_tx: AsyncSender<ApiCommand>,
        initial_url: String,
    ) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        apply_style(&cc.egui_ctx);

        #[cfg(feature = "tray")]
        let (_tray, quit_id) = build_tray();

        Self {
            status_rx,
            cmd_tx,
            status: AppStatus::default(),
            connected_since: None,
            url_buf: initial_url,
            url_editing: false,
            split_tunnel_buf: String::new(),
            #[cfg(feature = "tray")]
            _tray,
            #[cfg(feature = "tray")]
            quit_id,
        }
    }

    // ─── Helpers d'état ──────────────────────────────────────────────────

    fn state_color(&self) -> Color32 {
        if !self.status.reachable {
            return COL_FAIL;
        }
        match self.status.tunnel {
            TunnelState::Up | TunnelState::Rekeying                  => COL_UP,
            TunnelState::Connecting | TunnelState::CaptivePortal      => COL_TRANSIT,
            TunnelState::Failed                                        => COL_FAIL,
            TunnelState::Down                                          => COL_DOWN,
        }
    }

    fn state_label(&self) -> &'static str {
        if !self.status.reachable {
            return "Serveur inaccessible";
        }
        match self.status.tunnel {
            TunnelState::Up            => "Connecté",
            TunnelState::Rekeying      => "Renégociation",
            TunnelState::Connecting    => "Connexion…",
            TunnelState::Failed        => "Échec",
            TunnelState::Down          => "Déconnecté",
            TunnelState::CaptivePortal => "Portail captif",
        }
    }

    fn elapsed_str(&self) -> Option<String> {
        let s = self.connected_since?.elapsed().as_secs();
        Some(format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60))
    }

    fn bps(bps: u64) -> String {
        if bps >= 1_000_000 {
            format!("{:.1} MB/s", bps as f64 / 1_000_000.0)
        } else if bps >= 1_000 {
            format!("{:.0} KB/s", bps as f64 / 1_000.0)
        } else {
            format!("{bps} B/s")
        }
    }

    // ─── Mise à jour de l'état depuis le worker ───────────────────────────

    fn drain_status(&mut self) {
        let prev = self.status.tunnel;
        while let Ok(s) = self.status_rx.try_recv() {
            // Synchronise le buffer uniquement si le texte n'a pas été modifié par l'utilisateur.
            if self.split_tunnel_buf == self.status.split_tunnel_cidrs.join(", ") {
                self.split_tunnel_buf = s.split_tunnel_cidrs.join(", ");
            }
            self.status = s;
        }
        let curr = self.status.tunnel;

        if prev != curr {
            if curr == TunnelState::Up {
                self.connected_since = Some(Instant::now());
            } else if prev == TunnelState::Up {
                self.connected_since = None;
            }

            #[cfg(feature = "tray")]
            self.update_tray_icon();
        }
    }

    // ─── Rendu ───────────────────────────────────────────────────────────────

    fn render(&mut self, ui: &mut Ui) {
        let color     = self.state_color();
        let label     = self.state_label();
        let elapsed   = self.elapsed_str();
        let peer      = self.status.peer.clone();
        let profile   = self.status.active_profile.clone()
            .unwrap_or_else(|| self.status.ike_proposal.clone());
        let rx        = self.status.rx_bps;
        let tx_bps    = self.status.tx_bps;
        let dry_run   = self.status.dry_run;
        let reachable = self.status.reachable;
        let version   = self.status.version.clone();
        let tunnel    = self.status.tunnel;
        let portal_gw = self.status.captive_portal_gateway.clone();
        let mss       = self.status.mss_clamp;

        ui.add_space(14.0);

        // ── Indicateur d'état ─────────────────────────────────────────────
        ui.with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
            ui.label(RichText::new("●").color(color).size(26.0));
            ui.label(RichText::new(label).color(color).size(17.0).strong());
        });

        ui.add_space(10.0);
        ui.separator();
        ui.add_space(6.0);

        // ── Bannière portail captif ────────────────────────────────────────
        if tunnel == TunnelState::CaptivePortal {
            ui.horizontal(|ui| {
                ui.add_space(8.0);
                ui.label(
                    RichText::new("⚠ Portail captif détecté")
                        .size(13.0)
                        .color(COL_TRANSIT)
                        .strong(),
                );
            });
            if let Some(ref gw) = portal_gw {
                ui.horizontal(|ui| {
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(format!("Ouvrez http://{gw} dans votre navigateur"))
                            .size(11.0)
                            .color(COL_LABEL),
                    );
                });
            }
            ui.add_space(6.0);
            ui.with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
                let btn = egui::Button::new(
                    RichText::new("Connexion validée ✓").size(12.0),
                )
                .fill(Color32::from_rgb(50, 70, 20));
                if ui.add_sized([180.0, 26.0], btn).clicked() {
                    let _ = self.cmd_tx.try_send(ApiCommand::AcknowledgeCaptivePortal);
                }
            });
            ui.add_space(6.0);
            ui.separator();
            ui.add_space(6.0);
        }

        // ── Détails ───────────────────────────────────────────────────────
        if reachable && !peer.is_empty() {
            egui::Grid::new("details")
                .num_columns(2)
                .spacing([8.0, 3.0])
                .show(ui, |ui| {
                    row(ui, "Passerelle", &peer);

                    if !profile.is_empty() {
                        row(ui, "Profil", &profile);
                    }
                    if let Some(ref e) = elapsed {
                        row(ui, "Durée", e);
                    }
                    if rx > 0 || tx_bps > 0 {
                        row(ui, "Débit", &format!("↓ {}  ↑ {}", Self::bps(rx), Self::bps(tx_bps)));
                    }
                    if let Some(mss_val) = mss {
                        row(ui, "PMTUD", &format!("MTU {}  MSS {}", mss_val + 40, mss_val));
                    }
                    if dry_run {
                        ui.label(RichText::new("dry-run").size(11.0).color(Color32::from_rgb(180, 130, 220)));
                        ui.end_row();
                    }
                });
        } else if !reachable {
            ui.horizontal(|ui| {
                ui.add_space(8.0);
                ui.label(RichText::new("Impossible de joindre heliosd.").size(12.0).color(COL_FAIL));
            });
        }

        ui.add_space(10.0);

        // ── Bouton d'action principal ─────────────────────────────────────
        ui.with_layout(egui::Layout::top_down(egui::Align::Center), |ui| {
            let btn_size = [150.0_f32, 30.0_f32];
            match tunnel {
                TunnelState::Up | TunnelState::Rekeying => {
                    let btn = egui::Button::new(RichText::new("Déconnecter").size(13.0))
                        .fill(Color32::from_rgb(70, 18, 18));
                    if ui.add_sized(btn_size, btn).clicked() {
                        let _ = self.cmd_tx.try_send(ApiCommand::Disconnect);
                    }
                }
                TunnelState::Connecting | TunnelState::CaptivePortal => {
                    let btn = egui::Button::new(RichText::new("Connexion…").size(13.0));
                    ui.add_enabled_ui(false, |ui| { ui.add_sized(btn_size, btn); });
                }
                _ if reachable => {
                    let btn = egui::Button::new(RichText::new("Connecter").size(13.0))
                        .fill(Color32::from_rgb(18, 50, 35));
                    if ui.add_sized(btn_size, btn).clicked() {
                        let _ = self.cmd_tx.try_send(ApiCommand::Connect);
                    }
                }
                _ => {
                    let btn = egui::Button::new(RichText::new("Connecter").size(13.0));
                    ui.add_enabled_ui(false, |ui| { ui.add_sized(btn_size, btn); });
                }
            }
        });

        ui.add_space(8.0);

        // ── Options réseau (split-tunneling) ─────────────────────────────
        egui::CollapsingHeader::new(
            RichText::new("Split-tunneling").size(12.0).color(COL_LABEL),
        )
        .id_salt("split_tunnel_section")
        .show(ui, |ui| {
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("CIDRs locaux :").size(11.0).color(COL_LABEL));
                ui.add(
                    egui::TextEdit::singleline(&mut self.split_tunnel_buf)
                        .desired_width(180.0)
                        .hint_text("ex: 192.168.1.0/24, 10.0.0.0/8")
                        .font(FontId::monospace(11.0)),
                );
            });
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                if ui.small_button("Appliquer").clicked() {
                    let cidrs: Vec<String> = self.split_tunnel_buf
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    let _ = self.cmd_tx.try_send(ApiCommand::SetSplitTunnel(cidrs));
                }
                if ui.small_button("Désactiver").clicked() {
                    self.split_tunnel_buf.clear();
                    let _ = self.cmd_tx.try_send(ApiCommand::SetSplitTunnel(vec![]));
                }
            });
            if !self.status.split_tunnel_cidrs.is_empty() {
                ui.add_space(2.0);
                ui.label(
                    RichText::new(format!(
                        "Actif : {}",
                        self.status.split_tunnel_cidrs.join(", ")
                    ))
                    .size(10.0)
                    .color(COL_TRANSIT),
                );
            }
        });

        // ── Footer : URL du serveur ───────────────────────────────────────
        ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
            ui.add_space(4.0);
            ui.separator();

            ui.horizontal(|ui| {
                ui.add_space(4.0);
                let ver_text = if version.is_empty() {
                    "—".to_string()
                } else {
                    format!("v{version}")
                };
                ui.label(RichText::new(ver_text).size(10.0).color(Color32::DARK_GRAY));
            });

            ui.horizontal(|ui| {
                ui.add_space(4.0);
                ui.label(RichText::new("Serveur").size(11.0).color(COL_LABEL));

                if self.url_editing {
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut self.url_buf)
                            .desired_width(210.0)
                            .font(FontId::monospace(11.0)),
                    );
                    resp.request_focus();
                    if ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        let _ = self.cmd_tx.try_send(ApiCommand::SetUrl(self.url_buf.clone()));
                        self.url_editing = false;
                    } else if resp.lost_focus() {
                        self.url_editing = false;
                    }
                } else {
                    let lbl = ui.add(
                        egui::Label::new(
                            RichText::new(&self.url_buf)
                                .size(11.0)
                                .monospace()
                                .color(Color32::LIGHT_GRAY),
                        )
                        .sense(egui::Sense::click()),
                    );
                    if lbl.clicked() {
                        self.url_editing = true;
                    }
                    lbl.on_hover_text("Cliquer pour modifier l'URL du daemon");
                }
            });
        });
    }

    // ─── Icône systray dynamique ──────────────────────────────────────────

    #[cfg(feature = "tray")]
    fn update_tray_icon(&self) {
        let color = match self.status.tunnel {
            TunnelState::Up | TunnelState::Rekeying                  => [40u8, 228, 160],
            TunnelState::Connecting | TunnelState::CaptivePortal      => [255, 179, 71],
            TunnelState::Failed                                        => [255, 87, 87],
            TunnelState::Down                                          => [130, 130, 130],
        };
        if let Ok(icon) = circle_icon(color) {
            let _ = self._tray.set_icon(Some(icon));
        }
    }
}

// ─── eframe::App ─────────────────────────────────────────────────────────────

impl eframe::App for HeliosApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_status();

        #[cfg(feature = "tray")]
        {
            use tray_icon::TrayIconEvent;
            use tray_icon::menu::MenuEvent;

            if let Ok(e) = TrayIconEvent::receiver().try_recv() {
                if matches!(e, TrayIconEvent::Click { .. }) {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
            }
            if let Ok(e) = MenuEvent::receiver().try_recv() {
                if e.id == self.quit_id {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }

        #[cfg(feature = "tray")]
        if ctx.input(|i| i.viewport().close_requested()) {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            self.render(ui);
        });

        if self.connected_since.is_some() || self.status.tunnel == TunnelState::CaptivePortal {
            ctx.request_repaint_after(Duration::from_secs(1));
        }
    }
}

// ─── Utilitaires visuels ──────────────────────────────────────────────────────

fn row(ui: &mut Ui, label: &str, value: &str) {
    ui.label(RichText::new(label).size(12.0).color(COL_LABEL));
    ui.label(RichText::new(value).size(13.0));
    ui.end_row();
}

fn apply_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();
    style.text_styles.insert(
        egui::TextStyle::Body,
        FontId::proportional(14.0),
    );
    style.text_styles.insert(
        egui::TextStyle::Small,
        FontId::proportional(11.0),
    );
    style.spacing.item_spacing = egui::vec2(6.0, 4.0);
    ctx.set_style(style);
}

// ─── Systray ─────────────────────────────────────────────────────────────────

#[cfg(feature = "tray")]
fn build_tray() -> (tray_icon::TrayIcon, tray_icon::menu::MenuId) {
    use tray_icon::{TrayIconBuilder, menu::{Menu, MenuItem}};

    let quit    = MenuItem::new("Quitter Helios", true, None);
    let quit_id = quit.id().clone();
    let menu    = Menu::new();
    let _       = menu.append(&quit);

    let icon = circle_icon([130, 130, 130]).expect("icône systray");
    let tray = TrayIconBuilder::new()
        .with_icon(icon)
        .with_tooltip("Helios VPN")
        .with_menu(Box::new(menu))
        .build()
        .expect("création systray");

    (tray, quit_id)
}

#[cfg(feature = "tray")]
fn circle_icon(color: [u8; 3]) -> anyhow::Result<tray_icon::Icon> {
    const S: u32 = 16;
    let cx = S as f32 / 2.0;
    let cy = S as f32 / 2.0;
    let r  = S as f32 / 2.0 - 1.0;
    let mut rgba = vec![0u8; (S * S * 4) as usize];
    for y in 0..S {
        for x in 0..S {
            let dx = x as f32 + 0.5 - cx;
            let dy = y as f32 + 0.5 - cy;
            if dx * dx + dy * dy <= r * r {
                let i = ((y * S + x) * 4) as usize;
                rgba[i]     = color[0];
                rgba[i + 1] = color[1];
                rgba[i + 2] = color[2];
                rgba[i + 3] = 255;
            }
        }
    }
    Ok(tray_icon::Icon::from_rgba(rgba, S, S)?)
}
