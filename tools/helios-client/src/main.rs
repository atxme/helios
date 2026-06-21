//! `helios-client` — client VPN léger multiplateforme pour heliosd.
//!
//! Fenêtre compacte (~380×320 px) affichant l'état IPsec en temps réel.
//! Sur Windows/macOS la fermeture minimise dans le systray (feature `tray`).
//!
//! ```sh
//! # Lancer avec heliosd sur l'hôte par défaut :
//! cargo run -p helios-client --no-default-features
//!
//! # Daemon distant :
//! HELIOS_URL=http://192.168.1.1:8080 cargo run -p helios-client --no-default-features
//! ```

mod api;
mod app;

use std::sync::Arc;

use app::HeliosApp;

fn main() {

    gtk::init().expect("Failed to initialize GTK");
    
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime tokio");

    let (status_tx, status_rx) = std::sync::mpsc::channel::<api::AppStatus>();
    let (cmd_tx, cmd_rx)       = tokio::sync::mpsc::channel::<api::ApiCommand>(16);

    let initial_url = std::env::var("HELIOS_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());

    rt.spawn(api::run(status_tx, cmd_rx, initial_url.clone()));

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Helios VPN")
            .with_inner_size([380.0, 320.0])
            .with_resizable(false)
            .with_maximize_button(false)
            .with_icon(Arc::new(app_icon())),
        ..Default::default()
    };

    eframe::run_native(
        "Helios VPN",
        options,
        Box::new(move |cc| Ok(Box::new(HeliosApp::new(cc, status_rx, cmd_tx, initial_url)))),
    )
    .expect("erreur eframe");

    rt.shutdown_background();
}

/// Icône de l'application : cercle vert 32×32.
fn app_icon() -> egui::IconData {
    const S: u32 = 32;
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
                rgba[i]     = 40;
                rgba[i + 1] = 228;
                rgba[i + 2] = 160;
                rgba[i + 3] = 255;
            }
        }
    }
    egui::IconData { rgba, width: S, height: S }
}
