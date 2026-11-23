//! Tests of the gateway key-negotiation integration, one file per capability.

mod admission_generation;
mod fixtures;
mod generation_limits;
mod identity;
mod interop;
mod reclaimer;
mod renewal;
mod server_startup;
mod transaction;
mod transaction_cancellation;

#[cfg(feature = "tpm")]
#[path = "../../../../helios-tpm/tests/support/swtpm.rs"]
mod swtpm;

/// Uses the configured software backend without a TPM device or host paths.
pub(super) fn isolated_boot(directory: &std::path::Path) -> Option<helios_tpm::BootDecision> {
    let path = |name| directory.join(name).to_string_lossy().into_owned();
    #[cfg(feature = "tpm")]
    let device = {
        let Some(simulator) = swtpm::Swtpm::start().expect("start isolated software TPM") else {
            eprintln!("[out of scope] missing swtpm or loopback for sealed gateway fixture");
            return None;
        };
        simulator
    };
    #[cfg(feature = "tpm")]
    let tcti = device.tcti().to_owned();
    #[cfg(not(feature = "tpm"))]
    let tcti = path("absent-tpm");

    let settings = helios_tpm::TpmSettings {
        enabled: true,
        allow_provisioning: true,
        device: tcti,
        sealed_blob_path: path("sealed-root"),
        ticket_path: path("reseal-ticket"),
        update_window_marker_path: path("window-marker"),
        simulated_counter_path: path("counter"),
        counter_status_path: path("counter-status"),
        ..helios_tpm::TpmSettings::default()
    };
    Some(helios_tpm::BootController::unlock(&settings).expect("provision test vault root"))
}
