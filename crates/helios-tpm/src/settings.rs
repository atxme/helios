/// TPM controller parameters — appliance architecture constants.
///
/// All choices (PCR bank, selection, persistence paths) are architecture
/// decisions frozen for the product's lifetime. Only `enabled` varies: it is
/// set to `true` only if the `tpm` feature is compiled in (physical target).
pub struct TpmSettings {
    /// Enables sealing/unsealing. `false` = bypass (WSL2 / dev).
    pub enabled: bool,
    /// `false` = log only on failure (DEBUG ONLY).
    pub enforce: bool,
    /// Allows TOFU provisioning if no sealed blob exists.
    /// `true` only at the factory (first boot). In the field, a missing blob
    /// is a security anomaly.
    pub allow_provisioning: bool,
    pub device: String,
    pub pcr_bank: String,
    /// PCRs bound to sealing: 0=firmware, 4=bootloader, 7=Secure Boot.
    pub pcr_selection: Vec<u8>,
    pub sealed_blob_path: String,
    pub ticket_path: String,
    pub state_path: String,
    /// PCRs bound to the **update window** — a strict subset of
    /// [`Self::pcr_selection`], PCR 4 excluded.
    ///
    /// PCR 4 is precisely what a kernel or bootloader update moves, so a
    /// window bound to it would be unusable at the very boot it exists for.
    /// 0 and 7 stay: substituting the firmware or turning Secure Boot off
    /// still closes this path.
    pub update_window_pcr_selection: Vec<u8>,
    /// Non-secret marker recording the deadline and nominal-blob anchor.
    pub update_window_marker_path: String,
    /// NV index that carries the window payload (owner range).
    pub update_window_nv_index: u32,
    /// How long an armed window stays valid, in seconds.
    pub update_window_seconds: u64,
}

impl Default for TpmSettings {
    fn default() -> Self {
        Self {
            enabled: cfg!(feature = "tpm"),
            enforce: true,
            allow_provisioning: false,
            device: "/dev/tpmrm0".to_string(),
            pcr_bank: "sha256".to_string(),
            pcr_selection: vec![0, 4, 7],
            sealed_blob_path: "/var/lib/helios/sealed.key".to_string(),
            ticket_path: "/var/lib/helios/reseal-ticket.json".to_string(),
            state_path: "/var/lib/helios/tpm-state.json".to_string(),
            update_window_pcr_selection: vec![0, 7],
            update_window_marker_path: "/var/lib/helios/update-window.marker".to_string(),
            update_window_nv_index: 0x0180_4845,
            update_window_seconds: 30 * 60,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_bind_the_expected_boot_chain_and_storage_paths() {
        let settings = TpmSettings::default();

        assert_eq!(settings.enabled, cfg!(feature = "tpm"));
        assert!(settings.enforce);
        assert!(!settings.allow_provisioning);
        assert_eq!(settings.device, "/dev/tpmrm0");
        assert_eq!(settings.pcr_bank, "sha256");
        assert_eq!(settings.pcr_selection, [0, 4, 7]);
        assert_eq!(settings.sealed_blob_path, "/var/lib/helios/sealed.key");
        assert_eq!(settings.ticket_path, "/var/lib/helios/reseal-ticket.json");
        assert_eq!(settings.state_path, "/var/lib/helios/tpm-state.json");
        assert_eq!(
            settings.update_window_marker_path,
            "/var/lib/helios/update-window.marker"
        );
    }

    /// The window must never be bound to more than the nominal sealing, and
    /// never to PCR 4 — the one a kernel update moves.
    #[test]
    fn the_update_window_is_a_strict_subset_without_pcr_4() {
        let settings = TpmSettings::default();

        assert!(!settings.update_window_pcr_selection.contains(&4));
        assert!(settings
            .update_window_pcr_selection
            .iter()
            .all(|index| settings.pcr_selection.contains(index)));
        assert!(
            settings.update_window_pcr_selection.len() < settings.pcr_selection.len(),
            "a window bound to the whole selection would be pointless"
        );
    }
}
