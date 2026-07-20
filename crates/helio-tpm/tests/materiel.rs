//! Essais TPM sur matériel réel — cible uniquement.
//!
//! Les 27 tests unitaires du crate s'exécutent contre `DryRunTpm` : ils
//! vérifient la *logique* de décision, jamais le silicium. Ce fichier ferme
//! l'écart, en exerçant `/dev/tpmrm0` pour de bon.
//!
//! # Ce que ces essais écrivent, et pourquoi c'est réversible
//!
//! Le backend réel n'utilise que `create_primary` (clé primaire **transitoire**,
//! jamais rendue persistante), `create`, `load`, `policy_pcr` et `unseal`. Aucune
//! écriture NV, aucun `evict_control`, aucun changement de hiérarchie, aucun
//! `clear`. Tout l'état Helios tient dans les fichiers désignés par
//! `TpmSettings` — ici un répertoire temporaire, jamais `/var/lib/helios`.
//!
//! Supprimer ce répertoire ramène donc la machine à son état initial. C'est ce
//! qui distingue ces essais de ceux du cycle RAUC, qui touchaient aux slots de
//! boot et pouvaient rendre la cible non amorçable.
//!
//! Aucun PCR n'est étendu : une extension est irréversible jusqu'au prochain
//! redémarrage. Le refus sur PCR divergents est obtenu en *scellant* sous une
//! sélection puis en tentant le déscellement sous une autre — même effet
//! observable, sans toucher à l'état de la plateforme.
//!
//! # Exécution
//!
//! Ces essais ne s'exécutent que si `HELIOS_TPM_MATERIEL=1` est positionné :
//! `cargo test --all-features` doit rester jouable sur une machine sans TPM,
//! WSL2 comprise. La campagne cible positionne la variable, ce qui garantit
//! qu'ils tournent réellement quelque part.
//!
//! ```sh
//! HELIOS_TPM_MATERIEL=1 cargo test -p helio-tpm --features tpm --test materiel
//! ```
#![cfg(feature = "tpm")]

use helio_tpm::{BootController, BootDecision, SealedKeystore, TpmSettings};

/// Indique si les essais matériels sont demandés.
///
/// L'absence de la variable n'est pas un échec : c'est un environnement qui ne
/// permet pas de trancher. Le message le dit explicitement plutôt que de
/// laisser croire à un succès.
fn materiel_demande(nom: &str) -> bool {
    if std::env::var("HELIOS_TPM_MATERIEL").as_deref() == Ok("1") {
        return true;
    }
    eprintln!("[hors portée] {nom} : positionner HELIOS_TPM_MATERIEL=1 sur une cible à TPM");
    false
}

/// Réglages pointant sur un répertoire jetable, provisionnement autorisé.
fn reglages(dir: &std::path::Path, provisionnement: bool) -> TpmSettings {
    TpmSettings {
        enabled: true,
        enforce: true,
        allow_provisioning: provisionnement,
        device: "/dev/tpmrm0".to_string(),
        pcr_bank: "sha256".to_string(),
        pcr_selection: vec![0, 4, 7],
        sealed_blob_path: dir.join("sealed.key").to_string_lossy().into_owned(),
        ticket_path: dir
            .join("reseal-ticket.json")
            .to_string_lossy()
            .into_owned(),
        state_path: dir.join("tpm-state.json").to_string_lossy().into_owned(),
    }
}

fn repertoire_jetable(nom: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("helios-tpm-{nom}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("création du répertoire d'essai");
    dir
}

#[test]
fn le_secret_provisionne_est_reobtenu_a_l_identique() {
    if !materiel_demande("scellement puis déscellement") {
        return;
    }
    let dir = repertoire_jetable("aller-retour");

    // Premier boot : aucun blob, provisionnement autorisé.
    let provisionne = match BootController::unlock(&reglages(&dir, true)) {
        Ok(BootDecision::Provisioned(secret)) => secret,
        autre => panic!("provisionnement attendu, obtenu : {autre:?}"),
    };
    assert!(dir.join("sealed.key").exists(), "aucun blob scellé écrit");

    // Boot suivant : le blob existe, le provisionnement n'est plus autorisé.
    let descelle = match BootController::unlock(&reglages(&dir, false)) {
        Ok(BootDecision::Unsealed(secret)) => secret,
        autre => panic!("déscellement attendu, obtenu : {autre:?}"),
    };

    // Le cœur de l'essai : c'est l'égalité des deux secrets qui prouve que le
    // TPM a réellement scellé puis déscellé, et non qu'un chemin dégradé a
    // renvoyé deux valeurs plausibles.
    assert_eq!(
        provisionne.as_bytes(),
        descelle.as_bytes(),
        "le secret déscellé diffère du secret scellé"
    );

    std::fs::remove_dir_all(&dir).expect("nettoyage");
}

#[test]
fn un_blob_absent_hors_provisionnement_est_refuse() {
    if !materiel_demande("fail-closed sur blob absent") {
        return;
    }
    let dir = repertoire_jetable("blob-absent");

    let issue = BootController::unlock(&reglages(&dir, false));
    assert!(
        issue.is_err(),
        "un blob absent hors provisionnement doit échouer, obtenu : {issue:?}"
    );

    std::fs::remove_dir_all(&dir).expect("nettoyage");
}

#[test]
fn un_blob_altere_est_refuse() {
    if !materiel_demande("refus d'un blob altéré") {
        return;
    }
    let dir = repertoire_jetable("blob-altere");
    let blob = dir.join("sealed.key");

    BootController::unlock(&reglages(&dir, true)).expect("provisionnement initial");

    // Retourner un octet au milieu du blob : le TPM doit refuser de le charger
    // ou d'en dériver le secret. Un déscellement qui réussirait signalerait que
    // l'intégrité n'est pas vérifiée.
    let mut octets = std::fs::read(&blob).expect("lecture du blob");
    let milieu = octets.len() / 2;
    octets[milieu] ^= 0xFF;
    std::fs::write(&blob, &octets).expect("écriture du blob altéré");

    let issue = BootController::unlock(&reglages(&dir, false));
    assert!(
        issue.is_err(),
        "un blob altéré doit être refusé, obtenu : {issue:?}"
    );

    std::fs::remove_dir_all(&dir).expect("nettoyage");
}

#[test]
fn une_selection_pcr_alteree_dans_le_blob_refuse_le_descellement() {
    if !materiel_demande("liaison aux PCR effectivement appliquée") {
        return;
    }
    let dir = repertoire_jetable("pcr-alteres");
    let blob = dir.join("sealed.key");

    BootController::unlock(&reglages(&dir, true)).expect("provisionnement sous PCR 0,4,7");

    // La sélection PCR appliquée au déscellement vient du **blob**, pas des
    // réglages : le blob est auto-descriptif (`unmarshal_blob`). Modifier
    // `TpmSettings::pcr_selection` n'aurait donc aucun effet ici, et un essai
    // bâti là-dessus passerait au vert sans rien prouver.
    //
    // La propriété qui compte est ailleurs : le digest de politique est figé
    // dans l'objet scellé à sa création. Réécrire la sélection inscrite dans le
    // blob produit une politique qui ne correspond plus, et le TPM doit refuser.
    // C'est ce qui empêche un attaquant de déscelller en déclarant une liaison
    // plus faible que celle d'origine.
    //
    // Disposition du blob : MAGIC(4) | VERSION(1) | BANQUE(1) | n(1) | indices(n).
    const OFFSET_INDICES: usize = 7;
    let mut octets = std::fs::read(&blob).expect("lecture du blob");
    assert_eq!(
        octets[OFFSET_INDICES - 1],
        3,
        "trois indices PCR attendus dans le blob"
    );
    assert_eq!(
        &octets[OFFSET_INDICES..OFFSET_INDICES + 3],
        &[0, 4, 7],
        "sélection PCR inattendue dans le blob"
    );
    // PCR 7 (Secure Boot) → PCR 6 : liaison différente, objet inchangé.
    octets[OFFSET_INDICES + 2] = 6;
    std::fs::write(&blob, &octets).expect("écriture du blob altéré");

    let issue = BootController::unlock(&reglages(&dir, false));
    assert!(
        issue.is_err(),
        "une sélection PCR réécrite doit refuser le déscellement, obtenu : {issue:?}"
    );

    std::fs::remove_dir_all(&dir).expect("nettoyage");
}

#[test]
fn la_cle_wireguard_survit_a_un_aller_retour_scelle() {
    if !materiel_demande("coffre de la clé WireGuard") {
        return;
    }
    let dir = repertoire_jetable("keystore");

    let secret = match BootController::unlock(&reglages(&dir, true)) {
        Ok(BootDecision::Provisioned(secret)) => secret,
        autre => panic!("provisionnement attendu, obtenu : {autre:?}"),
    };

    // Une clé privée WireGuard fait 32 octets ; on vérifie qu'elle ressort
    // intacte du coffre chiffré par le secret dérivé du TPM.
    let cle: Vec<u8> = (0u8..32).collect();
    let coffre = SealedKeystore::new(dir.join("wg-key.sealed"));
    coffre.store(&secret, &cle).expect("scellement de la clé");
    assert!(coffre.exists(), "le coffre n'a pas été écrit");

    let relue = coffre.load(&secret).expect("relecture de la clé");
    assert_eq!(relue.as_slice(), cle.as_slice(), "clé WireGuard altérée");

    coffre.remove().expect("retrait du coffre");
    assert!(!coffre.exists(), "le coffre subsiste après retrait");

    std::fs::remove_dir_all(&dir).expect("nettoyage");
}
