//! Séquestre de l'identité de la gateway, côté **poste opérateur**.
//!
//! La gateway écrit à chaque scellement une copie de sa clé privée WireGuard,
//! chiffrée vers la clé publique de l'opérateur (`helio_tpm::escrow`). C'est le
//! seul moyen de récupérer l'identité d'une gateway après un changement de PCR
//! — nouveau noyau, bootloader ou firmware — sans accès SSH.
//!
//! Le code existait des deux côtés sans qu'aucun outil ne l'expose : la ligne
//! `escrow_public_key` de `network.toml` était un commentaire que personne ne
//! pouvait honorer. Ces deux commandes ferment le circuit.
//!
//! # Où vit la clé privée d'opérateur
//!
//! **Jamais sur la gateway qu'elle secourt.** Un séquestre déposé à côté de sa
//! propre clé de déchiffrement ne protège plus rien : il ajoute une copie en
//! clair de l'identité, exactement ce que le scellement TPM existe pour
//! empêcher. Elle vit hors ligne, sur le poste opérateur (ADR-004 §2).

use std::path::Path;

use anyhow::{bail, Context, Result};
use base64::Engine as _;

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

const PRIVATE_FILE: &str = "escrow-private.key";
const PUBLIC_FILE: &str = "escrow-public.key";

/// Génère la paire de séquestre de l'opérateur dans un répertoire neuf.
pub fn keygen(output_dir: &Path) -> Result<()> {
    crate::files::create_private_dir(output_dir)?;
    let (private_key, public_key) = helio_tpm::escrow::generate_operator_keypair()
        .map_err(|e| anyhow::anyhow!("génération de la paire de séquestre : {e}"))?;

    let public_b64 = B64.encode(public_key);
    crate::files::write_new(
        &output_dir.join(PRIVATE_FILE),
        B64.encode(private_key.as_slice()).as_bytes(),
        true,
    )?;
    crate::files::write_new(&output_dir.join(PUBLIC_FILE), public_b64.as_bytes(), false)?;

    println!("{public_b64}");
    eprintln!();
    eprintln!("  Clé publique de séquestre ci-dessus. À déclarer sur la gateway :");
    eprintln!();
    eprintln!("    escrow_public_key = \"{public_b64}\"");
    eprintln!();
    eprintln!(
        "  {} doit rester hors ligne et hors de la gateway : c'est la seule",
        output_dir.join(PRIVATE_FILE).display()
    );
    eprintln!("  moitié capable d'ouvrir un séquestre.");
    Ok(())
}

/// Ouvre un séquestre et écrit le fichier de récupération à déposer sur la
/// gateway.
///
/// La clé retrouvée n'est **pas** affichée : seule sa moitié publique l'est,
/// ce qui suffit à vérifier qu'on a bien ouvert le séquestre de la gateway
/// attendue, sans en faire défiler le secret dans un terminal ni un journal.
pub fn open(escrow_path: &Path, private_key_path: &Path, output: &Path) -> Result<()> {
    let blob = std::fs::read(escrow_path)
        .with_context(|| format!("lecture du séquestre {}", escrow_path.display()))?;
    let private_b64 = std::fs::read_to_string(private_key_path)
        .with_context(|| format!("lecture de {}", private_key_path.display()))?;
    let private_key = B64
        .decode(private_b64.trim())
        .context("clé privée de séquestre illisible (base64 attendu)")?;
    if private_key.len() != helio_tpm::escrow::KEY_LEN {
        bail!(
            "clé privée de séquestre de {} octets au lieu de {}",
            private_key.len(),
            helio_tpm::escrow::KEY_LEN
        );
    }

    let recovered = helio_tpm::escrow::open_as_operator(&private_key, &blob)
        .map_err(|e| anyhow::anyhow!("ouverture du séquestre impossible : {e}"))?;
    let wg_private_key = std::str::from_utf8(recovered.as_slice())
        .context("le séquestre ne contient pas une clé WireGuard base64")?
        .trim()
        .to_string();
    let wg_public_key = aether::wg::public_from_private(&wg_private_key)
        .context("le séquestre ne contient pas une clé WireGuard valide")?;

    crate::files::write_new(output, wg_private_key.as_bytes(), true)?;

    println!("{wg_public_key}");
    eprintln!();
    eprintln!("  Identité retrouvée : la clé publique ci-dessus doit être celle que");
    eprintln!("  les clients connaissent déjà. Si elle diffère, ce séquestre n'est");
    eprintln!("  pas celui de cette gateway — ne pas le déposer.");
    eprintln!();
    eprintln!(
        "  Déposer {} dans /var/lib/helios/wg-key.recovery sur la gateway, puis",
        output.display()
    );
    eprintln!("  redémarrer : elle rescelle la clé et efface le fichier.");
    Ok(())
}
