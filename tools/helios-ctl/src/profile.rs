//! Émission d'un profil client, au format lu par l'import Orion.
//!
//! Le document `orion-profile` v1 avait un consommateur
//! (`orion_core::profile_import`) et aucun producteur : le profil se recopiait
//! à la main. C'est ici que la boucle se ferme.
//!
//! # Deux modes, et pourquoi le défaut est le bon (ADR-004 §6)
//!
//! * **Invitation** — l'opérateur part de la clé **publique** que le client lui
//!   a transmise. Il l'admet et renvoie tout sauf la clé privée, qu'il n'a
//!   jamais détenue. Orion complète depuis le profil local de même nom.
//! * **Assisté** (`--with-private-key`) — l'opérateur génère la paire et remet
//!   un profil complet. C'est le seul chemin où une clé privée client existe
//!   hors du poste client. Il est conservé parce qu'un parc où l'utilisateur ne
//!   peut rien faire existe réellement, et que l'interdire ferait refaire la
//!   même chose à la main, plus mal.
//!
//! Les deux modes admettent le pair : un profil émis pour une clé que la
//! gateway ignore ne monterait aucun tunnel, et l'utilisateur n'aurait aucun
//! moyen de comprendre pourquoi.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use reqwest::Client;
use serde::Serialize;

use crate::api;

/// Identifiant et version du document, tels qu'`orion-core` les exige.
const FORMAT: &str = "orion-profile";
const VERSION: u16 = 1;

pub struct EmitOptions {
    /// Nom du profil, aussi utilisé comme nom du pair sur la gateway.
    pub name: String,
    /// Endpoint UDP public de la gateway (`IP:port` ou `FQDN:port`).
    pub endpoint: String,
    /// Clé publique du client, reçue hors bande. Mode invitation.
    pub public_key: Option<String>,
    /// Génère la paire côté opérateur. Mode assisté.
    pub with_private_key: bool,
    /// Admet le pair comme administrateur du plan de contrôle.
    pub admin: bool,
    /// Fichier de sortie. Absent : sortie standard.
    pub output: Option<PathBuf>,
}

#[derive(Serialize)]
struct Document<'a> {
    format: &'a str,
    version: u16,
    profile: Profile<'a>,
}

/// Le champ `private_key` est omis en mode invitation : `orion-core` le traite
/// comme absent, pas comme vide, et complète depuis le profil local.
#[derive(Serialize)]
struct Profile<'a> {
    name: &'a str,
    endpoint: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_key: Option<&'a str>,
    peer_public_key: &'a str,
    address: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    heliosd_url: Option<String>,
}

pub async fn emit(client: &Client, base: &str, options: EmitOptions) -> Result<()> {
    let (public_key, private_key) = resolve_keys(&options)?;

    let view = api::network(client, base).await?;
    let gateway_public_key = view
        .wg_public_key
        .clone()
        .filter(|k| !k.is_empty())
        .context(
            "la gateway n'a pas encore d'identité WireGuard — jouer `heliosd init-identity` \
         sur la gateway, avec accès console",
        )?;

    let address = admit_or_reuse(client, base, &options, &public_key).await?;

    let document = Document {
        format: FORMAT,
        version: VERSION,
        profile: Profile {
            name: &options.name,
            endpoint: &options.endpoint,
            private_key: private_key.as_deref(),
            peer_public_key: &gateway_public_key,
            address: &address,
            heliosd_url: heliosd_url(&view.wg_address),
        },
    };
    let json = serde_json::to_string_pretty(&document).context("sérialisation du profil")?;

    match &options.output {
        Some(path) => {
            // Un profil complet porte une clé privée : il naît en 0600, et ne
            // remplace jamais un fichier existant en silence.
            crate::files::write_new(path, json.as_bytes(), private_key.is_some())?;
            report(path, &options, &public_key);
        }
        None => println!("{json}"),
    }
    Ok(())
}

/// Choisit le mode et rend `(clé publique, clé privée éventuelle)`.
fn resolve_keys(options: &EmitOptions) -> Result<(String, Option<String>)> {
    match (&options.public_key, options.with_private_key) {
        (Some(_), true) => bail!(
            "--public-key et --with-private-key s'excluent : soit le client détient déjà sa \
             clé et fournit sa moitié publique, soit l'opérateur génère la paire"
        ),
        (Some(public_key), false) => {
            let public_key = public_key.trim().to_string();
            aether::wg::validate_key(&public_key).context("clé publique du client invalide")?;
            Ok((public_key, None))
        }
        (None, true) => {
            let pair = aether::wg::generate_keypair()
                .map_err(|e| anyhow::anyhow!("génération de la paire client : {e}"))?;
            Ok((pair.public_key, Some(pair.private_key.expose().to_string())))
        }
        (None, false) => bail!(
            "indiquer --public-key <clé publique du client> (mode recommandé : le secret du \
             client ne voyage pas), ou --with-private-key pour que l'opérateur génère la paire"
        ),
    }
}

/// Admet le pair, ou réutilise son admission si elle correspond déjà.
///
/// Réémettre un profil perdu est un besoin courant. Sans ce rattrapage, il
/// faudrait révoquer le pair pour le réadmettre — donc couper l'utilisateur
/// pour lui refabriquer le fichier qu'il a égaré.
async fn admit_or_reuse(
    client: &Client,
    base: &str,
    options: &EmitOptions,
    public_key: &str,
) -> Result<String> {
    match crate::peer::admit(client, base, &options.name, public_key, options.admin).await {
        Ok(peer) => Ok(peer.address),
        Err(error) => {
            let view = api::network(client, base).await?;
            let existing = view
                .peers
                .iter()
                .find(|peer| peer.name.trim() == options.name.trim())
                .ok_or(error)?;
            if existing.public_key.trim() != public_key {
                bail!(
                    "un pair « {} » est déjà admis avec une autre clé publique. Le révoquer \
                     d'abord (`helios-ctl peer revoke --name {}`) si l'ancienne clé est \
                     bien perdue : le client qui la détient tombera au prochain handshake.",
                    existing.name,
                    existing.name
                );
            }
            eprintln!(
                "  \x1b[2mpair déjà admis avec la même clé — profil réémis sur son adresse\x1b[0m"
            );
            Ok(existing.address.clone())
        }
    }
}

/// URL de l'API vue depuis le tunnel, dérivée de l'adresse de la gateway.
///
/// Sert la télémétrie enrichie et le provisioning post-quantique du client.
/// Absente si l'adresse est illisible : un profil sans cette URL fonctionne,
/// il perd seulement l'enrichissement.
fn heliosd_url(wg_address: &str) -> Option<String> {
    let host = wg_address.split('/').next()?.trim();
    host.parse::<std::net::Ipv4Addr>().ok()?;
    Some(format!("http://{host}:{}", aether::API_PORT))
}

fn report(path: &Path, options: &EmitOptions, public_key: &str) {
    println!(
        "{} profil « {} » écrit dans {}",
        crate::ok(),
        options.name,
        path.display()
    );
    println!();
    if options.with_private_key {
        println!(
            "  \x1b[33mCe fichier contient la clé privée du client.\x1b[0m Le remettre par un"
        );
        println!("  canal maîtrisé, puis l'effacer du poste opérateur.");
    } else {
        println!("  \x1b[2mAucune clé privée dans ce fichier : Orion complète depuis le\x1b[0m");
        println!("  \x1b[2mprofil local de même nom, celui qui détient la clé.\x1b[0m");
    }
    println!();
    println!("  \x1b[2mClé publique admise : {public_key}\x1b[0m");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options() -> EmitOptions {
        EmitOptions {
            name: "portable".into(),
            endpoint: "vpn.example.net:51820".into(),
            public_key: None,
            with_private_key: false,
            admin: false,
            output: None,
        }
    }

    #[test]
    fn le_mode_invitation_ne_produit_aucune_cle_privee() {
        let pair = aether::wg::generate_keypair().unwrap();
        let (public_key, private_key) = resolve_keys(&EmitOptions {
            public_key: Some(pair.public_key.clone()),
            ..options()
        })
        .expect("mode invitation");
        assert_eq!(public_key, pair.public_key);
        assert!(
            private_key.is_none(),
            "le secret du client ne doit pas être fabriqué par l'opérateur"
        );
    }

    #[test]
    fn le_mode_assiste_produit_une_paire_coherente() {
        let (public_key, private_key) = resolve_keys(&EmitOptions {
            with_private_key: true,
            ..options()
        })
        .expect("mode assisté");
        let private_key = private_key.expect("clé privée générée");
        assert_eq!(
            aether::wg::public_from_private(&private_key).unwrap(),
            public_key
        );
    }

    /// Les deux modes sont exclusifs : les combiner signifierait admettre une
    /// clé et en livrer une autre, donc un profil qui ne monte jamais.
    #[test]
    fn les_deux_modes_ne_se_combinent_pas() {
        assert!(resolve_keys(&EmitOptions {
            public_key: Some(aether::wg::generate_keypair().unwrap().public_key),
            with_private_key: true,
            ..options()
        })
        .is_err());
    }

    #[test]
    fn sans_mode_explicite_l_outil_refuse_plutot_que_de_choisir() {
        let erreur = resolve_keys(&options()).unwrap_err().to_string();
        assert!(erreur.contains("--public-key"), "message : {erreur}");
        assert!(erreur.contains("--with-private-key"), "message : {erreur}");
    }

    #[test]
    fn une_cle_publique_invalide_est_refusee_avant_tout_appel() {
        assert!(resolve_keys(&EmitOptions {
            public_key: Some("pas-une-cle".into()),
            ..options()
        })
        .is_err());
    }

    #[test]
    fn l_url_de_l_api_se_derive_de_l_adresse_de_la_gateway() {
        assert_eq!(
            heliosd_url("100.64.0.1/10").as_deref(),
            Some("http://100.64.0.1:8080")
        );
        assert_eq!(heliosd_url("pas-une-adresse").as_deref(), None);
    }

    /// Le document doit être relisible par l'import Orion : c'est le seul
    /// critère qui compte, et le vérifier ici évite un aller-retour manuel.
    #[test]
    fn le_document_emis_est_relu_par_l_import_orion() {
        let cle_client = aether::wg::generate_keypair().unwrap();
        let cle_gateway = aether::wg::generate_keypair().unwrap();

        for private_key in [None, Some(cle_client.private_key.expose())] {
            let document = Document {
                format: FORMAT,
                version: VERSION,
                profile: Profile {
                    name: "portable",
                    endpoint: "vpn.example.net:51820",
                    private_key,
                    peer_public_key: &cle_gateway.public_key,
                    address: "100.64.1.2/32",
                    heliosd_url: heliosd_url("100.64.0.1/10"),
                },
            };
            let json = serde_json::to_string(&document).unwrap();
            let profil = orion_core::parse_profile_import(&json, "portable.json")
                .expect("document relu par Orion");

            assert_eq!(profil.name, "portable");
            assert_eq!(profil.peer_public_key, cle_gateway.public_key);
            assert_eq!(profil.address.as_deref(), Some("100.64.1.2/32"));
            assert_eq!(profil.private_key.is_empty(), private_key.is_none());
        }
    }
}
