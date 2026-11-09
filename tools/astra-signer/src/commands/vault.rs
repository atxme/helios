//! The vault and its keys: init, enrol, verify, list, remove, devices,
//! rename, the domain, and the bindings re-emitted from the slot table.

use super::*;

pub(crate) fn init(
    path: &Path,
    rp_id: &str,
    trust_domain_id: Option<&str>,
    label: &str,
    role: SlotRole,
    transport: Transport,
) -> Result<()> {
    if path.exists() {
        bail!(
            "un coffre existe déjà à {} : `enrol` ajoute une clé, `init` en créerait un second \
             dont les ancres n'ont rien à voir",
            path.display()
        );
    }
    let trust_domain_id = match trust_domain_id {
        Some(value) => TrustDomainId::parse_hex(value)
            .context("lecture de l'identifiant de domaine de confiance")?,
        None => TrustDomainId::new(random_id()?).context("tirage du domaine de confiance")?,
    };

    eprintln!("Brancher la clé de sécurité à enregistrer, puis appuyer sur Entrée.");
    wait_for_operator()?;
    let key = authenticator::connect(transport)?;
    let pin = pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?;

    let created = gestures::create_authority(
        key.as_ref(),
        &NewAuthority {
            rp_id: rp_id.to_string(),
            trust_domain_id,
            label: label.to_string(),
            role,
        },
        &pin,
        now_unix(),
    )?;
    store::save_new(path, &created.vault)?;
    // Written straight away: the three values below are what two other
    // programs need, and retyping a base64 anchor is where a deployment goes
    // wrong — silently, with the failure surfacing much later.
    let handoff_path = handoff::path_beside(path);
    handoff::save(&handoff_path, &handoff::DomainHandoff::of(&created.vault)?)?;

    println!("coffre            : {}", path.display());
    println!("relais            : {}", handoff_path.display());
    println!("domaine           : {}", created.vault.trust_domain_id);
    println!("empreinte coffre  : {}", created.vault.fingerprint()?);
    println!(
        "CA-PQ (publique)  : {}",
        created.ca_pq_public_key.to_base64()
    );
    println!(
        "CA-PQ empreinte   : {}",
        created.ca_pq_public_key.authority_fingerprint()
    );
    println!();
    println!(
        "`./scripts/deploy.sh` lit le relais et amorce Astra et la gateway sans qu'aucune de ces \
         valeurs soit recopiée à la main"
    );
    report_bootstrap_state(&created.vault);
    Ok(())
}

pub(crate) fn enrol(path: &Path, label: &str, role: SlotRole, transport: Transport) -> Result<()> {
    // A rotation applies the vault it signed over this one: a key slot changed
    // meanwhile would be undone, and a removed key would get its access back.
    astra_operator::rotation_journal::ensure_vault_not_awaiting_overwrite(path)?;
    let mut vault = store::load(path)?;
    if vault.slots.len() >= MAX_SLOTS {
        bail!("le coffre est plafonné à {MAX_SLOTS} key-slots : en retirer un d'abord");
    }

    // The authorized key first. Registering before we knew we could open the
    // vault would leave an orphan credential on a fresh token, and an operator
    // with no way to tell which one it was.
    eprintln!("Brancher une clé DÉJÀ enregistrée, puis appuyer sur Entrée.");
    wait_for_operator()?;
    let opening = {
        let key = authenticator::connect(transport)?;
        let pin = pin_for(key.as_ref(), "PIN de la clé déjà enregistrée : ")?;
        let opened = gestures::open_with_authorized_key(key.as_ref(), &vault, &pin)?;
        let slot = vault.slot_for_credential(&opened.credential_id)?;
        eprintln!("Clé reconnue : « {} » ({}).", slot.label, slot.role);
        opened
    };

    eprintln!();
    eprintln!("Débrancher cette clé, brancher la NOUVELLE, puis appuyer sur Entrée.");
    wait_for_operator()?;
    let key = authenticator::connect(transport)?;
    let pin = pin_for(key.as_ref(), "PIN de la nouvelle clé : ")?;
    let slot_id = gestures::add_key(
        key.as_ref(),
        &mut vault,
        &opening,
        &NewKey {
            label: label.to_string(),
            role,
        },
        &pin,
        now_unix(),
    )?;
    store::save(path, &vault)?;
    // The credential document is rebuilt from the table that just moved, in
    // the same operation (spec §2.4). The key still plugged in is the new one,
    // and it is now a slot of this vault — so it can sign the document that
    // describes it.
    let opening = gestures::open_with_authorized_key(key.as_ref(), &vault, &pin)?;
    resign_bindings(path, &vault, &opening)?;

    println!("key-slot         : {}", hex::encode(slot_id));
    println!("libellé          : {label}");
    println!("empreinte coffre : {}", vault.fingerprint()?);
    report_bootstrap_state(&vault);
    Ok(())
}

pub(crate) fn verify(path: &Path, transport: Transport) -> Result<()> {
    let vault = store::load(path)?;

    eprintln!("Brancher la clé de sécurité à éprouver, puis appuyer sur Entrée.");
    wait_for_operator()?;
    let key = authenticator::connect(transport)?;
    let pin = pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?;
    let opened = gestures::open_with_authorized_key(key.as_ref(), &vault, &pin)?;
    let slot = vault.slot_for_credential(&opened.credential_id)?.clone();
    gestures::prove_anchors_open(&vault, &opened)?;

    println!("key-slot         : {}", hex::encode(slot.slot_id));
    println!("libellé          : {}", slot.label);
    println!("rôle             : {}", slot.role);
    println!("ancres           : ouvertes");
    println!("empreinte coffre : {}", vault.fingerprint()?);
    report_bootstrap_state(&vault);
    Ok(())
}

pub(crate) fn list(path: &Path) -> Result<()> {
    let vault = store::load(path)?;
    println!("coffre           : {}", path.display());
    println!("domaine          : {}", vault.trust_domain_id);
    println!("RP ID WebAuthn   : {}", vault.rp_id);
    println!("empreinte coffre : {}", vault.fingerprint()?);
    println!("key-slots        : {}/{}", vault.slots.len(), MAX_SLOTS);
    for slot in &vault.slots {
        println!(
            "  {} — {} — {} — enregistrée le {}",
            hex::encode(slot.slot_id),
            slot.label,
            slot.role,
            slot.enrolled_at
        );
    }
    report_bootstrap_state(&vault);
    Ok(())
}

pub(crate) fn remove(path: &Path, slot: &str, transport: Transport) -> Result<()> {
    // A rotation applies the vault it signed over this one: a key slot changed
    // meanwhile would be undone, and a removed key would get its access back.
    astra_operator::rotation_journal::ensure_vault_not_awaiting_overwrite(path)?;
    let mut vault = store::load(path)?;
    let removed = parse_slot_id(slot)?;
    let target: KeySlot = vault.slot(&removed)?.clone();

    eprintln!(
        "Retrait de « {} » ({}). Brancher une clé autorisée, puis appuyer sur Entrée.",
        target.label, target.role
    );
    wait_for_operator()?;
    let key = authenticator::connect(transport)?;
    let pin = pin_for(key.as_ref(), "PIN de la clé autorisée : ")?;
    let opened = gestures::open_with_authorized_key(key.as_ref(), &vault, &pin)?;

    gestures::remove_key(&mut vault, &opened, &removed)?;
    // Re-signed here, and this is where the withdrawn credential gets its
    // `revoked` row: «absent du document» n'est pas une décision qu'un
    // consommateur peut appliquer, un état signé l'est. Publish that terminal
    // decision first: a crash may then refuse a credential still present in
    // the old vault (fail closed), but can never leave an absent slot marked
    // active — ordinary approval does not open the vault and could otherwise
    // continue using the removed token.
    let opened = gestures::open_with_authorized_key(key.as_ref(), &vault, &pin)?;
    resign_bindings(path, &vault, &opened)?;
    store::save(path, &vault)?;

    println!("key-slot retiré  : {}", hex::encode(removed));
    println!("empreinte coffre : {}", vault.fingerprint()?);
    println!(
        "le corps a été rescellé : ce key-slot recollé depuis une sauvegarde n'ouvre plus ce \
         fichier. Une sauvegarde antérieure, elle, reste ouvrable par cette clé — si elle est \
         compromise, la réponse est une rotation de CA-PQ"
    );
    report_bootstrap_state(&vault);
    Ok(())
}

pub(crate) fn devices() -> Result<()> {
    let visible = authenticator::visible_devices();
    if visible.is_empty() {
        println!("aucun périphérique HID visible.");
        println!("ni clé, ni clavier, ni souris : c'est la pile HID du système qui ne répond pas.");
        return Ok(());
    }
    for device in &visible {
        println!(
            "{} {:04x}:{:04x} {}",
            match (device.fido, device.known_vendor) {
                (true, _) => "FIDO2 ",
                // Its vendor makes security keys, but no FIDO interface is
                // readable on it — the interesting line of the whole listing.
                (false, true) => "clé ? ",
                (false, false) => "      ",
            },
            device.vendor_id,
            device.product_id,
            device.product
        );
        println!("        {}", device.detail.trim());
    }
    let fido = visible.iter().filter(|device| device.fido).count();
    println!();
    println!("{} périphérique(s) HID, dont {fido} FIDO2.", visible.len());
    if fido == 0 {
        let suspects = visible.iter().filter(|device| device.known_vendor).count();
        println!();
        if suspects > 0 {
            println!(
                "{suspects} périphérique(s) marqués « clé ? » viennent d'un fabricant de clés de \
                 sécurité : la clé est branchée et vue par le système, seule son interface FIDO \
                 ne s'ouvre pas."
            );
        }
        println!(
            "Aucun n'expose l'usage page 0xF1D0. Ce n'est pas une question de modèle : rien ici \
             ne filtre sur le vendor ou le product."
        );
        if cfg!(windows) {
            println!(
                "Sous Windows, ouvrir un HID FIDO est réservé aux processus élevés depuis \
                 Windows 10 1903 — relancer dans une console administrateur. Si elle l'est déjà, \
                 vérifier `ykman config usb --list` : FIDO2 désactivé, l'interface n'existe pas."
            );
        } else {
            println!(
                "Sous Linux, il manque en général une règle udev donnant l'accès à l'utilisateur \
                 courant, ou l'application FIDO2 de la clé est désactivée."
            );
        }
    }
    Ok(())
}

pub(crate) fn domain(
    path: &Path,
    gateway_wg_public_key: Option<&str>,
    server_name: Option<&str>,
    astra_service_public_key: Option<&str>,
    astra_service_key_epoch: Option<u64>,
    astra_authority_url: Option<&str>,
) -> Result<()> {
    let vault = store::load(path)?;
    let handoff_path = handoff::path_beside(path);
    // Read first, then refreshed from the vault: rewriting from the vault
    // alone would drop the gateway and the pinned service key, and the next
    // signing command would ask an operator to retype them.
    let mut handoff = handoff::DomainHandoff::beside(path, &vault)?;

    // Parsed before anything is written. A gateway key that is not a key, or a
    // service key that is not an ML-DSA-87 key, is a value every later command
    // would carry into a signed object.
    if let Some(value) = gateway_wg_public_key {
        WireGuardKey::parse(value).context("clé publique WireGuard de la gateway")?;
        handoff.gateway_wg_public_key = Some(value.trim().to_string());
    }
    if let Some(value) = server_name {
        validate_server_name(value.trim()).context("nom de service de la gateway")?;
        handoff.server_name = Some(value.trim().to_string());
    }
    if let Some(value) = astra_service_public_key {
        MlDsa87PublicKey::parse(value.trim()).context("clé publique de service d'Astra")?;
        handoff.astra_service_public_key = Some(value.trim().to_string());
    }
    if let Some(epoch) = astra_service_key_epoch {
        if epoch == 0 {
            bail!("l'époque de la clé de service Astra doit être non nulle");
        }
        handoff.astra_service_key_epoch = Some(epoch);
    }
    if let Some(value) = astra_authority_url {
        let value = value.trim();
        if !value.starts_with("https://") {
            bail!("l'origine de l'autorité doit être une URL https:// : {value}");
        }
        handoff.astra_authority_url = Some(value.trim_end_matches('/').to_string());
    }
    handoff::save(&handoff_path, &handoff)?;

    println!("relais           : {}", handoff_path.display());
    println!("domaine          : {}", handoff.trust_domain_id);
    println!("RP ID WebAuthn   : {}", handoff.rp_id);
    println!("CA-PQ (publique) : {}", handoff.ca_pq_public_key);
    println!("empreinte coffre : {}", handoff.vault_fingerprint);
    println!("époque CA-PQ     : {}", handoff.ca_epoch.unwrap_or(1));
    println!("époque CA-TLS    : {}", handoff.ca_tls_epoch.unwrap_or(1));
    println!(
        "gateway          : {}",
        handoff.gateway_wg_public_key.as_deref().unwrap_or("—")
    );
    println!(
        "nom de service   : {}",
        handoff.server_name.as_deref().unwrap_or("—")
    );
    println!(
        "origine autorité : {}",
        handoff.astra_authority_url.as_deref().unwrap_or("—")
    );
    println!(
        "clé Astra        : {}",
        match &handoff.astra_service_public_key {
            Some(key) => format!(
                "époque {} — {}",
                handoff.astra_service_key_epoch.unwrap_or(1),
                short_key(key)
            ),
            None => "—".into(),
        }
    );
    println!(
        "CA-TLS           : {}",
        match &handoff.ca_tls_certificate {
            Some(_) => "auto-signée",
            None => "— (`astra-signer issue-ca-tls`)",
        }
    );
    Ok(())
}

/// Re-emits the credential document from the key-slot table.
///
/// Called by every gesture that moves that table, in the same operation
/// (spec §2.4): a document describing a slot the vault no longer holds is a
/// signed lie, and nothing downstream can catch it.
///
/// A domain whose gateway is not recorded yet has no document to emit — the
/// bindings name the gateway — so this says so and changes nothing, rather
/// than emitting one bound to a guess.
fn resign_bindings(path: &Path, vault: &AuthorityVault, opening: &Opened) -> Result<()> {
    let handoff = handoff::DomainHandoff::beside(path, vault)?;
    let identity = match handoff::identity_of(&handoff) {
        Ok(identity) => identity,
        Err(_) => {
            println!(
                "credentials      : non émis — le relais ne porte pas encore la gateway. Après \
                 `astra-signer domain --gateway-wg-public-key … --server-name …`, lancer \
                 `astra-signer bindings`"
            );
            return Ok(());
        }
    };
    let registry_path = credentials::path_beside(path);
    let previous = credentials::load(&registry_path)?;
    let registry = signing::sign_credential_bindings(
        vault,
        opening,
        &identity,
        previous.as_ref(),
        &[],
        now_unix(),
    )?;
    credentials::save(&registry_path, &registry)?;
    println!(
        "credentials      : {} — époque {}",
        registry_path.display(),
        registry.credential_registry_epoch
    );
    Ok(())
}

pub(crate) fn bindings(
    path: &Path,
    lost: &[String],
    active: &[String],
    transport: Transport,
) -> Result<()> {
    // A rotation applies the vault it signed over this one: a key slot changed
    // meanwhile would be undone, and a removed key would get its access back.
    astra_operator::rotation_journal::ensure_vault_not_awaiting_overwrite(path)?;
    let vault = store::load(path)?;
    let handoff = handoff::DomainHandoff::beside(path, &vault)?;
    let identity = handoff::identity_of(&handoff)?;

    // Slot identifiers rather than credential identifiers: `list` prints the
    // first, and a credential a decision is about is one the vault still
    // holds. Withdrawing a key already revokes it, and that is terminal.
    let mut overrides = Vec::new();
    for (slots, state) in [
        (lost, CredentialState::Lost),
        (active, CredentialState::Active),
    ] {
        for slot in slots {
            let slot_id = parse_slot_id(slot)?;
            overrides.push((vault.slot(&slot_id)?.credential_id()?, state));
        }
    }

    let registry_path = credentials::path_beside(path);
    let previous = credentials::load(&registry_path)?;
    let opening = open_vault(
        &vault,
        transport,
        "Signature du document de credentials. Brancher une clé autorisée, puis Entrée.",
    )?;
    let registry = signing::sign_credential_bindings(
        &vault,
        &opening,
        &identity,
        previous.as_ref(),
        &overrides,
        now_unix(),
    )?;
    credentials::save(&registry_path, &registry)?;

    println!("credentials      : {}", registry_path.display());
    println!("époque registre  : {}", registry.credential_registry_epoch);
    for line in credentials::summarize(&registry) {
        println!("{line}");
    }
    Ok(())
}

/// The first characters of a base64 key — enough to tell two apart on a
/// terminal, never enough to be mistaken for the whole.
fn short_key(value: &str) -> String {
    value.chars().take(24).collect::<String>() + "…"
}

pub(crate) fn rename(path: &Path, slot: &str, label: &str) -> Result<()> {
    astra_operator::rotation_journal::ensure_vault_not_awaiting_overwrite(path)?;
    let mut vault = store::load(path)?;
    let slot_id = parse_slot_id(slot)?;
    vault.rename_slot(&slot_id, label)?;
    store::save(path, &vault)?;
    println!("key-slot         : {}", hex::encode(slot_id));
    println!("libellé          : {label}");
    Ok(())
}

/// Says, after every command that could change it, whether the authority may
/// be used at all — and what is missing when it may not.
fn report_bootstrap_state(vault: &AuthorityVault) {
    if vault.is_bootstrapped() {
        println!("autorité         : {} clés enregistrées", vault.slots.len());
        return;
    }
    println!(
        "autorité         : NON amorcée — {} clé(s) sur les {REQUIRED_SLOTS} exigées",
        vault.slots.len()
    );
    println!(
        "tant que la seconde clé n'est pas enrôlée (`astra-signer enrol`), perdre celle-ci perd \
         le domaine de confiance : aucune phrase de passe ne la remplace"
    );
}

fn parse_slot_id(value: &str) -> Result<[u8; 16]> {
    let bytes = hex::decode(value.trim())
        .with_context(|| format!("« {value} » n'est pas un identifiant de key-slot"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("un identifiant de key-slot fait 32 caractères hexadécimaux"))
}
