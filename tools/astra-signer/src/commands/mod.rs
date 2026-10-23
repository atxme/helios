//! The gestures, one file per family, and the helpers several of them share.

use super::*;

mod ca_pq_rotation;
mod ca_tls_rotation;
mod campaign;
mod enrollment;
mod gateway_identity;
mod issuer;
mod recovery;
mod revocation;
mod vault;

pub(crate) use self::{
    ca_pq_rotation::*, ca_tls_rotation::*, campaign::*, enrollment::*, gateway_identity::*,
    issuer::*, recovery::*, revocation::*, vault::*,
};

/// A day, in seconds. Every window below is expressed in days on the command
/// line, because that is the unit an operator reasons about.
const DAY_SECS: u64 = 86_400;

/// The domain identity every signing gesture is bound to.
///
/// Every value comes from the hand-off rather than from a command line: an
/// operator who retypes a gateway key eventually signs a delegation for the
/// wrong one, and `CA-PQ` vouching for it is not something a later check
/// undoes.
/// Opens the vault at one plugged-in key, and says which slot answered.
fn open_vault(vault: &AuthorityVault, transport: Transport, prompt: &str) -> Result<Opened> {
    eprintln!("{prompt}");
    wait_for_operator()?;
    let key = authenticator::connect(transport)?;
    let pin = pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?;
    let opened = gestures::open_with_authorized_key(key.as_ref(), vault, &pin)?;
    let slot = vault.slot_for_credential(&opened.credential_id)?;
    eprintln!("Clé reconnue : « {} » ({}).", slot.label, slot.role);
    Ok(opened)
}

/// Reads the operation and its campaign, before anything is displayed.
///
/// Split out so the borrow of the client and the request it produced do not
/// have to be created in the same expression — and so the failure to fetch is
/// reported before an operator is asked to plug anything in.
/// Wraps what a ceremony produced into the one document §8.2 accepts.
///
/// Built here rather than by each gesture so the two cases stay visibly the
/// same shape: an ordinary campaign carries an approval and nothing else, an
/// anchor campaign carries the same approval plus what `CA-PQ` signed under
/// it. A second document for the second case would be a second thing to keep
/// equal on the wire.
fn campaign_result(
    approval: &aether::certificates::status::CampaignApproval,
    objects: Vec<aether::certificates::transport::TrustUpdateObject>,
    credential_registry: Option<Box<aether::certificates::approval::CredentialRegistry>>,
) -> aether::certificates::status::AstraSignerResult {
    aether::certificates::status::AstraSignerResult {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        approval: Box::new(approval.clone()),
        objects,
        credential_registry,
        issuer_authorization: None,
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path, what: &str) -> Result<T> {
    let raw = std::fs::read(path).with_context(|| format!("lecture de {}", path.display()))?;
    serde_json::from_slice(&raw).with_context(|| format!("décodage de {what} : {}", path.display()))
}

fn origin_client_fetch(
    client: &astra_operator::origin::Origin,
    operation_id: &Id16,
) -> Result<astra_operator::origin::CampaignRequest> {
    client.fetch(operation_id)
}

/// One security key, connected once and used for everything it owes.
struct ConnectedKey {
    key: Box<dyn astra_operator::authenticator::Authenticator>,
    /// Zeroized on drop, like every other PIN this program holds.
    pin: zeroize::Zeroizing<String>,
    opened: Opened,
}

fn connect_authorized_key(
    vault: &AuthorityVault,
    transport: Transport,
    prompt: &str,
) -> Result<ConnectedKey> {
    eprintln!("{prompt}");
    wait_for_operator()?;
    let key = authenticator::connect(transport)?;
    let pin = pin_for(key.as_ref(), "PIN de la clé de sécurité : ")?;
    let opened = gestures::open_with_authorized_key(key.as_ref(), vault, &pin)?;
    let slot = vault.slot_for_credential(&opened.credential_id)?;
    eprintln!("Clé reconnue : « {} » ({}).", slot.label, slot.role);
    Ok(ConnectedKey { key, pin, opened })
}

/// A Unix timestamp, as a date an operator can act on.
///
/// The raw seconds stay out of the operator-facing lines: a rotation window is
/// something someone has to diary, and «1791792171» is not a date anyone
/// compares to a calendar. The signed value remains a Unix instant; only this
/// operator-facing representation uses Europe/Paris civil time.
pub(crate) fn horodatage(seconds: u64) -> String {
    aether::display_time::format_paris_timestamp(seconds)
}

fn wait_for_operator() -> Result<()> {
    if !std::io::stdin().is_terminal() {
        bail!(
            "cette commande demande de brancher une clé de sécurité : elle ne s'exécute pas sans \
             terminal"
        );
    }
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("lecture de la confirmation")?;
    Ok(())
}

/// Asks for the PIN only when the transport needs it.
///
/// On the platform transport the operating system collects it in its own
/// dialog. Prompting here would ask an operator for a secret this process has
/// no use for — and would then have to hold it.
fn pin_for(
    key: &dyn astra_operator::authenticator::Authenticator,
    prompt: &str,
) -> Result<Zeroizing<String>> {
    if !key.needs_pin() {
        eprintln!("Le système va demander le PIN et le contact de la clé.");
        return Ok(Zeroizing::new(String::new()));
    }
    ask_pin(prompt)
}

/// Reads the PIN without echoing it.
///
/// The prompt is printed by us rather than by `rpassword::prompt_password`:
/// that one writes straight to the terminal device, bypassing the stream every
/// other message goes through — and on a Windows console in a non-UTF-8 code
/// page it comes out as mojibake, on the one line an operator has to read
/// carefully.
fn ask_pin(prompt: &str) -> Result<Zeroizing<String>> {
    eprint!("{prompt}");
    std::io::stderr().flush().ok();
    let pin = rpassword::read_password().context("lecture du PIN")?;
    if pin.is_empty() {
        bail!("PIN vide : la vérification utilisateur est exigée");
    }
    Ok(Zeroizing::new(pin))
}

fn random_id() -> Result<[u8; 16]> {
    let mut out = [0u8; 16];
    aether::random::fill_secret(&mut out)
        .map_err(|error| anyhow::anyhow!("générateur approuvé indisponible: {error}"))?;
    Ok(out)
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}
