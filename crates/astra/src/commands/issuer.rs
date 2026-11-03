//! The delegated issuer: prepare it here, have it signed there, install it.
//!
//! Two commands and not one, because the signature happens on another machine
//! at a security key: the private halves are born in the service and never
//! travel, and what crosses is a public request one way and a `CA-PQ`-signed
//! authorization the other.

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::Path;

use anyhow::{Context, Result};
use astra::door::local::MAX_DOOR_BODY_BYTES;
use astra::door::{DoorOutcome, DoorRequest, Opening};

use crate::{console, now_unix};

/// Has the service draw the next delegation's keys, and prints its request.
///
/// Nothing is installed and nothing is announced. Until an authorization
/// comes back, the two key files are a pair no signed object names — which
/// is exactly the state an interrupted ceremony should leave behind.
pub(crate) fn issuer_request(
    state_dir: &Path,
    out: Option<&Path>,
    campaign: Option<(&str, &str)>,
    window_secs: u64,
) -> Result<()> {
    let request = match campaign {
        Some((reason, requested_by)) => DoorRequest::IssuerDelegation {
            text: console::opening_text(reason, requested_by, window_secs),
        },
        None => DoorRequest::IssuerRequest {},
    };
    let out = out.map(RequestOut::open).transpose()?;
    match console::open(state_dir, request)? {
        DoorOutcome::IssuerRequested { request, opened } => {
            print_issuer_request(out, &request, opened.as_ref())
        }
        other => Err(console::unexpected(&other)),
    }
}

/// The `--out` file of a delegation request, opened before the door is
/// called.
///
/// The service opens the delegation campaign before it answers. A path found
/// unwritable only once the answer is back would leave that campaign live,
/// blocking its family until its window closes, for a request nobody holds.
/// Opened first, an unwritable path is refused while nothing is open. The
/// file is written only from the answer, and one this command created is
/// removed again if no request comes to fill it.
pub(super) struct RequestOut<'a> {
    path: &'a Path,
    file: File,
    /// Created by this command, and not yet holding a request.
    created: bool,
}

impl<'a> RequestOut<'a> {
    /// Opens `path` for writing without changing it: created empty when it
    /// does not exist, left as it is when it does.
    pub(super) fn open(path: &'a Path) -> Result<Self> {
        let writing = || format!("writing {}", path.display());
        let (file, created) = match OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(file) => (file, true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (
                OpenOptions::new()
                    .write(true)
                    .open(path)
                    .with_context(writing)?,
                false,
            ),
            Err(error) => return Err(error).with_context(writing),
        };
        Ok(Self {
            path,
            file,
            created,
        })
    }

    /// Replaces the file's content with the request.
    fn write(mut self, request: &str) -> Result<()> {
        self.file
            .set_len(0)
            .and_then(|()| self.file.write_all(request.as_bytes()))
            .with_context(|| format!("writing {}", self.path.display()))?;
        self.created = false;
        Ok(())
    }
}

impl Drop for RequestOut<'_> {
    fn drop(&mut self) {
        if self.created {
            // Best effort: the command is already failing with the reason
            // that matters, and an empty file is all this would leave.
            let _ = std::fs::remove_file(self.path);
        }
    }
}

/// What an issuer request prints, alone or as the first step of the chain.
///
/// The `--out` file is written here, from the answer: the service never
/// writes to a path the caller names.
pub(super) fn print_issuer_request(
    out: Option<RequestOut<'_>>,
    request: &str,
    opened: Option<&Opening>,
) -> Result<()> {
    let parsed: astra::issuer::IssuerDelegationRequest =
        serde_json::from_str(request).context("reading the delegation request")?;
    if let Some(out) = out {
        let path = out.path;
        out.write(request)?;
        eprintln!("delegation request : {}", path.display());
    }
    eprintln!("issuer epoch       : {}", parsed.issuer_epoch);
    match opened {
        Some(opening) => {
            // Standard error, unlike `campaign open`: on this command standard
            // output already belongs to the delegation request, which a
            // deployment script pipes out of the container. Two things there
            // would give the script neither.
            eprintln!(
                "operation         : {}",
                opening.opened.operation_id.to_hex()
            );
            eprintln!(
                "empreinte de campagne : {}",
                opening.opened.campaign_fingerprint
            );
            eprintln!(
                "sign it from the operator machine:\n  astra-signer authorize-issuer \\\n    \
                 --authority-url {} \\\n    --operation-id {}",
                opening.authority_url,
                opening.opened.operation_id.to_hex()
            );
            eprintln!(
                "the delegation is recorded here as soon as the companion deposits it; restart \
                 Astra to issue under it"
            );
        }
        None => {
            eprintln!(
            "hors campagne      : `astra-signer authorize-issuer --request <file> --out <file>`, \
             puis `astra issuer install`. Rien ne rattache alors cette demande à cette autorité : \
             l'opérateur signe le fichier qu'on lui présente. Passer --reason et --requested-by \
             pour la cérémonie du §8.2."
            );
        }
    }
    // On standard output, alone, so a deployment script can pipe it out of the
    // container without a shared volume.
    println!("{request}");
    Ok(())
}

/// Installs a signed delegation, after checking it three ways.
///
/// The anchor the registry pins, the policy it computed at bootstrap, and the
/// private keys already on disk. The three come from three different places on
/// purpose: a file that satisfies all of them is one this authority can
/// actually issue with, and the alternative is announcing a delegation whose
/// first use fails at 80 % of a client's leaf.
pub(crate) fn issuer_install(state_dir: &Path, authorization: Option<&Path>) -> Result<()> {
    let encoded = read_authorization(authorization)?;
    let authorization: aether::certificates::authority::AstraIssuerAuthorization =
        serde_json::from_slice(&encoded).context("reading the issuer authorization")?;

    let outcome = console::write(
        state_dir,
        DoorRequest::IssuerInstall {
            authorization: Box::new(authorization.clone()),
        },
        |registry| {
            let installed =
                astra::door::write::issuer_install(registry, state_dir, authorization, now_unix())?;
            Ok(installed.into())
        },
    )?;
    let DoorOutcome::IssuerInstalled {
        issuer_epoch,
        not_after,
        audit_head,
    } = outcome
    else {
        return Err(console::unexpected(&outcome));
    };

    println!("issuer epoch     : {issuer_epoch}");
    println!("delegation until : {not_after}");
    println!("audit head       : {audit_head}");
    println!(
        "restart Astra to load it: the delegation is read at start-up, beside the private keys \
         it names"
    );
    Ok(())
}

/// The signed authorization, from its file or from standard input, bounded
/// by what the door accepts.
fn read_authorization(path: Option<&Path>) -> Result<Vec<u8>> {
    let limit = u64::try_from(MAX_DOOR_BODY_BYTES)
        .context("door bound")?
        .saturating_add(1);
    let mut buffer = Vec::new();
    match path {
        Some(path) => std::fs::File::open(path)
            .and_then(|file| file.take(limit).read_to_end(&mut buffer))
            .with_context(|| format!("reading {}", path.display()))?,
        None => std::io::stdin()
            .take(limit)
            .read_to_end(&mut buffer)
            .context("reading the authorization from standard input")?,
    };
    anyhow::ensure!(
        buffer.len() <= MAX_DOOR_BODY_BYTES,
        "cette délégation dépasse {MAX_DOOR_BODY_BYTES} octets : ce n'est pas une délégation, et \
         rien n'a été enregistré"
    );
    Ok(buffer)
}
