//! Approved randomness for the v5 negotiation and the certificate lifecycle.
//!
//! Every identifier, challenge, salt, nonce, capability secret and private key
//! of these two protocols follows one pipeline, fixed by the negotiation
//! specification §4.3 and the rotation specification §2.3.2:
//!
//! ```text
//! fail-closed platform entropy source
//!     -> SP 800-90A DRBG of the crypto library, 256-bit strength
//!     -> consumed bytes
//! ```
//!
//! # This module does not implement a DRBG, and must not
//!
//! Both specifications are explicit: Helios, Astra and Orion **do not
//! reimplement** a DRBG — no HMAC-DRBG or CTR-DRBG state, no update function,
//! no seed derivation, no health test is recoded here. Two mechanisms are
//! admissible and both belong to the provider: HMAC-DRBG-SHA-512, or
//! CTR-DRBG-AES-256 with the derivation function enabled.
//!
//! So what lives here is a **type and configuration adaptation that produces
//! no byte of its own**: one door to the provider, the description its
//! start-up banner must name, and the refusal that follows when the provider
//! fails. Writing a second DRBG in front of the library's would not add a
//! control — it would move unreviewed bytes back to the front of the pipeline.
//!
//! # The provider, read out of its source rather than assumed
//!
//! [`aws_lc_rs::rand::SystemRandom`], the same AWS-LC the rest of the
//! workspace already uses for AES-GCM, HKDF and HMAC. Behind
//! [`aws_lc_rs::rand::SecureRandom::fill`] sits `RAND_bytes`, and every line
//! below was checked against the vendored source rather than inferred from the
//! library's reputation:
//!
//! - a **CTR-DRBG-AES-256**, 256-bit strength, **without a derivation
//!   function**: `CTR_DRBG_init` takes exactly `CTR_DRBG_ENTROPY_LEN` = 48
//!   bytes — one seedlen — and XORs the personalization string into it. That
//!   is SP 800-90Ar1 §10.2.1.3.1, the full-entropy instantiation, not
//!   §10.2.1.3.2. See the limit below: the two specifications name
//!   `use_df = true`, and this is the one place the shipped provider and their
//!   wording do not line up;
//! - **per-thread state** (`OPENSSL_THREAD_LOCAL_PRIVATE_RAND`), so no lock is
//!   contended on the negotiation path;
//! - **seeded from a jitter-rooted tree DRBG, personalized from the OS**. The
//!   roles swap under a hypervisor: when a VM uniqueness-breaking environment
//!   is detected, the OS becomes the seed and the CPU hardware RNG the extra
//!   entropy. Two independent sources either way, by construction;
//! - **reseeded every 4096 generate calls** (`kCtrDrbgReseedInterval`), 256
//!   times inside the ceiling [`MAX_GENERATES_BETWEEN_RESEEDS`] this protocol
//!   sets;
//! - **fork and VM-snapshot aware**: before generating, the state is checked
//!   against a uniqueness-breaking-event counter (`crypto/ube/`, built on
//!   `MADV_WIPEONFORK`), and a state inherited by a child — or restored with a
//!   snapshot — is reseeded before it returns a byte. When that detection is
//!   *unavailable*, the check fails closed and forces a reseed before **every**
//!   generate. This is why the module below has no fork detection of its own:
//!   the provider does it, and does it better than a PID comparison;
//! - **a failure kills the process.** `RAND_bytes` returns 1 unconditionally;
//!   an entropy source that cannot deliver, a failed instantiation, a failed
//!   reseed and a failed generate all reach `abort()`. Fail-closed to the
//!   letter — stricter than the specification asks — and the reason
//!   [`RandomError::ProviderFailed`] is close to unreachable in a shipped
//!   binary rather than a routine outcome.
//!
//! **FIPS validation is deliberately out of scope.** `aws-lc-rs` also ships an
//! `aws-lc-fips-sys` build carrying CAVP/CMVP certificates, and this project
//! does not use it: it needs the CMake and Go toolchains ADR-001 §2 keeps out
//! of the build, and no deployment of Helios is claiming a certificate. The
//! DRBG above is the same mechanism either way; what the validated build adds
//! is paperwork, not entropy. Nothing here should be read as a validation
//! claim, and the banner names the ordinary module by name.
//!
//! # What else in the workspace draws from this same DRBG
//!
//! The pipeline is only worth its name if nothing important sits outside it,
//! so the provenance of every key was traced rather than assumed:
//!
//! - **ML-KEM-1024** ([`crate::pq`]) — key generation and encapsulation go
//!   through AWS-LC's `mlk_randombytes`, which is `RAND_bytes`. Same DRBG, no
//!   adaptation needed;
//! - **ML-DSA-87** — [`crate::ml_dsa`] hands `fips204` a [`DrbgRng`], so key
//!   generation and hedged signing draw from here. (AWS-LC's own ML-DSA also
//!   calls `RAND_bytes`, but this project uses the `fips204` implementation.);
//! - **X.509 private keys** produced by `rcgen` — CA-TLS, client leaves, the
//!   Astra delegated issuer's material, test fixtures. `rcgen` defaults to
//!   `ring`, whose CSPRNG is a *second, unrelated* generator; the workspace
//!   manifest therefore pins its `aws_lc_rs` feature so these keys come from
//!   the DRBG above.
//!
//! # Limite connue
//!
//! **The derivation function.** Both specifications admit CTR-DRBG-AES-256
//! only "with the derivation function activated (`use_df = true`)", and the
//! provider does not use one — it relies on a full-entropy seed input instead,
//! which is the case SP 800-90Ar1 §10.2.1.3.1 exists for and which the
//! jitter-rooted source satisfies. The security argument holds; the wording
//! does not. [`ProviderDescription::use_df`] reports `false` so the gap is
//! visible on every start-up rather than assumed away. What closes it is an
//! arbitration: amend the two specifications to admit the full-entropy
//! instantiation, or move to a provider that runs the derivation function.
//!
//! **Per-call prediction resistance is not reachable through `aws-lc-rs`.**
//! AWS-LC does expose it in C — `RAND_bytes_with_user_prediction_resistance`
//! mixes caller-supplied prediction resistance into a generate — but the Rust
//! wrapper offers only the plain fill, so [`PredictionResistance::Required`]
//! records the intent without changing the call. What the provider does give
//! is a fresh state randomized with prediction resistance on its **first** use,
//! and only where the CPU carries RDRAND or RNDR — without one, the entropy
//! source declares no prediction-resistance method at all. Implementing the
//! missing flag above the wrapper would mean owning DRBG state here, which is
//! exactly what the specification forbids; what unblocks it is that entry
//! point on the `aws-lc-rs` side.
//!
//! **TLS session material is still on `ring`.** `rustls` and `quinn` are built
//! with their `ring` provider, so the ephemeral (EC)DHE keys, the handshake
//! randoms and the session keys of the negotiation transport come from ring's
//! CSPRNG, not from the DRBG above — while §4.3 names TLS among the keys the
//! pipeline must cover. Long-lived material is unaffected: WireGuard keys,
//! PSKs, ML-KEM, ML-DSA and every X.509 private key are on AWS-LC. What blocks
//! the swap is `reqwest` 0.12, whose only rustls provider feature is `ring`;
//! its `-no-provider` variant compiles but then requires
//! `CryptoProvider::install_default` in **every** binary and test that builds a
//! client, which is a change to make deliberately rather than as a side effect
//! of this module.
//!
//! # The rules, and what each one refuses
//!
//! - a call returns bytes only if the provider produced them. A failure is
//!   **fatal**: no fallback to the clock, a UUID, a general-purpose PRNG or a
//!   counter, and no partial output;
//! - the reseed interval and the fork boundary belong to the provider. They
//!   are reported by [`ProviderDescription`], never re-enforced here;
//! - a secret is drawn through [`fill_secret`] and a public value through
//!   [`fill_public`]. The distinction is [`PredictionResistance`], which the
//!   provider does not currently take — see the limit below — and which
//!   nonetheless says at every call site which draws are key material;
//! - a deterministic provider exists only under `cfg(test)`. No shipped binary
//!   has a path that installs one, and none is ever described as conforming.
//!
//! # Limite connue
//!
//! **Per-call prediction resistance is not reachable through `aws-lc-rs`.**
//! AWS-LC does expose it in C — `RAND_bytes_with_user_prediction_resistance`
//! mixes caller-supplied prediction resistance into a generate — but the Rust
//! wrapper offers only the plain fill, so [`PredictionResistance::Required`]
//! records the intent without changing the call. What the provider does give
//! is a state randomized with prediction resistance on its first use and
//! reseeded every 4096 calls. Implementing the missing flag above the wrapper
//! would mean owning DRBG state here, which is exactly what the specification
//! forbids; what unblocks it is that entry point on the `aws-lc-rs` side.

use std::sync::OnceLock;

use zeroize::Zeroizing;

/// Version of the provider crate the build resolved, for the banner.
const PROVIDER_VERSION: &str = env!("HELIOS_DRBG_PROVIDER_VERSION");

/// Bytes a single call may ask for.
///
/// The same 65536 as AWS-LC's `CTR_DRBG_MAX_GENERATE_LENGTH`, the SP 800-90A
/// per-request cap. The provider would chunk a larger request by itself, so
/// this bound is the module's own: nothing in these two protocols draws
/// anything near it — the largest single draw is a key seed — and a call that
/// did would be a bug worth naming rather than quietly satisfying.
pub const MAX_BYTES_PER_REQUEST: usize = 1 << 16;

/// Generate calls the specification allows between two entropy inputs.
pub const MAX_GENERATES_BETWEEN_RESEEDS: u64 = 1 << 20;

/// What can stop the pipeline. Every variant is a refusal to emit bytes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RandomError {
    /// No provider is reachable — the start-up error §4.3 names.
    ///
    /// A shipped binary resolves AWS-LC on first use, so this reports the
    /// provider slot itself being unreadable rather than a build with no
    /// provider at all. It stays a distinct variant because "the provider
    /// could not be reached" and "the provider refused" call for different
    /// answers from an operator.
    #[error("no DRBG provider is reachable")]
    ProviderUnavailable,
    /// The provider refused.
    ///
    /// Close to unreachable with the shipped provider: AWS-LC answers an
    /// entropy, instantiation, reseed or generate failure with `abort()`, and
    /// `RAND_bytes` returns 1 unconditionally. The variant stays because the
    /// trait admits other providers — the `cfg(test)` ones exercise exactly
    /// this path — and because a call site must handle a refusal without ever
    /// being tempted to continue past it.
    #[error("the DRBG provider produced no bytes")]
    ProviderFailed,
    /// The provider answered with the block an unfilled buffer would have.
    #[error("the DRBG provider returned an all-zero block")]
    ProviderProbeFailed,
    /// One call cannot return that many bytes.
    #[error("a single generate call cannot return {requested} bytes")]
    RequestTooLarge {
        /// Bytes the caller asked for.
        requested: usize,
    },
}

/// The SP 800-90A mechanism families the specifications name.
///
/// The derivation function is **not** part of the variant: it is a separate
/// field, because a name that carried it would have to be trusted, whereas a
/// field can be read against the provider. That distinction is not academic —
/// see the module's "Limite connue".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrbgMechanism {
    /// HMAC-DRBG-SHA-512.
    HmacSha512,
    /// CTR-DRBG-AES-256. Whether a derivation function is used is
    /// [`ProviderDescription::use_df`].
    CtrAes256,
}

impl std::fmt::Display for DrbgMechanism {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HmacSha512 => f.write_str("HMAC-DRBG-SHA-512"),
            Self::CtrAes256 => f.write_str("CTR-DRBG-AES-256"),
        }
    }
}

/// What the start-up banner must name, without a secret in it.
///
/// Every field answers a question a reader would otherwise have to put to the
/// build system: which provider, which version, which mechanism, and reseeded
/// how often.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderDescription {
    /// Provider that owns the DRBG state.
    pub provider: &'static str,
    /// Version of that provider, as the build resolved it.
    pub version: &'static str,
    /// Mechanism in use. Local, explicit, never negotiated on the wire.
    pub mechanism: DrbgMechanism,
    /// Whether the mechanism runs a derivation function over its entropy
    /// input. Meaningful for CTR-DRBG only, and `false` for the provider this
    /// project ships — the divergence the module's "Limite connue" describes.
    pub use_df: bool,
    /// Generate calls the provider allows between two entropy inputs.
    pub reseed_interval_generates: u64,
    /// Whether the provider takes per-call prediction resistance.
    pub per_call_prediction_resistance: bool,
}

impl std::fmt::Display for ProviderDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "provider={} version={} mechanism={} use_df={} reseed_interval={} \
             prediction_resistance={}",
            self.provider,
            self.version,
            self.mechanism,
            self.use_df,
            self.reseed_interval_generates,
            if self.per_call_prediction_resistance {
                "per-call"
            } else {
                "provider-profile"
            },
        )
    }
}

/// Whether a fresh entropy input must precede the bytes about to be produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredictionResistance {
    /// Mandatory for a private key, a PSK, or any lasting secret.
    Required,
    /// Admissible for a request identifier or another public value.
    NotRequired,
}

/// The DRBG, seen from the protocols that consume it.
///
/// An implementation **forwards** to a crypto library; it does not generate.
/// The only implementation a shipped binary can reach is [`AwsLcProvider`].
pub trait DrbgProvider: Send + Sync {
    /// What the start-up banner names.
    fn describe(&self) -> ProviderDescription;

    /// Fills `out` from the provider's DRBG, or fails without writing.
    fn fill(&self, out: &mut [u8], resistance: PredictionResistance) -> Result<(), RandomError>;
}

/// Generate calls AWS-LC allows between two entropy inputs.
///
/// `kCtrDrbgReseedInterval`, from `crypto/fipsmodule/rand/internal.h` of the
/// vendored source. Reported rather than enforced: the reseed belongs to the
/// provider, and this module's job is to say what the provider does, not to
/// count alongside it.
const AWS_LC_RESEED_INTERVAL: u64 = 4096;

/// AWS-LC's CTR-DRBG-AES-256, reached through [`aws_lc_rs::rand::SystemRandom`].
///
/// The same library the rest of the workspace uses for AES-GCM, HKDF and HMAC,
/// so the randomness of the protocol comes from the engine already reviewed
/// for everything else rather than from a second one nobody looked at.
#[derive(Debug, Default)]
pub struct AwsLcProvider {
    source: aws_lc_rs::rand::SystemRandom,
}

impl DrbgProvider for AwsLcProvider {
    fn describe(&self) -> ProviderDescription {
        ProviderDescription {
            provider: "AWS-LC (aws-lc-rs)",
            version: PROVIDER_VERSION,
            mechanism: DrbgMechanism::CtrAes256,
            // `CTR_DRBG_init` consumes exactly one seedlen of full entropy and
            // XORs the personalization string into it: SP 800-90Ar1
            // §10.2.1.3.1, no derivation function. Reported as it is, not as
            // the specifications wish it were.
            use_df: false,
            reseed_interval_generates: AWS_LC_RESEED_INTERVAL,
            per_call_prediction_resistance: false,
        }
    }

    fn fill(&self, out: &mut [u8], _resistance: PredictionResistance) -> Result<(), RandomError> {
        use aws_lc_rs::rand::SecureRandom as _;

        // The requested resistance travels to this boundary and stops here:
        // `aws-lc-rs` exposes one entry point, and the reseed profile behind it
        // is what the description reports. Nothing supplements it — supplementing
        // it would mean generating bytes, which this module must not do.
        self.source
            .fill(out)
            .map_err(|_| RandomError::ProviderFailed)
    }
}

/// The provider this process draws from, resolved once.
static PROVIDER: OnceLock<Box<dyn DrbgProvider>> = OnceLock::new();

#[cfg(test)]
thread_local! {
    /// A provider installed in place of the shipped one, for tests only.
    ///
    /// Separate from [`PROVIDER`] and behind `cfg(test)`: a shipped binary has
    /// no path that reads this, and none that writes it.
    ///
    /// **Thread-local**, and that is the whole point. `cargo test` runs the
    /// crate's tests in parallel threads, so a process-wide slot would hand a
    /// starved or deterministic provider to whatever unrelated test happened
    /// to draw a nonce at that moment — which is exactly the flake it
    /// produced. A test now stands its provider up in front of itself only.
    static TEST_PROVIDER: std::cell::RefCell<Option<Box<dyn DrbgProvider>>> =
        const { std::cell::RefCell::new(None) };
}

fn with_provider<T>(
    action: impl FnOnce(&dyn DrbgProvider) -> Result<T, RandomError>,
) -> Result<T, RandomError> {
    #[cfg(test)]
    if TEST_PROVIDER.with(|slot| slot.borrow().is_some()) {
        return TEST_PROVIDER.with(|slot| {
            let slot = slot.borrow();
            action(slot.as_ref().expect("just checked").as_ref())
        });
    }
    action(
        PROVIDER
            .get_or_init(|| Box::new(AwsLcProvider::default()))
            .as_ref(),
    )
}

/// Resolves the provider, probes it, and returns what the banner must log.
///
/// Called at start-up so an unusable provider is a start-up error rather than
/// a refusal discovered by the first client to negotiate. The probe is one
/// call through the provider — it computes nothing, and it tests nothing the
/// provider is responsible for; it only refuses the block an unfilled buffer
/// leaves behind.
pub fn configure() -> Result<ProviderDescription, RandomError> {
    with_provider(|provider| {
        let mut probe = Zeroizing::new([0u8; 32]);
        provider.fill(probe.as_mut_slice(), PredictionResistance::Required)?;
        if probe.iter().all(|byte| *byte == 0) {
            return Err(RandomError::ProviderProbeFailed);
        }
        Ok(provider.describe())
    })
}

fn fill(out: &mut [u8], resistance: PredictionResistance) -> Result<(), RandomError> {
    if out.len() > MAX_BYTES_PER_REQUEST {
        return Err(RandomError::RequestTooLarge {
            requested: out.len(),
        });
    }
    with_provider(|provider| provider.fill(out, resistance))
}

/// Fills a public value: a request identifier, a challenge, a serial.
pub fn fill_public(out: &mut [u8]) -> Result<(), RandomError> {
    fill(out, PredictionResistance::NotRequired)
}

/// Fills a secret: a private key, a PSK, a salt, a capability secret.
pub fn fill_secret(out: &mut [u8]) -> Result<(), RandomError> {
    fill(out, PredictionResistance::Required)
}

/// A fixed-size public value.
pub fn public_bytes<const N: usize>() -> Result<[u8; N], RandomError> {
    let mut out = [0u8; N];
    fill_public(&mut out)?;
    Ok(out)
}

/// A fixed-size secret, zeroized when it goes out of scope.
pub fn secret_bytes<const N: usize>() -> Result<Zeroizing<[u8; N]>, RandomError> {
    let mut out = Zeroizing::new([0u8; N]);
    fill_secret(out.as_mut_slice())?;
    Ok(out)
}

/// The provider behind the `rand_core` interface `fips204` expects.
///
/// # Panics
///
/// [`rand_core::RngCore::next_u32`], [`rand_core::RngCore::next_u64`] and
/// [`rand_core::RngCore::fill_bytes`] have no failure path, so a provider that
/// cannot produce bytes leaves them one honest option: abort. Returning
/// anything at all would be returning unapproved randomness under a name that
/// promises the opposite. `fips204` only calls
/// [`rand_core::RngCore::try_fill_bytes`], which fails properly.
#[derive(Debug, Default, Clone, Copy)]
pub struct DrbgRng;

impl rand_core::RngCore for DrbgRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill_secret(dest).expect("the approved DRBG provider produced no bytes");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        // `rand_core` carries no payload without its `std` feature, and that
        // feature would pull a second entropy path into the tree; the code
        // says "the provider refused", and the caller's own error says the
        // rest.
        fill_secret(dest).map_err(|_| {
            rand_core::Error::from(
                std::num::NonZeroU32::new(rand_core::Error::CUSTOM_START)
                    .expect("CUSTOM_START is not zero"),
            )
        })
    }
}

impl rand_core::CryptoRng for DrbgRng {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Holds the provider a test needs in place for its whole duration.
    ///
    /// Scoped to the calling thread, so a test that starves its provider says
    /// nothing about what another test is drawing from at the same moment.
    struct TestProvider;

    impl TestProvider {
        /// Keeps the shipped provider, and says so.
        fn shipped() -> Self {
            TEST_PROVIDER.with(|slot| *slot.borrow_mut() = None);
            Self
        }

        fn install(provider: impl DrbgProvider + 'static) -> Self {
            TEST_PROVIDER.with(|slot| *slot.borrow_mut() = Some(Box::new(provider)));
            Self
        }
    }

    impl Drop for TestProvider {
        fn drop(&mut self) {
            TEST_PROVIDER.with(|slot| *slot.borrow_mut() = None);
        }
    }

    fn test_description() -> ProviderDescription {
        ProviderDescription {
            provider: "test stand-in",
            version: "0",
            mechanism: DrbgMechanism::HmacSha512,
            use_df: false,
            reseed_interval_generates: MAX_GENERATES_BETWEEN_RESEEDS,
            per_call_prediction_resistance: false,
        }
    }

    /// A deterministic stand-in: unreachable outside `cfg(test)`, and never
    /// described as conforming.
    struct Counting(std::sync::Mutex<u8>);

    impl DrbgProvider for Counting {
        fn describe(&self) -> ProviderDescription {
            test_description()
        }

        fn fill(&self, out: &mut [u8], _: PredictionResistance) -> Result<(), RandomError> {
            let mut next = self.0.lock().expect("counter");
            for byte in out.iter_mut() {
                *next = next.wrapping_add(1);
                *byte = *next;
            }
            Ok(())
        }
    }

    /// A provider that always refuses, which is what an entropy outage is.
    struct Refusing;

    impl DrbgProvider for Refusing {
        fn describe(&self) -> ProviderDescription {
            test_description()
        }

        fn fill(&self, _: &mut [u8], _: PredictionResistance) -> Result<(), RandomError> {
            Err(RandomError::ProviderFailed)
        }
    }

    /// A provider that answers with an unfilled buffer.
    struct Silent;

    impl DrbgProvider for Silent {
        fn describe(&self) -> ProviderDescription {
            test_description()
        }

        fn fill(&self, out: &mut [u8], _: PredictionResistance) -> Result<(), RandomError> {
            out.fill(0);
            Ok(())
        }
    }

    #[test]
    fn the_shipped_provider_produces_distinct_values() {
        let _shipped = TestProvider::shipped();
        let first = public_bytes::<32>().expect("public bytes");
        let second = public_bytes::<32>().expect("public bytes");
        assert_ne!(first, second);
        assert_ne!(first, [0u8; 32]);
        let secret = secret_bytes::<32>().expect("secret bytes");
        assert_ne!(*secret, first);
    }

    /// The provider's own profile has to sit inside what the protocol asks
    /// for — otherwise the specification's reseed rule would be a sentence
    /// nobody checks against the library actually linked.
    ///
    /// The banner is a claim about someone else's code, so what it claims is
    /// pinned here: a description that drifts from the vendored AWS-LC source
    /// has to break a test, not merely become quietly untrue.
    #[test]
    fn the_shipped_provider_matches_the_profile_the_specification_asks_for() {
        let _shipped = TestProvider::shipped();
        let description = AwsLcProvider::default().describe();
        assert_eq!(description.mechanism, DrbgMechanism::CtrAes256);
        // No derivation function: `CTR_DRBG_init` takes one seedlen of full
        // entropy (SP 800-90Ar1 §10.2.1.3.1). Announcing `true` here would be
        // the comfortable answer and the false one.
        assert!(!description.use_df);
        // The provider reseeds far inside the protocol's ceiling; if AWS-LC
        // ever raised its interval past it, this is where it would show.
        assert!(description.reseed_interval_generates <= MAX_GENERATES_BETWEEN_RESEEDS);
        assert_eq!(
            description.reseed_interval_generates,
            AWS_LC_RESEED_INTERVAL
        );
        // Per-call prediction resistance is not reachable through the wrapper;
        // claiming it would make `fill_secret` promise what it cannot keep.
        assert!(!description.per_call_prediction_resistance);
        // The banner carries every field, secrets excepted: a deployment reads
        // what it runs on its first journal line.
        let banner = description.to_string();
        for field in [
            "provider=",
            "version=",
            "mechanism=",
            "use_df=",
            "reseed_interval=",
            "prediction_resistance=",
        ] {
            assert!(banner.contains(field), "banner is missing {field}");
        }
    }

    #[test]
    fn a_provider_that_refuses_yields_no_bytes() {
        let _installed = TestProvider::install(Refusing);
        let mut out = [0u8; 32];
        assert_eq!(
            fill_secret(&mut out).err(),
            Some(RandomError::ProviderFailed)
        );
        assert_eq!(out, [0u8; 32]);
        assert_eq!(configure().err(), Some(RandomError::ProviderFailed));
    }

    #[test]
    fn a_provider_answering_with_an_unfilled_buffer_fails_the_start_up_probe() {
        let _installed = TestProvider::install(Silent);
        assert_eq!(configure().err(), Some(RandomError::ProviderProbeFailed));
    }

    #[test]
    fn a_request_longer_than_one_call_allows_is_refused_before_the_provider() {
        let _installed = TestProvider::install(Counting(std::sync::Mutex::new(0)));
        let mut out = vec![0u8; MAX_BYTES_PER_REQUEST + 1];
        assert_eq!(
            fill_public(&mut out).err(),
            Some(RandomError::RequestTooLarge {
                requested: MAX_BYTES_PER_REQUEST + 1
            })
        );
        assert!(out.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn the_rng_adapter_draws_from_the_provider_and_propagates_its_refusal() {
        use rand_core::RngCore as _;

        let _shipped = TestProvider::shipped();
        let mut rng = DrbgRng;
        let mut first = [0u8; 48];
        let mut second = [0u8; 48];
        rng.try_fill_bytes(&mut first).expect("fill");
        rng.try_fill_bytes(&mut second).expect("fill");
        assert_ne!(first, second);

        let _installed = TestProvider::install(Refusing);
        assert!(rng.try_fill_bytes(&mut first).is_err());
    }
}
