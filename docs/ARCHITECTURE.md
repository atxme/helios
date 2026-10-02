# Current architecture

This document is the operational view of the code as it stands. The ADRs keep
the historical reasoning; when the two disagree, the code and the accepted ADRs
win.

## System boundaries

Helios is the Linux gateway. Orion is the road-warrior client. `aether` holds
the shared pure contracts and owns no runtime system resource.

```text
Orion (Tauri)                          Helios (Linux appliance)
┌──────────────────────┐              ┌────────────────────────────────┐
│ React ↔ Tauri cmds   │              │ heliosd                        │
│                      │─ QUIC/mTLS ─►│  ├─ key negotiation (v5)       │
│ orion-core           │  (pre-tunnel)│  ├─ orchestrator               │
│  ├─ key negotiation  │              │  ├─ Axum API / WebSocket       │
│  ├─ identity store   │◄─ WireGuard ►│  ├─ WireGuard backend          │
│  └─ WireGuard backend│              │  ├─ nftables firewall          │
└──────────────────────┘              │  ├─ TPM, vault                 │
                                      │  ├─ escrow                     │
                                      │  └─ signed update + rollback   │
                                      └────────────────────────────────┘
```

The kernel carries and encrypts packets. `heliosd` does not reimplement
WireGuard: it brings the interface up, configures peers, observes handshakes and
applies the nftables policy.

## Gateway startup

The order is a security property:

1. load the configuration and the secrets the TPM authorises;
2. engage the kill-switch before any network contact;
3. bring up `helios0` and configure its peers;
4. move to `connecting`;
5. poll handshakes every 10 seconds;
6. move to `up` once a handshake is younger than 150 seconds;
7. fall back to `connecting` when that handshake goes stale.

With `wg_address_v6`, step 3 also installs `<prefix>::1/64` on `helios0`, puts
each peer's `/128` next to its `/32` in `AllowedIPs`, and pins those `/128` in
the VIP routing table `51820` with an `ip -6` rule. Before bring-up the gateway
refuses IPv6 when the tunnel MTU is below 1280 or the kernel has
`disable_ipv6 = 1` (or no IPv6 stack); a kernel that still refuses the address
gets one IPv4-only retry after the interface is taken down. The gateway then
starts IPv4-only in a visible degraded state: a warning on the journal and the
event stream, `ipv6: {"unavailable": {"reason": …}}` in `GET /api/status`
(`"installed"` or `"not_configured"` otherwise), shown by `helios-ctl status`,
and the same pre-checks printed by `heliosd status`. Without `wg_address_v6`
nothing changes (`specification/ADRESSAGE-IPV6.md` §6).

Only `TunnelState::Up` allows LAN traffic. `down`, `connecting`, `failed` and
`captive_portal` stay fail-closed, save for the narrowly declared openings for
the handshake, administration and the captive portal.

The Netlink backend translates the **whole** ruleset first. A translation error
sends nothing. The batch is then applied as one atomic transaction; rule-by-rule
application is never allowed. NAT belongs to that same transaction: a masquerade
outliving the kill-switch would leak in clear what the switch just cut.

`network.toml` is watched and re-read live, so the peer table changes without a
restart. Every reload goes through `NetworkConfig::adopt_runtime_secrets_from`:
the file holds neither the sealed private key nor the negotiated PSKs, and
applying it verbatim would strip the gateway of its identity. What cannot change
under a running data plane — interface name, listen port, API address — still
requires a restart. The optional IPv6 tunnel prefix `wg_address_v6` is in that
position and is enforced: a file or a `POST /api/network` that changes it is not
applied at all until the next start — the watcher logs a warning, the API
answers `409` and writes nothing. Peers' `address_v6` reload live with the peer
table (`specification/ADRESSAGE-IPV6.md` §5.4).

A policy change — a reload, or a split-tunnel list — becomes the running policy
only once it compiles for every tunnel state and the backend has applied it. A
refused one leaves the running policy, configuration and ruleset in force, is
logged as an error on the event stream, and does not stop the orchestrator.
`POST /api/split-tunnel` checks each CIDR with the ruleset compiler's parser and
`POST /api/network` checks the whole policy: both answer `400`, naming the
refused address, and send and write nothing.

## Key negotiation (v5)

Before any WireGuard packet, Orion negotiates on a dedicated UDP port and leaves
with the PSK the **first** handshake will use. TLS carries; the ML-DSA-87
application certificate and the signed transcript authenticate.

- One 32-byte `server_challenge` per connection, single-use, deliberately
  unsigned by the gateway — signing it would hand an unauthenticated peer a free
  ML-DSA-87 operation.
- The TLS fingerprint resolves to **its** one admitted peer as soon as mTLS
  completes. A request's WireGuard key is then compared against that peer; it is
  never the lookup key into the table.
- Two negotiable modes, `static_psk` and `ml_kem`, plus a per-peer floor that
  only ever rises. `classic` is not a v5 mode: `validate()` rejects it.
- The gateway installs the PSK on the data plane **before** announcing it, and
  refuses the request if the install fails. A negotiated PSK never reaches disk.
- Commit requires a **WireGuard handshake proof** read from the data plane,
  strictly newer than the observation taken before the candidate was installed.
  It is the only evidence that engages the peer's WireGuard private key.
- The signed commit is the point of no return. Rollback only searches active
  transactions, so after signing it finds nothing — by construction.
- Each slot carries a per-peer generation, reserved under the same lock that
  reserves the peer. Any late actor must present the generation it observed; a
  stale one is a no-op, never a write.
- The QUIC session is closed after commit. It carried a transaction, not a
  liveness signal — the opposite of v4, where a 35-second network blip killed a
  healthy tunnel.

Liveness is read on the data plane only, at three distinct thresholds:
`HANDSHAKE_STALE_AFTER_SECS` (150 s) decides tunnel state and therefore the
kill-switch; `PSK_RECLAIM_AFTER_STALE_SECS` (300 s) decides when the gateway
destroys a vanished peer's secret; `MAX_PSK_LIFETIME` (24 h) bounds a PSK's age
on a healthy tunnel. All of it assumes a persistent keep-alive, so the gateway
sets its own (25 s) rather than trusting one it cannot inspect.

The listener is one dual-stack `[::]` UDP socket with `IPV6_V6ONLY` cleared
(`aether_key_negotiation::dual_stack_server_endpoint`): IPv6 clients arrive
natively and IPv4 clients as `::ffff:a.b.c.d`, which the server canonicalizes
before counting or logging them. One socket rather than two keeps a single
connection table, Retry key and set of budgets. A host that refuses the IPv6
address family (`EAFNOSUPPORT`) falls back to `0.0.0.0` with a warning naming
the reason; any other bind error still stops the service.

The public QUIC port answers with three error codes only — `protocol`,
`rejected`, `internal` — so that it cannot be used to enumerate admitted peers
or read their floor. Its DoS bounds are Retry before any state, a budget per
IPv4 address or per IPv6 `/64` prefix (an IPv4-mapped `::ffff:a.b.c.d` source
counts as its IPv4 address), a budget per admitted identity after
mTLS, a 90-second absolute connection lifetime, TLS resumption and 0-RTT
disabled on both ends, no unidirectional streams, and datagrams pinned to 1200
bytes with MTU discovery off on both sides — 1248 bytes on the wire over IPv6,
under its 1280-byte minimum link MTU.

Releasing a PSK lives **inside** the tunnel, on
`POST /api/key-negotiation/release`, and nowhere else. It is best-effort and its
failure does not delay disconnection; the 300-second reclaim is the net.

The negotiation is not a compile-time feature — every binary carries it, and
only `key_negotiation_port` decides whether the service opens.

## Certificate lifecycle

Not implemented. The gateway's PQ leaf is still self-signed and pinned as such
in every profile; there is no active/next slot and no anti-rollback generation.
The target is fixed by
[specification/ROTATION-CERTIFICATS.md](specification/ROTATION-CERTIFICATS.md)
and [ADR-008](adr/ADR-008-ASTRA-AUTORITE-CERTIFICATS.md), which names **Astra**
the PKI coordinator: a dedicated container co-located with `heliosd`, a separate
public HTTPS channel, a private veth channel to the gateway, a master anchor in
an HVLT vault and a bounded delegated issuing key.

`init-key-negotiation --rotate` is not that path. It replaces files; it prepares
no transition and no next slot, and every profile pinning the old identity stops
connecting after the restart.

## Orion lifecycle

Orion brings its adapter up straight from the profile: UDP endpoint, client
private key, gateway public key, VIP, `AllowedIPs`, keep-alive and the PSK the
negotiation just produced. The Helios API never takes part in that initial
bring-up, since it lives behind the tunnel.

Orion has no local kill-switch. With `AllowedIPs = 0.0.0.0/0, ::/0` (the
default full tunnel), the adapter must stay up after a failure so WireGuard
keeps capturing and dropping packets; `down()` is called on explicit
disconnection only. `::/0` is captured even though the gateway routes no IPv6
for its peers: WireGuard drops it, which is what keeps a dual-stack machine's
IPv6 from leaving in clear. A profile stored with `0.0.0.0/0` alone is never
rewritten; Orion and `helios-ctl profile check` flag it as an IPv4-only full
tunnel. A binary built with
`orion/wireguard` refuses to start when the real backend cannot initialise, and
never falls back to a simulation. Conversely, an Orion **for Windows** built
without that feature does not compile: the fallback would ship a client that
opens no tunnel while displaying a profile and a negotiated mode.

The client identity is sealed by DPAPI to the Windows account. Known limitation:
DPAPI neither compiles nor runs under WSL2 — off Windows the seal fails loudly
rather than writing those keys in clear.

## Administration API

The API listens on the host address of `wg_address` once the gateway is ready,
otherwise on `127.0.0.1:8080`. nftables limits remote access to `admin_iface`.
It never brings the initial tunnel up. That host must be an IPv4 address: a
ready gateway whose `wg_address` names no IPv4 host (malformed, or IPv6) stops
`heliosd run` at startup instead of moving the API and the speedtest to
loopback, and `heliosd status` prints the reason.

- state and rule reads carry no secret;
- `GET /api/network` returns a dedicated view that only says **whether** a
  private key or a PSK is configured;
- `GET /api/trust` exposes the required algorithms and the compiled publisher
  keyring fingerprints, never whole keys;
- `GET /api/key-negotiation` serves the public negotiation material that
  `helios-ctl enroll` reads;
- every mutation requires `application/json`, and no permissive CORS is enabled;
- the source address, canonicalized (`::ffff:a.b.c.d` is its IPv4 address),
  resolves to a WireGuard peer's single `/32` IPv4 VIP, with no proxy header
  accepted, and mutations require `admin = true`; a native IPv6 source is never
  a caller;
- the WebSocket streams state transitions and post-connection telemetry.

The HTTP barrier guards against cross-origin forms. The application identity is
the WireGuard peer's; no separate web login exists.

## Admission and provisioning

Admission binds, out of band, a client's WireGuard public key and the
fingerprints of its TLS and ML-DSA-87 certificates. `heliosd peer` and
`helios-ctl peer` share one implementation in
`helios_provisioning::admission`. Admission never does a read-modify-write of
`network.toml` from the API's redacted view — that would erase other peers'
PSKs — and it persists neither private key nor PSK. It also refuses an explicit
keep-alive of `0`: without one, an idle tunnel produces no handshake and the
liveness thresholds would read a stale timestamp on a perfectly healthy peer.

Admission is also the IPAM's only caller. One collision view covers both
families — declared peers, the live WireGuard table when the caller has one
(`POST /api/peers` does, `heliosd peer add` does not), and the gateway's
reserved addresses — and one allocation point chooses the peer's IPv4 VIP and,
when the gateway has `wg_address_v6`, its IPv6 VIP. What admission writes to
`network.toml` is the peer's address from then on. Readmitting the same
identity returns those addresses unchanged, adding only an IPv6 VIP the
gateway's prefix postdates ([ADRESSAGE-IPV6.md](specification/ADRESSAGE-IPV6.md)
§3 bis).

`POST /api/provision` remains the in-tunnel ML-KEM exchange for an already
admitted peer, deliberately without TLS: the tunnel already provides
confidentiality and mutual authentication, and the PSK's post-quantum
confidentiality does not depend on the channel. It returns the persisted VIPs
and never derives one, so the address announced to a client is the one the
gateway routes. The deterministic IPAM is independent of key negotiation.

## Secrets at rest

[ADR-006](adr/ADR-006-SECRETS-AU-REPOS.md) mandates a single container,
`aether-vault`: AES-256-GCM, domain and object-context separation, bounded
parser. A `domain` separates uses; an `object_context` separates instances of
one use, so two blobs of the same kind never stay interchangeable.

The gateway's identity is born **on** the gateway (`heliosd init-identity`) and
sealed to the TPM. A cleartext `wg_private_key` in `network.toml` is a legacy
fallback, not an installation path. The escrow private key belongs on the
operator workstation, never on the gateway it rescues.

## Verified boot and update window

`helios-tpm` seals the secret protecting the gateway's WireGuard identity against
PCR 0/4/7. A v2 resealing ticket must carry two valid signatures over the same
canonical bytes — Ed25519 **and** ML-DSA-65. The signed key epoch selects a
compiled public keyring; its counter is mandatory and must strictly increase;
its PCR binding is optional but must match when present. The v1 Ed25519-only
format is refused with no fallback.

[ADR-007](adr/ADR-007-FENETRE-DE-MISE-A-JOUR.md) adds an update window that
**carries** an integrity verdict across a planned reboot rather than
manufacturing one. Arming requires a nominal unseal of the current boot. At
startup the nominal PCR 0/4/7 unseal always runs first, and its success revokes
a window left armed. On consumption, the NV payload is overwritten only **after**
the resealed blob is on disk and synced.

WireGuard identity recovery is deliberately unfinished: the choice between a
file-based `TpmState.version` and a TPM NV counter must be settled before ADR-002
lot 3.

## Application update

The UI or `helios-ctl app-update` transfers a `helios-binary-release-v1`
manifest and the binary in JSON chunks. `heliosd` verifies the Ed25519 and
ML-DSA-65 signatures, the target, the channel, the size and the SHA-256, then
stages under `/var/lib/helios/updates`.
`helios-installer`, launched by systemd and denied network access, re-verifies
the artefact, switches `/opt/helios/current`, restarts the daemon and restores
the previous link if the daemon and its API do not become ready.

This flow replaces neither kernel nor rootfs, does not reboot the machine, and
therefore does not move TPM PCR 0/4/7. Upgrading the OS is a different path:
`helios-ctl update`, which arms the ADR-007 window and reboots.

Two ML-DSA parameter sets coexist and do not substitute for one another:
`ml-dsa-65` signs publisher artefacts (`aether::sig`), `ml-dsa-87` carries the
negotiation PKI (`aether::key_negotiation`). Swapping them would invalidate the
verification of every release already signed.

## Backends and validation

Default backends are simulated. The hardware features are `netlink`,
`wireguard`, `tpm` and `embed-ui`. Compiling them under WSL2 validates types and
contracts; it validates no kernel or TPM effect. The hardware recipe in
[TESTING.md](testing/TESTING.md) stays mandatory before delivery.

When real mode is requested, an unavailable feature or backend stops the daemon.
A gateway never silently falls back to a simulation.
