// Access layer to the Rust backend via Tauri (invoke) + event stream (listen).
// The connection mounts WireGuard on the Rust side. Only post-tunnel
// telemetry/provisioning then uses Helios's internal HTTP API.

import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import type {
  About,
  ApprovalManifest,
  AstraRotationInput,
  AstraRotationStatus,
  OperationLocator,
  OperatorAction,
  OperatorStatus,
  CertificateAction,
  CertificateActionState,
  ActionOutcome,
  RenewalProgress,
  CertificateInventory,
  ClientConfig,
  ClientEvent,
  ImportOutcome,
  KeyNegotiationSettings,
  KeyNegotiationSupport,
  ProfileCertificates,
  ProfileDraft,
  ProfileIssues,
  SpeedTestResult,
  SpeedTestMode,
  SpeedTestProgress,
  TunnelState,
  VaultPosture,
} from './types'

export const getState = () => invoke<TunnelState>('get_state')
export const backendKind = () => invoke<string>('backend_kind')
export const adapterIsUp = () => invoke<boolean>('adapter_is_up')
export const getConfig = () => invoke<ClientConfig>('get_config')

/**
 * What the About box states.
 *
 * Read from Rust rather than from `package.json`: the version that matters is
 * the one of the binary driving the adapter, and the profile extension it
 * reports is the same constant the file association is built from.
 */
export const aboutOrion = () => invoke<About>('about_orion')

/**
 * Imports a document and seals any identity it carries.
 *
 * The sealing happens on the Rust side, at import time: it is the only moment
 * the private material exists in the clear, and the shorter that moment is
 * the better.
 */
export const importProfile = (contents: string, fileName: string) =>
  invoke<ImportOutcome>('import_profile', { contents, fileName })
export const importProfilePath = (path?: string) =>
  invoke<ImportOutcome | null>('import_profile_path', { path: path ?? null })

/**
 * Reports the faulty fields of a profile being edited.
 *
 * The rules live in `orion-core`: the UI highlights what the core refuses,
 * it doesn't reimplement them.
 */
export const validateProfile = (draft: ProfileDraft) =>
  invoke<ProfileIssues>('validate_profile', { draft })

/**
 * What this build can do with the negotiation port.
 *
 * Compiled-in support and a wired identity store fail differently, so the
 * screen states which one is missing rather than promising a mode the client
 * would refuse at connection time.
 */
export const keyNegotiationSupport = () =>
  invoke<KeyNegotiationSupport>('key_negotiation_support')

/**
 * The four certificates a connection depends on, with their dates.
 *
 * Read in Rust, through the same validator the negotiation uses: the two
 * client certificates live in the protected identity store, which this side
 * has no business reaching, and re-deriving the 80 / 90 / 95 % ladder here
 * would be a second implementation of the planner's arithmetic.
 *
 * It supersedes the two calls it replaced — one for the pinned fingerprint,
 * one for "is the identity sealed". Both answered a third of this question,
 * and three round trips for three halves of one fact is how a screen ends up
 * showing a fingerprint that belongs to a certificate it has not checked.
 */
export const certificateInventory = (keyNegotiation: KeyNegotiationSettings | null) =>
  invoke<CertificateInventory>('certificate_inventory', { keyNegotiation })

/**
 * State of the four certificate actions of spec §12.2, for one profile.
 *
 * The decision is the shell's, beside the state it reads. This side renders
 * the reason it is given and never composes one: a screen that guessed why an
 * action is unavailable would eventually guess wrong, and it would guess in
 * the reassuring direction.
 */
export const certificateActions = (keyNegotiation: KeyNegotiationSettings | null) =>
  invoke<CertificateActionState[]>('certificate_actions', { keyNegotiation })

/**
 * The same, for every profile of this device, in one call.
 *
 * Reading a profile's certificates unseals its protected identity. A screen
 * listing six profiles asking two questions each would make twelve DPAPI round
 * trips to draw one view.
 */
export const certificateOverview = () =>
  invoke<ProfileCertificates[]>('certificate_overview')

/**
 * Runs one of them, or rejects with the reason it cannot run.
 *
 * Resolves with where the renewal stopped rather than with nothing: a renewal
 * waits on a human, so «lancé» is not an outcome the screen can show. Pressing
 * again on an operation already open resumes it — it never opens a second one.
 *
 * Keyed by profile: `renew_every_profile` advances all of them by one step,
 * and each has its own place to wait.
 */
export const runCertificateAction = (name: string, action: CertificateAction) =>
  invoke<ActionOutcome>('run_certificate_action', { name, action })

/**
 * Launches the operator companion for this profile's in-memory operation.
 *
 * The inlined Tauri plugin accepts only the profile name. Rust resolves the
 * session and its core-built invocation; no executable or argument crosses
 * from the WebView.
 */
export const launchCertificateCompanion = (name: string) =>
  invoke<void>('plugin:companion|launch_certificate_companion', { name })

/**
 * Reads the approval request the open renewal is waiting on.
 *
 * Verified on the Rust side before it comes back. Nothing touches a security
 * key here — the manifest exists so the user decides before the ceremony.
 */
export const certificateApprovalManifest = (name: string) =>
  invoke<ApprovalManifest>('certificate_approval_manifest', { name })

/**
 * Whether this machine's key collects its own PIN.
 *
 * Asked rather than assumed: under Windows the platform dialog collects it and
 * it never enters Orion, so prompting would be asking for a secret Orion has
 * no use for.
 */
export const certificateApprovalNeedsPin = (name: string) =>
  invoke<boolean>('certificate_approval_needs_pin', { name })

/**
 * Runs the ceremony and posts the assertion.
 *
 * Resolves with where the renewal reached. The manifest must have been read
 * first: what is signed is what was shown.
 */
export const approveCertificateRenewal = (name: string, pin?: string) =>
  invoke<RenewalProgress>('approve_certificate_renewal', { name, pin })

/** The last certificate action that failed on this profile, if any. */
export const lastCertificateError = (name: string) =>
  invoke<string | null>('last_certificate_error', { name })

/**
 * Measures the authenticated WireGuard path for the fixed 20-second interval.
 *
 * The mode is required rather than defaulted: it decides how many phases run,
 * and therefore how long the call blocks. A silent `full` doubled that for any
 * caller who left it out.
 */
export const runSpeedTest = (mode: SpeedTestMode) =>
  invoke<SpeedTestResult>('run_speed_test', { mode })

/** Receives progress from the direct socket benchmark. */
export function onSpeedTestProgress(cb: (progress: SpeedTestProgress) => void): Promise<UnlistenFn> {
  return listen<SpeedTestProgress>('helios://speedtest', (event) => cb(event.payload))
}

/**
 * Draws a WireGuard key pair in Rust and returns its **public** half.
 *
 * The private half never comes back — it waits in the shell until the profile
 * is saved. The public one is returned at once because it is what the user
 * hands the operator: admission is out of band, and it has to happen before
 * the profile can work at all.
 */
export const generatePrivateKey = () => invoke<string>('generate_private_key')

/**
 * Hands an existing private key to Rust, which validates it and answers with
 * its public half.
 *
 * This is the one place a secret travels **towards** the shell, at an explicit
 * gesture. The caller must clear its input immediately afterwards: a value
 * left in a field stays in the DOM for as long as the screen lives.
 */
export const adoptPrivateKey = (privateKey: string) =>
  invoke<string>('adopt_private_key', { privateKey })

/** Drops the staged key. Called when an edit is abandoned. */
export const discardStagedKey = () => invoke<void>('discard_staged_key')

/**
 * Hands a static PSK to Rust, which validates it and holds it until the save.
 *
 * Same one-way rule as {@link adoptPrivateKey}, and nothing comes back: a PSK
 * has no public half to show. The caller clears its input immediately.
 */
export const adoptPresharedKey = (presharedKey: string) =>
  invoke<void>('adopt_preshared_key', { presharedKey })

/** Drops the staged PSK. Called when an edit is abandoned. */
export const discardStagedPsk = () => invoke<void>('discard_staged_psk')

export const saveProfile = (draft: ProfileDraft) =>
  invoke<ClientConfig>('save_profile', { draft })
export const deleteProfile = (name: string) =>
  invoke<ClientConfig>('delete_profile', { name })
export const selectProfile = (name: string) =>
  invoke<ClientConfig>('select_profile', { name })

/**
 * The SSH command line for the gateway, to paste into your own terminal.
 *
 * Orion does **not** run it, and must not: it runs elevated to load the
 * WireGuard driver, so any terminal it spawned would be an Administrator
 * terminal — an escalation one click away from the UI. Rust still owns the
 * gates: the tunnel must be up, and the destination is re-validated before it
 * reaches a clipboard.
 */
export const sshCommand = (name?: string) =>
  invoke<string>('ssh_command', { name: name ?? null })

/**
 * Opens a terminal connected to the gateway, **below** Orion's privileges.
 *
 * Orion runs elevated to load the WireGuard driver, so the child is built from
 * the standard-user token Windows keeps linked to the elevated one. Rust
 * refuses to launch anything until Windows confirms that token is not
 * elevated — on a machine with no such token the call fails, and the caller
 * falls back to {@link sshCommand}.
 */
export const openSshTerminal = (name?: string) =>
  invoke<void>('open_ssh_terminal', { name: name ?? null })

export const connect = (name?: string) => invoke<void>('connect', { name: name ?? null })
export const disconnect = () => invoke<void>('disconnect')

/** Opens the Rust-owned, two-key CA-TLS signing ceremony. */
export const startAstraCaTlsRotation = (input: AstraRotationInput) =>
  invoke<AstraRotationStatus>('start_astra_ca_tls_rotation', { input })

/** Advances the open ceremony after the requested security key was connected. */
export const continueAstraCaTlsRotation = () =>
  invoke<AstraRotationStatus>('continue_astra_ca_tls_rotation')

/** Stops the open signer session without producing a transition. */
export const cancelAstraCaTlsRotation = () =>
  invoke<AstraRotationStatus>('cancel_astra_ca_tls_rotation')

/** Restores or polls the Rust-owned ceremony after a view change. */
export const astraCaTlsRotationStatus = () =>
  invoke<AstraRotationStatus>('astra_ca_tls_rotation_status')

/* Cérémonies opérateur (protocole 2). Le WebView ne nomme qu'un localisateur ;
 * l'origine, le RP ID, le domaine et la clé de service viennent du hand-off que
 * le processus opérateur épingle lui-même. */
export const beginOperatorCeremony = (locator: OperationLocator) =>
  invoke<OperatorStatus>('begin_operator_ceremony', { locator })

export const advanceOperatorCeremony = (action: OperatorAction, revision: number) =>
  invoke<OperatorStatus>('advance_operator_ceremony', { action, revision })

export const operatorCeremonyStatus = () =>
  invoke<OperatorStatus | null>('operator_ceremony_status')

/**
 * Adjusts the window to the displayed view.
 *
 * Dimensions are decided on the Rust side: the frontend names the view, it
 * doesn't size anything itself.
 */
export const resizeForView = (view: string) => invoke<void>('resize_for_view', { view })

/**
 * Writes the log to disk and returns the resulting path.
 *
 * `stem` is only a label: the frontend proposes it because it knows the
 * local time, but Rust sanitizes it and picks the directory on its own.
 */
export const exportLogs = (stem: string, contents: string) =>
  invoke<string>('export_logs', { stem, contents })

/** Subscription to the backend's real-time event stream. */
export function onEvent(cb: (ev: ClientEvent) => void): Promise<UnlistenFn> {
  return listen<ClientEvent>('helios://event', (e) => cb(e.payload))
}

/** A double-click added a path to the Rust import queue. */
export function onProfilePath(cb: () => void): Promise<UnlistenFn> {
  return listen('helios://profile-path', cb)
}

/**
 * What the notification-area menu asks the window to show.
 *
 * `import` and `about` are not views: the first opens the profile screen *and*
 * its file picker, the second a dialog over whatever is displayed. They travel
 * on the same channel all the same — the menu names an intent, the window
 * decides what that means.
 */
export type TrayView = 'connect' | 'profiles' | 'logs' | 'import' | 'about'

const TRAY_VIEWS: TrayView[] = ['connect', 'profiles', 'logs', 'import', 'about']

/** A tray action selected while the main window was hidden. */
export function onTrayView(cb: (view: TrayView) => void): Promise<UnlistenFn> {
  return listen<string>('helios://tray-view', (event) => {
    const view = TRAY_VIEWS.find((known) => known === event.payload)
    if (view) cb(view)
  })
}

/**
 * The Rust side changed the profile list or the selection.
 *
 * Emitted when the tray connects to a profile: that click selects it, and the
 * window — which may have been open behind the menu — has no other way to learn
 * that the selection moved under it.
 */
export function onConfigChanged(cb: () => void): Promise<UnlistenFn> {
  return listen('helios://config-changed', cb)
}

/**
 * Reads the vault's posture.
 *
 * Asked on every panel opening rather than cached: BitLocker can be suspended
 * and the memory-lock privilege can change while Orion runs, so a value read
 * once at startup would eventually claim a protection that has since gone.
 */
export const vaultPosture = () => invoke<VaultPosture>('vault_posture')

/**
 * Persists the informed choice made in the bare-volume warning.
 *
 * Kept separate from save/import so neither action can silently manufacture
 * consent merely because BitLocker is absent.
 */
export const allowUnencryptedVolume = () =>
  invoke<VaultPosture>('allow_unencrypted_volume')
