// Access layer to the Rust backend via Tauri (invoke) + event stream (listen).
// The connection mounts WireGuard on the Rust side. Only post-tunnel
// telemetry/provisioning then uses Helios's internal HTTP API.

import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import type {
  VaultOverview,
  About,
  ApprovalManifest,
  AstraRotationInput,
  AstraRotationStatus,
  OperationLocator,
  OperatorAction,
  OperatorPendingOperation,
  OperatorStatus,
  OperatorArtifact,
  DomainDefaults,
  EnrollmentGesture,
  IssuerGesture,
  RotationGesture,
  RotationTerms,
  RelayUpdate,
  VaultGesture,
  VaultLocationView,
  InvitationView,
  CertificateAction,
  CertificateActionState,
  ActionOutcome,
  RenewalProgress,
  CertificateInventory,
  ClientConfig,
  ClientEvent,
  ImportOutcome,
  InvitationPreview,
  PendingEnrollment,
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
 * Imports a document. A signed v5 document is verified and completed on the
 * Rust side against the pending enrollment it answers, before anything is
 * shown.
 */
export const importProfile = (contents: string, fileName: string) =>
  invoke<ImportOutcome>('import_profile', { contents, fileName })
export const importProfilePath = (path?: string) =>
  invoke<ImportOutcome | null>('import_profile_path', { path: path ?? null })

/** Reads an enrollment invitation; nothing is trusted or generated yet. */
export const previewEnrollmentInvitation = (contents: string) =>
  invoke<InvitationPreview>('preview_enrollment_invitation', { contents })

/**
 * Generates the keys once the `CA-PQ` fingerprint is confirmed, seals them,
 * and returns the `.helios-request` text to hand to the operator.
 */
export const beginEnrollment = (
  invitation: string,
  confirmedCaFingerprint: string,
  requestedName: string,
) =>
  invoke<string>('begin_enrollment', {
    invitation,
    confirmedCaFingerprint,
    requestedName,
  })

export const listPendingEnrollments = () =>
  invoke<PendingEnrollment[]>('list_pending_enrollments')

/** The `.helios-request` of a pending enrollment, written again. */
export const exportPendingRequest = (requestId: string) =>
  invoke<string>('export_pending_request', { requestId })

/** Abandons a pending enrollment: its private keys are destroyed. */
export const discardPendingEnrollment = (requestId: string) =>
  invoke<void>('discard_pending_enrollment', { requestId })

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
 * no use for. Rust answers from the key plugged into this workstation; `name`
 * is kept for the command's signature and is not used there.
 */
export const certificateApprovalNeedsPin = (name: string) =>
  invoke<boolean>('certificate_approval_needs_pin', { name })

/**
 * Runs the key ceremony in this process and has the engine deposit the assertion.
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
 * This command only returns the line; {@link openSshTerminal} is the one that
 * opens a terminal. Only the engine is elevated, so a shell the UI starts is
 * not an Administrator shell. Rust still owns the gates: the tunnel must be
 * up, and the destination is re-validated before it reaches a clipboard.
 */
export const sshCommand = (name?: string) =>
  invoke<string>('ssh_command', { name: name ?? null })

/**
 * Opens a terminal connected to the gateway, **below** Orion's privileges.
 *
 * The UI runs at its caller's level and only the engine is elevated, so the
 * child inherits a non-elevated token. Rust refuses to launch anything while
 * Windows reports the UI's own token as elevated, or cannot say — then the
 * call fails, and the caller falls back to {@link sshCommand}.
 */
export const openSshTerminal = (name?: string) =>
  invoke<void>('open_ssh_terminal', { name: name ?? null })

export const connect = (name?: string) => invoke<void>('connect', { name: name ?? null })
export const disconnect = () => invoke<void>('disconnect')

/** Renews the ML-KEM PSK now, through the tunnel. */
export const renewPsk = () => invoke<void>('renew_psk')

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

/**
 * Opens an enrollment gesture. La passerelle est lue côté Rust (profil
 * sélectionné et connecté) ; le contenu d'un fichier choisi voyage tel quel.
 */
export const beginEnrollmentCeremony = (gesture: EnrollmentGesture) =>
  invoke<OperatorStatus>('begin_enrollment_ceremony', { gesture })

/** Opens the delegation of Astra's issuer; only the request's text travels. */
export const beginIssuerCeremony = (gesture: IssuerGesture) =>
  invoke<OperatorStatus>('begin_issuer_ceremony', { gesture })

/** Opens a CA rotation gesture; the tunnel and the vault are read on the Rust side. */
export const beginRotationCeremony = (gesture: RotationGesture) =>
  invoke<OperatorStatus>('begin_rotation_ceremony', { gesture })

/** Answers the approval screen, which opens the campaign. */
export const approveRotationCeremony = (terms: RotationTerms, revision: number) =>
  invoke<OperatorStatus>('approve_rotation_ceremony', { terms, revision })

/** Opens a vault or domain gesture; the vault path is read on the Rust side. */
export const beginVaultCeremony = (gesture: VaultGesture) =>
  invoke<OperatorStatus>('begin_vault_ceremony', { gesture })

/** Renames a key. No key is asked anything. */
export const renameOperatorKey = (slotId: string, label: string) =>
  invoke<void>('rename_operator_key', { slotId, label })

/** Records values on the domain relay beside the vault. No key. */
export const writeDomainRelay = (update: RelayUpdate) =>
  invoke<void>('write_domain_relay', { update })

/** Records the connected gateway's identity on the relay, after checking it. */
export const adoptConnectedGateway = () => invoke<void>('adopt_connected_gateway')

/** What the domain creation form starts from. */
export const operatorDomainDefaults = () => invoke<DomainDefaults>('operator_domain_defaults')

/** Where the operator vault is kept. */
export const operatorVaultLocation = () => invoke<VaultLocationView>('operator_vault_location')

/** Opens the folder dialog; `null` when the operator cancels. */
export const chooseVaultLocation = () =>
  invoke<VaultLocationView | null>('choose_vault_location')

/** Goes back to the default vault location. */
export const resetVaultLocation = () => invoke<VaultLocationView>('reset_vault_location')

/** Les fichiers produits par la session courante, que l'IHM enregistre. */
export const operatorArtifacts = () => invoke<OperatorArtifact[]>('operator_artifacts')

export const advanceOperatorCeremony = (action: OperatorAction, revision: number) =>
  invoke<OperatorStatus>('advance_operator_ceremony', { action, revision })

export const dismissOperatorCeremony = () => invoke<void>('dismiss_operator_ceremony')

export const operatorCeremonyStatus = () =>
  invoke<OperatorStatus | null>('operator_ceremony_status')

/** Les invitations de ce poste ; `peer_admitted` vient de la gateway connectée, si elle répond. */
export const operatorInvitations = () => invoke<InvitationView[]>('operator_invitations')

/** Révoque une invitation émise. Aucune clé. */
export const revokeInvitation = (invitationId: string) =>
  invoke<void>('revoke_invitation', { invitationId })

/** The operator vault and its trust domain, read without any key or PIN. */
export const operatorOverview = () => invoke<VaultOverview>('operator_overview')

/** Installs and commits the grant released by the matching §7.5 ceremony. */
export const resumeCertificateRecovery = (operationId: string) =>
  invoke<ActionOutcome>('resume_certificate_recovery', { operationId })

/* Lu sur la gateway, dans le tunnel, sur la surface administrateur : l'origine
 * publique d'Astra sert une récupération sans tunnel, et y placer une liste la
 * rendrait lisible par quiconque l'atteint. */
export const operatorPendingOperations = () =>
  invoke<OperatorPendingOperation[]>('operator_pending_operations')

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
