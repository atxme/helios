// Access layer to the Rust backend via Tauri (invoke) + event stream (listen).
// The connection mounts WireGuard on the Rust side. Only post-tunnel
// telemetry/provisioning then uses Helios's internal HTTP API.

import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import type {
  ClientConfig,
  ClientEvent,
  ImportOutcome,
  KeyNegotiationSettings,
  KeyNegotiationSupport,
  ProfileDraft,
  ProfileIssues,
  TunnelState,
  VaultPosture,
} from './types'

export const getState = () => invoke<TunnelState>('get_state')
export const backendKind = () => invoke<string>('backend_kind')
export const adapterIsUp = () => invoke<boolean>('adapter_is_up')
export const getConfig = () => invoke<ClientConfig>('get_config')

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
 * Is this profile's identity already sealed on this machine?
 *
 * Takes the negotiation block alone, not the profile: the answer depends on one
 * field, and passing the whole profile would have meant shipping its secrets
 * across the IPC to read it.
 */
export const keyNegotiationIdentitySealed = (
  keyNegotiation: KeyNegotiationSettings | null,
) => invoke<boolean>('key_negotiation_identity_sealed', { keyNegotiation })

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
 * Fingerprint of the gateway PQ certificate pinned by the profile.
 *
 * Read out loud against what the gateway printed, it is what proves the
 * imported material comes from the right gateway.
 */
export const keyNegotiationFingerprint = (
  keyNegotiation: KeyNegotiationSettings | null,
) => invoke<string | null>('key_negotiation_fingerprint', { keyNegotiation })

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

/** A tray action selected while the main window was hidden. */
export function onTrayView(
  cb: (view: 'connect' | 'profiles' | 'logs') => void,
): Promise<UnlistenFn> {
  return listen<string>('helios://tray-view', (event) => {
    if (event.payload === 'connect' || event.payload === 'profiles' || event.payload === 'logs') {
      cb(event.payload)
    }
  })
}

/**
 * Reads the vault's posture.
 *
 * Asked on every panel opening rather than cached: BitLocker can be suspended
 * and the memory-lock privilege can change while Orion runs, so a value read
 * once at startup would eventually claim a protection that has since gone.
 */
export const vaultPosture = () => invoke<VaultPosture>('vault_posture')
