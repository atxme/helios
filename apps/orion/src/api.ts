// Access layer to the Rust backend via Tauri (invoke) + event stream (listen).
// The connection mounts WireGuard on the Rust side. Only post-tunnel
// telemetry/provisioning then uses Helios's internal HTTP API.

import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import type {
  ClientConfig,
  ClientEvent,
  ClientProfile,
  ImportOutcome,
  KeyNegotiationSupport,
  ProfileIssues,
  TunnelState,
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

/** Is this profile's identity already sealed on this machine? */
export const keyNegotiationIdentitySealed = (profile: ClientProfile) =>
  invoke<boolean>('key_negotiation_identity_sealed', { profile })

/**
 * Reports the faulty fields of a profile being edited.
 *
 * The rules live in `orion-core`: the UI highlights what the core refuses,
 * it doesn't reimplement them.
 */
export const validateProfile = (profile: ClientProfile) =>
  invoke<ProfileIssues>('validate_profile', { profile })

/** Public key derived from the profile: the only half to send to the operator. */
export const profilePublicKey = (profile: ClientProfile) =>
  invoke<string | null>('profile_public_key', { profile })

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
export const keyNegotiationFingerprint = (profile: ClientProfile) =>
  invoke<string | null>('key_negotiation_fingerprint', { profile })

export const saveProfile = (profile: ClientProfile) =>
  invoke<ClientConfig>('save_profile', { profile })
export const deleteProfile = (name: string) =>
  invoke<ClientConfig>('delete_profile', { name })
export const selectProfile = (name: string) =>
  invoke<ClientConfig>('select_profile', { name })

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
