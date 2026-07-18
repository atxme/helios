// Couche d'accès au backend Rust via Tauri (invoke) + flux d'événements (listen).
// La connexion monte WireGuard côté Rust. Seule la télémétrie/provisioning
// post-tunnel utilise ensuite l'API HTTP interne d'Helios.

import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import type { ClientConfig, ClientEvent, ClientProfile, TunnelState } from './types'

export const getState = () => invoke<TunnelState>('get_state')
export const backendKind = () => invoke<string>('backend_kind')
export const adapterIsUp = () => invoke<boolean>('adapter_is_up')
export const getConfig = () => invoke<ClientConfig>('get_config')

export const saveProfile = (profile: ClientProfile) =>
  invoke<ClientConfig>('save_profile', { profile })
export const deleteProfile = (name: string) =>
  invoke<ClientConfig>('delete_profile', { name })
export const selectProfile = (name: string) =>
  invoke<ClientConfig>('select_profile', { name })

export const connect = (name?: string) => invoke<void>('connect', { name: name ?? null })
export const disconnect = () => invoke<void>('disconnect')

/** Abonnement au flux d'événements temps réel du backend. */
export function onEvent(cb: (ev: ClientEvent) => void): Promise<UnlistenFn> {
  return listen<ClientEvent>('helios://event', (e) => cb(e.payload))
}
