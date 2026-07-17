// Couche d'accès au backend Rust via Tauri (invoke) + flux d'événements (listen).
// Aucune requête HTTP ici : se connecter = monter l'IPsec côté Rust.

import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import type { ClientConfig, ClientEvent, ClientProfile, PredefinedProfile, TunnelState } from './types'

export const getState = () => invoke<TunnelState>('get_state')
export const backendKind = () => invoke<string>('backend_kind')
export const getConfig = () => invoke<ClientConfig>('get_config')
export const listPredefined = () => invoke<PredefinedProfile[]>('list_predefined')

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
