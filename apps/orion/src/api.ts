// Couche d'accès au backend Rust via Tauri (invoke) + flux d'événements (listen).
// La connexion monte WireGuard côté Rust. Seule la télémétrie/provisioning
// post-tunnel utilise ensuite l'API HTTP interne d'Helios.

import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'
import type {
  ClientConfig,
  ClientEvent,
  ClientProfile,
  ProfileIssues,
  TunnelState,
} from './types'

export const getState = () => invoke<TunnelState>('get_state')
export const backendKind = () => invoke<string>('backend_kind')
export const adapterIsUp = () => invoke<boolean>('adapter_is_up')
export const getConfig = () => invoke<ClientConfig>('get_config')
export const importProfile = (contents: string, fileName: string) =>
  invoke<ClientProfile>('import_profile', { contents, fileName })
export const importProfilePath = (path?: string) =>
  invoke<ClientProfile | null>('import_profile_path', { path: path ?? null })

/**
 * Relève les champs fautifs d'un profil en cours d'édition.
 *
 * Les règles vivent dans `orion-core` : l'IHM surligne ce que le cœur refuse,
 * elle ne les réimplémente pas.
 */
export const validateProfile = (profile: ClientProfile) =>
  invoke<ProfileIssues>('validate_profile', { profile })

/** Clé publique dérivée du profil : la seule moitié à communiquer à l'opérateur. */
export const profilePublicKey = (profile: ClientProfile) =>
  invoke<string | null>('profile_public_key', { profile })

export const saveProfile = (profile: ClientProfile) =>
  invoke<ClientConfig>('save_profile', { profile })
export const deleteProfile = (name: string) =>
  invoke<ClientConfig>('delete_profile', { name })
export const selectProfile = (name: string) =>
  invoke<ClientConfig>('select_profile', { name })

export const connect = (name?: string) => invoke<void>('connect', { name: name ?? null })
export const disconnect = () => invoke<void>('disconnect')

/**
 * Ajuste la fenêtre à la vue affichée.
 *
 * Les dimensions sont décidées côté Rust : le frontend nomme la vue, il ne
 * dimensionne rien lui-même.
 */
export const resizeForView = (view: string) => invoke<void>('resize_for_view', { view })

/**
 * Écrit le journal sur disque et renvoie le chemin obtenu.
 *
 * `stem` n'est qu'un libellé : le frontend le propose parce qu'il connaît
 * l'heure locale, mais Rust l'assainit et choisit seul le répertoire.
 */
export const exportLogs = (stem: string, contents: string) =>
  invoke<string>('export_logs', { stem, contents })

/** Abonnement au flux d'événements temps réel du backend. */
export function onEvent(cb: (ev: ClientEvent) => void): Promise<UnlistenFn> {
  return listen<ClientEvent>('helios://event', (e) => cb(e.payload))
}

/** Un double-clic a ajouté un chemin à la file Rust d'import. */
export function onProfilePath(cb: () => void): Promise<UnlistenFn> {
  return listen('helios://profile-path', cb)
}
