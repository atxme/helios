// Types miroir des structures Rust (orion-core) sérialisées via Tauri.
// Aligné sur web/src/types.ts pour la partie état/télémétrie partagée avec heliosd.

// Modèle WireGuard (ADR-001). `rekeying` a disparu : WireGuard rekeye de façon
// transparente, il n'y a pas d'état observable. `up` est *inféré* d'un handshake
// récent (< 150 s), pas reçu comme événement.
export type TunnelState =
  | 'down'
  | 'connecting'
  | 'up'
  | 'failed'
  | 'captive_portal'

// Un pair WireGuard : identité = clé publique Curve25519, joint par un endpoint
// UDP. Ni CA, ni EAP, ni proposition cryptographique — WireGuard n'a qu'une suite.
export interface ClientProfile {
  name: string
  /** Endpoint UDP de la gateway : `IP:port` ou `FQDN:port`. */
  endpoint: string
  /** Clé privée Curve25519 du client (base64). Secret. */
  private_key: string
  /** Clé publique Curve25519 de la gateway (base64). */
  peer_public_key: string
  /**
   * PSK **statique** partagé hors bande (base64). Secret.
   *
   * Le PSK PQC issu de ML-KEM n'atterrit jamais ici : il n'est pas persisté et
   * se renégocie à chaque connexion. `null` est donc le cas normal d'un profil
   * Helios — voir `PskKind`.
   */
  preshared_key: string | null
  /** VIP CGNAT assignée par la gateway à l'enrôlement (ex. `100.64.1.2/32`). */
  address: string | null
  /** Trafic routé dans le tunnel. Défaut `0.0.0.0/0`. */
  allowed_ips: string
  /** Keepalive en secondes. Défaut 25. */
  persistent_keepalive: number
  heliosd_url: string | null
}

export interface ClientConfig {
  profiles: ClientProfile[]
  selected: string | null
}

/**
 * Champs fautifs d'un profil, relevés par `orion-core::inspect_profile`.
 *
 * `null` = rien à signaler. Un champ vide n'est jamais signalé : pendant la
 * saisie, « pas encore rempli » n'est pas « impossible ».
 */
export interface ProfileIssues {
  name: string | null
  endpoint: string | null
  private_key: string | null
  peer_public_key: string | null
  preshared_key: string | null
  address: string | null
  allowed_ips: string | null
  persistent_keepalive: string | null
  heliosd_url: string | null
}

/**
 * Ce qui occupe le slot `PresharedKey` du tunnel courant — miroir de
 * `orion_core::events::PskKind`.
 *
 * Un PSK n'est pas un PSK PQC : les deux vivent dans le même slot WireGuard,
 * mais l'un a été recopié à la main et ne tourne jamais, l'autre vient d'un
 * échange ML-KEM-768 rejoué à chaque connexion. Le profil ne permet pas de les
 * distinguer, puisque le second n'est jamais persisté — seul le cœur client
 * sait lequel il a posé.
 */
export type PskKind = 'none' | 'static' | 'ml_kem'

// Événements poussés par le backend Rust (emit "helios://event").
export type ClientEvent =
  | { type: 'state_changed'; state: TunnelState }
  | { type: 'protection'; psk: PskKind }
  | { type: 'log'; level: string; message: string }
  | { type: 'telemetry'; iface: string; rx_bps: number; tx_bps: number; rx_pps: number; tx_pps: number }
  | { type: 'error'; message: string }

export interface LogLine {
  level: string
  message: string
  ts: string
}

export interface TelemetrySample {
  rx_bps: number
  tx_bps: number
}
