// Types miroir des structures Rust (orion-core) sérialisées via Tauri.
// Aligné sur web/src/types.ts pour la partie état/télémétrie partagée avec heliosd.

export type TunnelState =
  | 'down'
  | 'connecting'
  | 'up'
  | 'rekeying'
  | 'failed'
  | 'captive_portal'

export type AuthConfig =
  | { method: 'psk'; secret: string }
  | { method: 'cert'; cert_path: string; key_path: string }
  | { method: 'eap'; username: string; password: string }

export interface ClientProfile {
  name: string
  gateway: string
  local_id: string | null
  remote_id: string | null
  auth: AuthConfig
  profile_id: string | null
  ike_proposal: string | null
  esp_proposal: string | null
  heliosd_url: string | null
}

export interface ClientConfig {
  profiles: ClientProfile[]
  selected: string | null
}

export interface PredefinedProfile {
  id: string
  name: string
  description: string
  pqc_level: string
  reserved: boolean
  ike_proposal: string
  esp_proposal: string
}

// Événements poussés par le backend Rust (emit "helios://event").
export type ClientEvent =
  | { type: 'state_changed'; state: TunnelState }
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
