export type TunnelState = 'down' | 'connecting' | 'up' | 'rekeying' | 'failed'

export interface ConnectionSummary {
  name: string
  remote_addr: string
  local_id: string | null
  remote_id: string | null
  ike_proposal: string
  esp_proposal: string
}

export interface Status {
  state: TunnelState
  version: string
  wan_iface: string
  lan_ifaces: string[]
  ike_peers: string[]
  connections: ConnectionSummary[]
  dry_run: boolean
}

export type HeliosEvent =
  | { type: 'state_changed'; state: TunnelState }
  | { type: 'log'; level: string; message: string }
  | { type: 'telemetry'; iface: string; rx_bps: number; tx_bps: number; rx_pps: number; tx_pps: number }

export interface TelemetrySample {
  rx_bps: number
  tx_bps: number
  rx_pps: number
  tx_pps: number
}

/** Événements affichés dans le terminal — hors télémétrie (streamée séparément). */
export type DisplayEvent = Exclude<HeliosEvent, { type: 'telemetry' }>
