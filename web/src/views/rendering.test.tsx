// @vitest-environment jsdom

import { ThemeProvider } from '@mui/material/styles'
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { heliosTheme } from '../theme'
import type { Status, TelemetrySample } from '../types'
import { DashboardView } from './Dashboard'
import { FirewallView } from './Firewall'
import { SettingsView } from './Settings'
import { TelemetryView } from './Telemetry'
import { TrustView } from './Trust'
import { UpdateView } from './Update'
import { WireGuardView } from './WireGuard'

/**
 * Mounts every view once.
 *
 * A view is mostly declarative markup, so it typechecks whatever it does with
 * a null status or an empty list — and then throws at runtime on the first
 * `.join` of something that was never an array. These are cheap smoke tests
 * whose real job is to be run against a status object shaped exactly like the
 * daemon's contract, in both of its shapes: filled, and not yet received.
 */

const STATUS: Status = {
  state: 'up',
  version: '0.1.0',
  wan_iface: 'eth0',
  lan_ifaces: ['eth1', 'eth2'],
  wg_peers: ['site-b'],
  allow_ssh_from: ['192.168.1.0/24'],
  peers: [
    {
      name: 'orion-portable',
      public_key: 'Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWo=',
      address: '100.64.0.12',
      post_quantum: true,
      admin: false,
      minimum_key_negotiation_mode: 'ml_kem',
    },
    {
      name: 'orion-bureau',
      public_key: 'YmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbA==',
      address: '100.64.0.19',
      post_quantum: false,
      admin: true,
      minimum_key_negotiation_mode: 'classic',
    },
  ],
  wg_iface: 'helios0',
  wg_listen_port: 51820,
  key_negotiation_port: 51821,
  dry_run: false,
  split_tunnel_cidrs: ['10.0.0.0/8'],
  mss_clamp: 1380,
  captive_portal_gateway: null,
}

const SAMPLES: TelemetrySample[] = Array.from({ length: 12 }, (_, index) => ({
  rx_bps: 1_000 * index,
  tx_bps: 500 * index,
  rx_pps: 10 * index,
  tx_pps: 5 * index,
}))

function mount(ui: React.ReactNode) {
  return render(<ThemeProvider theme={heliosTheme}>{ui}</ThemeProvider>)
}

function jsonResponse(body: unknown) {
  return new Response(JSON.stringify(body), { status: 200 })
}

beforeEach(() => {
  // Views that fetch on mount: firewall rules, trust anchor, update status.
  vi.stubGlobal(
    'fetch',
    vi.fn((input: string) => {
      if (input.includes('/api/firewall')) {
        return Promise.resolve(jsonResponse({ rules: 'table inet helios {}', default_verdict: 'drop', dry_run: false }))
      }
      if (input.includes('/api/trust')) {
        return Promise.resolve(
          jsonResponse({
            required_algs: ['ed25519', 'ml-dsa-65'],
            publisher_keys: [{ key_epoch: 1, fingerprint: 'a'.repeat(32) }],
            development_keys: true,
            reseal_domain: 'helios.reseal.v2',
            reseal_format_version: 2,
          }),
        )
      }
      if (input.includes('/api/update')) {
        return Promise.resolve(
          jsonResponse({
            highest_confirmed_sequence: 7,
            active_version: '0.1.0',
            staged: [],
            activation_pending: null,
            channel: 'stable',
            target: 'x86_64-unknown-linux-gnu',
          }),
        )
      }
      return Promise.resolve(jsonResponse({}))
    }),
  )
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

const noop = () => Promise.resolve()

describe('views render with a full status', () => {
  it('dashboard', () => {
    mount(
      <DashboardView
        status={STATUS}
        currentState="up"
        error={null}
        events={[{ type: 'log', level: 'info', message: 'démarrage', ts: '09:00:00' }]}
        tunnelUpSince={new Date(Date.now() - 65_000)}
        connect={noop}
        disconnect={noop}
        releaseCaptivePortal={noop}
      />,
    )

    expect(screen.getByText('Handshake actif')).toBeTruthy()
    expect(screen.getByText('00:01:05')).toBeTruthy()
    expect(screen.getByText('helios0')).toBeTruthy()
  })

  it('telemetry', () => {
    mount(<TelemetryView samples={SAMPLES} status={STATUS} />)
    expect(screen.getByText('Rx entrant')).toBeTruthy()
    expect(screen.getByText(/CPU, mémoire et température/)).toBeTruthy()
  })

  it('wireguard, with each peer and its floor', () => {
    mount(<WireGuardView status={STATUS} />)

    expect(screen.getByText('orion-portable')).toBeTruthy()
    expect(screen.getByText('plancher : ML-KEM-1024')).toBeTruthy()
    expect(screen.getByText('plancher : aucun')).toBeTruthy()
    expect(screen.getByText('slot PSK occupé')).toBeTruthy()
    expect(screen.getByText('slot PSK vide')).toBeTruthy()
  })

  it('firewall', async () => {
    mount(<FirewallView status={STATUS} state="up" />)

    expect(screen.getByText('Kill-switch levé')).toBeTruthy()
    // The documented limits this view is required to state.
    expect(screen.getByText(/DNS d’un client ne passe pas par le tunnel/)).toBeTruthy()
    await waitFor(() => expect(screen.getByDisplayValue('table inet helios {}')).toBeTruthy())
  })

  it('trust, and it shouts about a development keyring', async () => {
    mount(<TrustView />)

    await waitFor(() =>
      expect(screen.getByText(/Trousseau de développement compilé/)).toBeTruthy(),
    )
    expect(screen.getByText('ML-DSA-65')).toBeTruthy()
  })

  it('update', async () => {
    mount(<UpdateView />)
    await waitFor(() => expect(screen.getByText('stable')).toBeTruthy())
    expect(screen.getByText('Transférer une release signée')).toBeTruthy()
  })

  it('settings', () => {
    mount(<SettingsView status={STATUS} onSplitTunnelChange={() => Promise.resolve()} />)

    expect(screen.getByDisplayValue('10.0.0.0/8')).toBeTruthy()
    expect(screen.getByText('1380')).toBeTruthy()
  })
})

describe('views render before the daemon has answered', () => {
  it('dashboard, firewall, wireguard and settings tolerate a null status', () => {
    expect(() =>
      mount(
        <DashboardView
          status={null}
          currentState="down"
          error={null}
          events={[]}
          tunnelUpSince={null}
          connect={noop}
          disconnect={noop}
          releaseCaptivePortal={noop}
        />,
      ),
    ).not.toThrow()

    expect(() => mount(<FirewallView status={null} state="down" />)).not.toThrow()
    expect(() => mount(<WireGuardView status={null} />)).not.toThrow()
    expect(() =>
      mount(<SettingsView status={null} onSplitTunnelChange={() => Promise.resolve()} />),
    ).not.toThrow()
    expect(() => mount(<TelemetryView samples={[]} status={null} />)).not.toThrow()
  })

  it('shows a peer count of zero rather than an empty screen', () => {
    mount(<WireGuardView status={{ ...STATUS, peers: [] }} />)
    expect(screen.getByText('Clients admis (0)')).toBeTruthy()
    expect(screen.getByText(/Aucun pair déclaré/)).toBeTruthy()
  })
})
