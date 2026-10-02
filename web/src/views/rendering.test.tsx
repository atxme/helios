// @vitest-environment jsdom

import { ThemeProvider } from '@mui/material/styles'
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { heliosTheme } from '../theme'
import type { PeerSummary, Status, TelemetrySample } from '../types'
import { ClientsView } from './Clients'
import { OverviewView } from './Overview'
import { SecurityView } from './Security'
import { SystemView } from './System'

/**
 * Mounts each destination once, against a status shaped exactly like the
 * daemon's contract — filled, and not yet received.
 *
 * A view is mostly declarative markup, so it typechecks whatever it does with
 * a null status and then throws at runtime on the first `.join` of something
 * that was never an array.
 */

function peer(overrides: Partial<PeerSummary> = {}): PeerSummary {
  return {
    name: 'orion-portable',
    public_key: 'kZ8vQ2nR4tLmXpW7yB3cF6hJ1dS5gA0eU9iO2rT4vNc=',
    address: '100.64.0.12',
    address_v6: null,
    post_quantum: true,
    admin: false,
    minimum_key_negotiation_mode: 'ml_kem',
    last_handshake_age_seconds: 20,
    endpoint: '203.0.113.9:51820',
    rx_bytes: 5_242_880,
    tx_bytes: 1_048_576,
    ...overrides,
  }
}

const STATUS: Status = {
  state: 'up',
  version: '0.1.0',
  wan_ifaces: ['eth0'],
  lan_ifaces: ['eth1'],
  wg_peers: ['site-lyon'],
  allow_ssh_from: ['192.168.1.0/24'],
  peers: [
    peer(),
    peer({
      name: 'orion-mobile',
      public_key: 'aQ7wS2eD5rF8tG1yH4jK7lM0nB3vC6xZ9pO2iU5yT8r=',
      address: '100.64.0.27',
      post_quantum: false,
      minimum_key_negotiation_mode: 'classic',
      last_handshake_age_seconds: 4_000,
      rx_bytes: 131_072,
      tx_bytes: 65_536,
    }),
  ],
  wg_iface: 'helios0',
  wg_listen_port: 51820,
  key_negotiation_port: 51821,
  dry_run: false,
  split_tunnel_cidrs: ['10.0.0.0/8'],
  mss_clamp: 1380,
  captive_portal_gateway: null,
  handshake_stale_after_seconds: 150,
  ipv6: 'not_configured',
}

const SAMPLES: TelemetrySample[] = Array.from({ length: 10 }, (_, index) => ({
  rx_bps: 1_000 * index,
  tx_bps: 500 * index,
  rx_pps: 10 * index,
  tx_pps: 5 * index,
}))

function mount(ui: React.ReactNode) {
  return render(<ThemeProvider theme={heliosTheme}>{ui}</ThemeProvider>)
}

const noop = () => Promise.resolve()

let fetchMock: ReturnType<typeof vi.fn>

beforeEach(() => {
  fetchMock = vi.fn((input: string) => {
    // Security mounts the lifecycle panel, which reads the trust domain. A
    // gateway with none answers 404, and the panel says so — which is what
    // this harness wants: the destination must mount without a registry.
    if (input.includes('/api/certificates')) {
      return Promise.resolve(new Response('{}', { status: 404 }))
    }
    const body = input.includes('/trust')
      ? {
          required_algs: ['ed25519', 'ml-dsa-65'],
          publisher_keys: [{ key_epoch: 3, fingerprint: 'ab'.repeat(16) }],
          development_keys: true,
          reseal_domain: 'helios.reseal.v2',
          reseal_format_version: 2,
        }
      : input.includes('/health')
        ? {
            uptime_seconds: 90_000,
            load: [0.42, 0.51, 0.48],
            cpu_count: 4,
            memory_total_bytes: 8_589_934_592,
            memory_available_bytes: 5_368_709_120,
            temperature_celsius: 47.5,
            tpm: { kind: 'unsealed', preserved_vaults: true },
          }
      : input.includes('/update')
        ? {
            highest_confirmed_sequence: 42,
            active_version: '0.1.0',
            staged: [],
            activation_pending: null,
            channel: 'stable',
            target: 'x86_64-unknown-linux-gnu',
          }
        : { ok: true }
    return Promise.resolve(new Response(JSON.stringify(body), { status: 200 }))
  })
  vi.stubGlobal('fetch', fetchMock)
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe('Overview', () => {
  it('leads with the tunnel state and counts who is actually online', () => {
    mount(
      <OverviewView
        status={STATUS}
        currentState="up"
        error={null}
        events={[{ type: 'log', level: 'info', message: 'démarrage', ts: '09:00:00' }]}
        telemetry={SAMPLES}
        tunnelUpSince={new Date(Date.now() - 65_000)}
        connect={noop}
        disconnect={noop}
        releaseCaptivePortal={noop}
      />,
    )

    expect(screen.getByText('Handshake actif')).toBeTruthy()
    expect(screen.getByText('00:01:05')).toBeTruthy()
    // One peer handshaked 20 s ago, the other 4 000 s ago — only the first is
    // within the daemon's 150 s threshold.
    expect(screen.getByText('1 / 2')).toBeTruthy()
  })

  it('survives a status the daemon has not sent yet', () => {
    expect(() =>
      mount(
        <OverviewView
          status={null}
          currentState="down"
          error={null}
          events={[]}
          telemetry={[]}
          tunnelUpSince={null}
          connect={noop}
          disconnect={noop}
          releaseCaptivePortal={noop}
        />,
      ),
    ).not.toThrow()
  })
})

describe('Clients', () => {
  it('separates a connected client from one that is merely admitted', () => {
    mount(
      <ClientsView status={STATUS} refresh={noop} admitOpen={false} onAdmitOpenChange={vi.fn()} />,
    )

    expect(screen.getByText('orion-portable')).toBeTruthy()
    expect(screen.getByText('il y a 20 s')).toBeTruthy()
    expect(screen.getByText('il y a 1 h')).toBeTruthy()
    expect(screen.getByText('5.0 Mio')).toBeTruthy()
  })

  it('shows the negotiation floor of every client', () => {
    mount(
      <ClientsView status={STATUS} refresh={noop} admitOpen={false} onAdmitOpenChange={vi.fn()} />,
    )

    expect(screen.getByText('ML-KEM-1024')).toBeTruthy()
    expect(screen.getByText('aucun')).toBeTruthy()
  })

  it('admits a client without asking for an address', async () => {
    const refresh = vi.fn(noop)
    mount(
      <ClientsView status={STATUS} refresh={refresh} admitOpen onAdmitOpenChange={vi.fn()} />,
    )

    // The VIP is derived by the gateway from the public key: offering the
    // operator an address field would invite a collision the IPAM exists to
    // prevent.
    expect(screen.queryByLabelText(/adresse/i)).toBeNull()

    fireEvent.change(screen.getByLabelText('Nom'), { target: { value: 'poste-atelier' } })
    fireEvent.change(screen.getByLabelText('Clé publique WireGuard'), {
      target: { value: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=' },
    })

    // Both identities, or the admission layer refuses the peer outright: the
    // button stays disabled until each one is there.
    expect(screen.getByRole('button', { name: 'Admettre' }).hasAttribute('disabled')).toBe(true)
    fireEvent.change(screen.getByLabelText('Empreinte du certificat TLS du client'), {
      target: { value: 'aa'.repeat(32) },
    })
    fireEvent.change(screen.getByLabelText('Empreinte du certificat PQ du client'), {
      target: { value: 'bb'.repeat(32) },
    })

    fireEvent.click(screen.getByRole('button', { name: 'Admettre' }))

    await waitFor(() => expect(refresh).toHaveBeenCalled())
    const [url, init] = fetchMock.mock.calls.at(-1)!
    expect(url).toBe('/api/peers')
    expect(JSON.parse((init as RequestInit).body as string)).toMatchObject({
      name: 'poste-atelier',
      public_key: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=',
      admin: false,
      key_negotiation_certificate_sha256: 'aa'.repeat(32),
      key_negotiation_pq_certificate_sha256: 'bb'.repeat(32),
    })
  })

  it('asks before revoking, and names the client it is about to drop', async () => {
    const refresh = vi.fn(noop)
    mount(
      <ClientsView status={STATUS} refresh={refresh} admitOpen={false} onAdmitOpenChange={vi.fn()} />,
    )

    fireEvent.click(screen.getByRole('button', { name: 'Révoquer orion-portable' }))
    expect(screen.getByText('Révoquer orion-portable ?')).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: 'Révoquer' }))
    await waitFor(() => expect(refresh).toHaveBeenCalled())
    const [url, init] = fetchMock.mock.calls.at(-1)!
    expect(url).toBe('/api/peers/revoke')
    expect(JSON.parse((init as RequestInit).body as string)).toEqual({ name: 'orion-portable' })
  })

  it('leaves the traffic columns empty rather than showing zeros as measurements', () => {
    mount(
      <ClientsView
        status={{ ...STATUS, peers: [peer({ rx_bytes: null, tx_bytes: null, last_handshake_age_seconds: null })] }}
        refresh={noop}
        admitOpen={false}
        onAdmitOpenChange={vi.fn()}
      />,
    )

    expect(screen.getByText('jamais')).toBeTruthy()
    expect(screen.getAllByText('—').length).toBeGreaterThan(0)
  })
})

describe('Security', () => {
  it('reports the kill-switch as a consequence of the tunnel state', () => {
    mount(<SecurityView status={STATUS} state="up" />)
    expect(screen.getByText('Kill-switch levé')).toBeTruthy()

    cleanup()
    mount(<SecurityView status={STATUS} state="failed" />)
    expect(screen.getByText('Kill-switch engagé')).toBeTruthy()
  })

  it('warns that a development keyring is compiled into this binary', async () => {
    mount(<SecurityView status={STATUS} state="up" />)

    await waitFor(() =>
      expect(screen.getByText(/Trousseau de développement compilé/)).toBeTruthy(),
    )
  })

  it('no longer offers a firewall editor that applies nothing', () => {
    mount(<SecurityView status={STATUS} state="up" />)
    expect(screen.queryByText(/Transmettre/)).toBeNull()
  })
})

describe('System', () => {
  it('renders the configuration, the update panel and the log', async () => {
    mount(<SystemView status={STATUS} events={[]} onSplitTunnelChange={noop} />)

    expect(screen.getByDisplayValue('10.0.0.0/8')).toBeTruthy()
    expect(screen.getByText('Mise à jour')).toBeTruthy()
    await waitFor(() => expect(screen.getByText('stable')).toBeTruthy())
  })

  it('reports the health of the machine and its sealing posture', async () => {
    mount(<SystemView status={STATUS} events={[]} onSplitTunnelChange={noop} />)

    await waitFor(() => expect(screen.getByText('1 j 1 h')).toBeTruthy())
    expect(screen.getByText('47.5 °C')).toBeTruthy()
    expect(screen.getByText('Descellement nominal')).toBeTruthy()
    // MemAvailable, not MemFree: 8 GiB total, 5 GiB available -> 3 GiB used.
    expect(screen.getByText('3.0 Gio / 8.0 Gio')).toBeTruthy()
  })

  it('warns loudly when a boot no longer opens the sealed vaults', async () => {
    fetchMock.mockImplementation((input: string) =>
      Promise.resolve(
        new Response(
          JSON.stringify(
            input.includes('/health')
              ? {
                  uptime_seconds: 100,
                  load: null,
                  cpu_count: 2,
                  memory_total_bytes: null,
                  memory_available_bytes: null,
                  temperature_celsius: null,
                  tpm: { kind: 'resealed', preserved_vaults: false },
                }
              : { ok: true },
          ),
          { status: 200 },
        ),
      ),
    )

    mount(<SystemView status={STATUS} events={[]} onSplitTunnelChange={noop} />)

    await waitFor(() =>
      expect(screen.getByText(/coffres scellés ne s’ouvrent plus/)).toBeTruthy(),
    )
    // A kernel publishing no thermal zone must not take the other readings down.
    expect(screen.getByText('non relevée')).toBeTruthy()
  })

  it('survives a status the daemon has not sent yet', () => {
    expect(() =>
      mount(<SystemView status={null} events={[]} onSplitTunnelChange={noop} />),
    ).not.toThrow()
  })

  it('says discreetly that IPv6 is not configured, and raises no warning', () => {
    mount(<SystemView status={STATUS} events={[]} onSplitTunnelChange={noop} />)

    expect(screen.getByText('IPv6 tunnel')).toBeTruthy()
    expect(screen.getByText('non configurée')).toBeTruthy()
    expect(screen.queryByText(/IPv6 indisponible/)).toBeNull()
  })

  it('reports an installed IPv6 tunnel', () => {
    mount(<SystemView status={{ ...STATUS, ipv6: 'installed' }} events={[]} onSplitTunnelChange={noop} />)

    expect(screen.getByText('installée')).toBeTruthy()
    expect(screen.queryByText(/IPv6 indisponible/)).toBeNull()
  })

  it('makes the degraded IPv4-only start visible, with the reason in French', () => {
    mount(
      <SystemView
        status={{
          ...STATUS,
          ipv6: { unavailable: { reason: 'tunnel_mtu_too_small', tunnel_mtu: 1200, minimum: 1280 } },
        }}
        events={[]}
        onSplitTunnelChange={noop}
      />,
    )

    expect(screen.getByText('indisponible')).toBeTruthy()
    expect(screen.getByText('IPv6 indisponible — passerelle en IPv4 seule')).toBeTruthy()
    expect(screen.getByText(/Le MTU du tunnel \(1200 octets\) est inférieur aux 1280 octets/)).toBeTruthy()
  })

  it('keeps the warning for a reason this console does not know', () => {
    mount(
      <SystemView
        status={{
          ...STATUS,
          ipv6: { unavailable: { reason: 'firmware_said_no' } } as unknown as Status['ipv6'],
        }}
        events={[]}
        onSplitTunnelChange={noop}
      />,
    )

    expect(screen.getByText('IPv6 indisponible — passerelle en IPv4 seule')).toBeTruthy()
    expect(screen.getByText(/Raison non reconnue par cette interface/)).toBeTruthy()
  })
})
