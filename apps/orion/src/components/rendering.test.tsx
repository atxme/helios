// @vitest-environment jsdom

import { cleanup, render } from '@testing-library/react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'

import App from '../App'
import type { CaptureCheck, ClientProfile, LogLine, TunnelState, VaultPosture } from '../types'
import { ConnectView } from '../views/ConnectView'
import { ProfilesView } from '../views/ProfilesView'
import { CopyButton } from './CopyButton'
import { EventLog } from './EventLog'
import { OrionMark } from './OrionMark'
import { PosturePanel } from './PosturePanel'
import { Sparkline } from './Sparkline'
import { StatusOrb } from './StatusOrb'

const profile = (overrides: Partial<ClientProfile> = {}): ClientProfile => ({
  name: 'portable',
  endpoint: '203.0.113.10:51820',
  peer_public_key: 'gateway-public',
  profile_type: 'classic',
  public_key: 'client-public',
  has_private_key: true,
  has_static_psk: false,
  address: '100.64.1.2/32',
  address_v6: null,
  allowed_ips: '0.0.0.0/0, ::/0',
  ipv6_uncaptured_full_tunnel: false,
  persistent_keepalive: 25,
  heliosd_url: 'http://100.64.0.1:8080',
  ssh_target: null,
  key_negotiation: null,
  ...overrides,
})

function postureHtml(
  selected: ClientProfile,
  vault: VaultPosture | null,
  capture: CaptureCheck | null = null,
): string {
  const anchor = document.createElement('button')
  document.body.append(anchor)
  render(
    <PosturePanel
      anchor={anchor}
      onClose={vi.fn()}
      state="up"
      adapterUp
      profile={selected}
      psk="ml_kem"
      capture={capture}
      vault={vault}
    />,
  )
  const html = document.body.innerHTML
  cleanup()
  anchor.remove()
  return html
}

describe('Orion presentational branches', () => {
  it('renders both logo variants and both sparkline states', () => {
    const titled = renderToStaticMarkup(<OrionMark title="Orion" />)
    expect(titled).toContain('<title>Orion</title>')
    expect(titled).toContain('<ellipse')

    const compact = renderToStaticMarkup(<OrionMark compact />)
    expect(compact).not.toContain('<ellipse')
    expect(compact).toContain('aria-hidden="true"')

    expect(
      renderToStaticMarkup(<Sparkline points={[]} ceiling={0} color="#123" label="Réception" />),
    ).toContain('mesure en cours')
    const graph = renderToStaticMarkup(
      <Sparkline points={[0, 50, 200]} ceiling={100} color="#123" height={20} label="Réception / s" />,
    )
    expect(graph).toContain('<polyline')
    expect(graph).toContain('spark-Rceptions')
  })

  it('renders every tunnel posture in the status instrument', () => {
    for (const state of ['down', 'connecting', 'captive_portal', 'failed', 'up'] as TunnelState[]) {
      const html = renderToStaticMarkup(
        <StatusOrb state={state} adapterUp={state !== 'down'} size={120} />,
      )
      expect(html).toContain('role="img"')
    }
    expect(renderToStaticMarkup(<StatusOrb state="up" adapterUp />)).toContain('Protégé')
  })

  it('renders empty and populated logs, including an unknown level', () => {
    expect(renderToStaticMarkup(<EventLog logs={[]} />)).toContain('Aucun événement')
    const logs: LogLine[] = [
      { ts: '10:00:00', level: 'error', message: 'failure' },
      { ts: '10:00:01', level: 'warn', message: 'warning' },
      { ts: '10:00:02', level: 'debug', message: 'detail' },
    ]
    const html = renderToStaticMarkup(<EventLog logs={logs} />)
    expect(html).toContain('failure')
    expect(html).toContain('warning')
    expect(html).toContain('detail')
    expect(renderToStaticMarkup(<CopyButton value="public" label="la clé" />)).toContain(
      'Copier la clé',
    )
  })

  it('renders connection decisions for missing, incomplete, blocked and active profiles', () => {
    const callback = vi.fn()
    const render = (
      state: TunnelState,
      selected: ClientProfile | null,
      history = [] as { rx_bps: number; tx_bps: number }[],
      adapterUp = state !== 'down',
      renewing = false,
    ) =>
      renderToStaticMarkup(
        <ConnectView
          state={state}
          profile={selected}
          upSince={state === 'up' ? 0 : null}
          telemetry={history[history.length - 1] ?? null}
          history={history}
          adapterUp={adapterUp}
          psk={state === 'up' ? 'ml_kem' : null}
          renewing={renewing}
          onConnect={callback}
          onOpenSsh={callback}
          onRenewKey={callback}
          onDisconnect={callback}
        />,
      )

    expect(render('down', null)).toContain('aucun profil sélectionné')
    expect(render('down', profile({ has_private_key: false }))).toContain('Profil incomplet')
    expect(render('failed', profile())).toContain('Trafic bloqué')
    expect(render('connecting', profile())).toContain('Annuler et démonter')

    // A lost session ends on `down` with the adapter still mounted: the screen
    // states a disconnection, and must keep the one gesture that removes the
    // adapter — nothing on the machine reaches the network until it goes.
    const lost = render('down', profile(), [], true)
    expect(lost).toContain('Déconnecté')
    expect(lost).toContain('Démonter l’adaptateur WireGuard')
    // Nothing mounted, nothing to unmount: the button would name a gesture
    // with no object.
    expect(render('down', profile())).not.toContain('Démonter l’adaptateur')
    const active = render('up', profile(), [
      { rx_bps: 1000, tx_bps: 500 },
      { rx_bps: 2000, tx_bps: 750 },
    ])
    expect(active).toContain('Débit du tunnel')
    expect(active).toContain('100.64.1.2/32')
    expect(active).toContain('Renouveler la clé post-quantique')
    expect(render('connecting', profile())).not.toContain('Renouveler la clé post-quantique')
    expect(render('down', profile())).not.toContain('Renouveler la clé post-quantique')
    // A renewal in flight is never offered a second one: the action stays in
    // place, disabled, and says what it is waiting for.
    const renewing = render('up', profile(), [], true, true)
    expect(renewing).not.toContain('Renouveler la clé post-quantique')
    expect(renewing).toMatch(/<button[^>]*disabled=""[^>]*>(?:(?!<\/button>).)*Renouvellement en cours/)
  })

  it('renders the profile master-detail entry points without invoking effects', () => {
    const callbacks = {
      onPathImportHandled: vi.fn(),
      onImport: vi.fn(),
      onSave: vi.fn(),
      onDelete: vi.fn(),
      onSelect: vi.fn(),
    }
    const empty = renderToStaticMarkup(
      <ProfilesView config={{ profiles: [], selected: null }} pathImport={null} {...callbacks} />,
    )
    expect(empty).toContain('Profils')

    const populated = renderToStaticMarkup(
      <ProfilesView
        config={{ profiles: [profile()], selected: 'portable' }}
        pathImport={profile({ name: 'imported' })}
        {...callbacks}
      />,
    )
    expect(populated).toContain('portable')
  })

  it('renders the posture facts hidden behind the closed popover', () => {
    const negotiated = profile({
      allowed_ips: '100.64.0.0/10',
      key_negotiation: {
        mode: 'ml_kem',
        minimum_mode: 'static_psk',
        endpoint: '203.0.113.10:51821',
        server_name: 'gateway.example',
        gateway_ca_der: 'ca',
        gateway_pq_certificate: 'pq',
        identity: 'portable',
      },
    })
    const html = postureHtml(negotiated, null)

    expect(html).toContain('203.0.113.10:51821')
    expect(html).toContain('100.64.0.0/10')
    // A narrowed range is the operator's decision: stated, not warned about.
    expect(html).not.toContain('IPv6 sort en clair')
  })

  /// The full tunnel stored before `::/0` joined the default leaks IPv6 with
  /// the tunnel up. The core's verdict decides the row, not the panel.
  it('warns in amber on a full tunnel that leaves IPv6 out', () => {
    const legacy = postureHtml(
      profile({ allowed_ips: '0.0.0.0/0', ipv6_uncaptured_full_tunnel: true }),
      null,
    )
    expect(legacy).toContain('0.0.0.0/0 — IPv4 seulement, l’IPv6 sort en clair')
    expect(legacy).toContain('rgb(161, 98, 7)')

    const dual = postureHtml(profile(), null)
    expect(dual).toContain('0.0.0.0/0, ::/0')
    expect(dual).not.toContain('IPv6 sort en clair')
  })

  /// The driver may apply less than the profile asks — on Windows, `::/0` on
  /// an adapter without IPv6 — and nothing else on screen would show it.
  it('names in amber the prefixes the driver did not apply', () => {
    const stripped = postureHtml(profile(), null, {
      status: 'incomplete',
      missing: ['::/0'],
      missing_addresses: [],
    })
    expect(stripped).toContain('::/0 non appliqué par le pilote — hors tunnel')
    expect(stripped).toContain('rgb(161, 98, 7)')
    // The gap outranks the profile's own list: showing «0.0.0.0/0, ::/0»
    // alone would state a capture the adapter does not have.
    expect(stripped).not.toContain('0.0.0.0/0, ::/0')

    const both = postureHtml(profile(), null, {
      status: 'incomplete',
      missing: ['0.0.0.0/0', '::/0'],
      missing_addresses: [],
    })
    expect(both).toContain('0.0.0.0/0, ::/0 non appliqués par le pilote — hors tunnel')

    // Even on a legacy IPv4-only profile, the measured gap is what is shown.
    const legacy = postureHtml(
      profile({ allowed_ips: '0.0.0.0/0', ipv6_uncaptured_full_tunnel: true }),
      null,
      { status: 'incomplete', missing: ['0.0.0.0/0'], missing_addresses: [] },
    )
    expect(legacy).toContain('0.0.0.0/0 non appliqué par le pilote — hors tunnel')
  })

  /// Both addresses on the one «adresse» row, IPv4 first; a profile without
  /// IPv6 reads exactly as before.
  it('shows both tunnel addresses on the address row', () => {
    const dual = postureHtml(profile({ address_v6: 'fd3c:91a2:7e04::2/128' }), null)
    expect(dual).toContain('100.64.1.2/32, fd3c:91a2:7e04::2/128')
    expect(dual).toContain('Copier les adresses virtuelles')
    expect(dual).not.toContain('non posée')

    const ipv4 = postureHtml(profile(), null)
    expect(ipv4).toContain('100.64.1.2/32')
    expect(ipv4).not.toContain('fd3c')
    expect(ipv4).toContain('Copier l’adresse virtuelle')
  })

  /// On Windows an adapter without IPv6 drops the IPv6 address as silently as
  /// `::/0`: the read-back names it, in amber, on the row it belongs to.
  it('names in amber an address the driver did not put on the adapter', () => {
    const skipped = postureHtml(profile({ address_v6: 'fd3c:91a2:7e04::2/128' }), null, {
      status: 'incomplete',
      missing: ['::/0'],
      missing_addresses: ['fd3c:91a2:7e04::2/128'],
    })
    expect(skipped).toContain(
      '100.64.1.2/32, fd3c:91a2:7e04::2/128 — fd3c:91a2:7e04::2/128 non posée par le pilote',
    )
    expect(skipped).toContain('::/0 non appliqué par le pilote — hors tunnel')

    // An address alone missing leaves the traffic row as the profile states.
    const alone = postureHtml(profile({ address_v6: 'fd3c:91a2:7e04::2/128' }), null, {
      status: 'incomplete',
      missing: [],
      missing_addresses: ['fd3c:91a2:7e04::2/128'],
    })
    expect(alone).toContain('fd3c:91a2:7e04::2/128 non posée par le pilote')
    expect(alone).not.toContain('non appliqué')
    expect(alone).toContain('0.0.0.0/0, ::/0')
  })

  it('does not present an unverified capture as a healthy one', () => {
    const unverified = postureHtml(profile(), null, {
      status: 'unverified',
      reason: 'configuration du pilote : lecture impossible',
    })
    expect(unverified).toContain('0.0.0.0/0, ::/0 — non vérifié sur l’adaptateur')
    expect(unverified).toContain('rgb(161, 98, 7)')

    const complete = postureHtml(profile(), null, { status: 'complete' })
    expect(complete).toContain('0.0.0.0/0, ::/0')
    expect(complete).not.toContain('non vérifié')
    expect(complete).not.toContain('non appliqué')
    expect(complete).not.toContain('rgb(161, 98, 7)')
  })

  it('server-renders the initial application without starting platform effects', () => {
    const html = renderToStaticMarkup(<App />)
    expect(html).toContain('Orion')
    expect(html).toContain('Navigation principale')
    expect(html).toContain('aucun profil sélectionné')
  })

  /// Every withheld guarantee must be visible, and the reassuring wording must
  /// never appear when the guarantee is absent.
  it('states each vault guarantee it can, and names the ones it cannot', () => {
    const degraded: VaultPosture = {
      hardwareBacked: false,
      softwareKeystore: true,
      volume: 'Volume non chiffré.',
      volumeProtected: false,
      unencryptedVolumeWaived: false,
      memoryLocked: false,
      memory: 'Verrouillage mémoire refusé par le système.',
      dumpsExcluded: false,
      dumps: 'Exclusion des rapports d’erreur refusée.',
      rotationRequired: ['portable'],
      legacyPresent: true,
    }
    const html = postureHtml(profile(), degraded)

    expect(html).toContain('scellés au compte uniquement')
    expect(html).not.toContain('scellés au TPM')
    expect(html).toContain('non couvert')
    expect(html).toContain('non verrouillée')
    expect(html).toContain('fichier en clair présent')
    // The blocked profile is named: an operator has to know which one.
    expect(html).toContain('portable')
  })

  /// A refusal and a waiver retain the same concise UI wording.
  it('reports an unencrypted volume without exposing waiver terminology', () => {
    const base: VaultPosture = {
      hardwareBacked: true,
      softwareKeystore: false,
      volume: 'Volume non chiffré.',
      volumeProtected: false,
      unencryptedVolumeWaived: false,
      memoryLocked: true,
      memory: '',
      dumpsExcluded: true,
      dumps: '',
      rotationRequired: [],
      legacyPresent: false,
    }

    const refused = postureHtml(profile(), base)
    expect(refused).toContain('non couvert')
    expect(refused).not.toContain('exigence levée')

    const waived = postureHtml(profile(), { ...base, unencryptedVolumeWaived: true })
    expect(waived).toContain('non chiffré')
    expect(waived).not.toContain('exigence levée')
  })

  /// A nominal vault reports nothing at all.
  ///
  /// Rows stating that the seal holds, the volume is encrypted and memory is
  /// locked gave the user nothing to act on while pushing the degraded rows —
  /// the only ones worth a glance — out of sight. Silence is the healthy state.
  it('stays silent about a vault that has nothing to report', () => {
    const clean: VaultPosture = {
      hardwareBacked: true,
      softwareKeystore: false,
      volume: 'Volume chiffré.',
      volumeProtected: true,
      unencryptedVolumeWaived: false,
      memoryLocked: true,
      memory: 'Pages verrouillées en RAM.',
      dumpsExcluded: true,
      dumps: 'Pages secrètes exclues.',
      rotationRequired: [],
      legacyPresent: false,
    }
    const html = postureHtml(profile(), clean)

    expect(html).not.toContain('scellés')
    expect(html).not.toContain('verrouillée')
    expect(html).not.toContain('non couvert')
    expect(html).not.toContain('fichier en clair présent')
  })

  /// A posture that could not be read shows nothing rather than reassuring.
  it('shows no vault row when the posture is unknown', () => {
    const html = postureHtml(profile(), null)

    expect(html).not.toContain('scellés')
    expect(html).not.toContain('verrouillée')
  })
})
