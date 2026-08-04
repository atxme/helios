// @vitest-environment jsdom

import { cleanup, render } from '@testing-library/react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it, vi } from 'vitest'

import App from '../App'
import type { ClientProfile, LogLine, TunnelState, VaultPosture } from '../types'
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
  public_key: 'client-public',
  has_private_key: true,
  has_static_psk: false,
  address: '100.64.1.2/32',
  allowed_ips: '0.0.0.0/0',
  persistent_keepalive: 25,
  heliosd_url: 'http://100.64.0.1:8080',
  ssh_target: null,
  key_negotiation: null,
  ...overrides,
})

function postureHtml(selected: ClientProfile, vault: VaultPosture | null): string {
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
      backend="wireguard-nt"
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
          onConnect={callback}
          onOpenSsh={callback}
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
        minimum_mode: 'classic',
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
    expect(html).toContain('hors tunnel')
    expect(html).toContain('wireguard-nt')
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

  /// A refusal and a waiver must not read alike.
  ///
  /// Both leave the disk unencrypted, so the amber tone is the same — what
  /// differs is whether somebody *chose* it. Reporting a machine without
  /// BitLocker as a deliberate waiver would credit the user with a decision
  /// they never made, and hide the one they did.
  it('separates an unencrypted volume from one whose requirement was waived', () => {
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
    expect(waived).toContain('exigence levée')
  })

  it('claims the hardware seal only when it holds', () => {
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

    expect(html).toContain('scellés au TPM')
    expect(html).toContain('verrouillée')
    expect(html).not.toContain('fichier en clair présent')
  })

  /// A posture that could not be read shows nothing rather than reassuring.
  it('shows no vault row when the posture is unknown', () => {
    const html = postureHtml(profile(), null)

    expect(html).not.toContain('scellés')
    expect(html).not.toContain('verrouillée')
  })
})
