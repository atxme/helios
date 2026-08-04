// @vitest-environment jsdom

import Box from '@mui/material/Box'
import { ThemeProvider } from '@mui/material/styles'
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { NAV_ITEMS, navItem } from '../navigation'
import { heliosTheme } from '../theme'
import type { Status } from '../types'
import { AppShell } from './AppShell'
import { EventLog, describeEvent } from './EventLog'
import { StateBanner } from './StateBadge'

afterEach(cleanup)

function mount(ui: React.ReactNode) {
  return render(<ThemeProvider theme={heliosTheme}>{ui}</ThemeProvider>)
}

const STATUS: Status = {
  state: 'up',
  version: '0.1.0',
  wan_iface: 'eth0',
  lan_ifaces: ['eth1'],
  wg_peers: [],
  allow_ssh_from: [],
  peers: [],
  wg_iface: 'helios0',
  wg_listen_port: 51820,
  key_negotiation_port: 51821,
  dry_run: false,
  split_tunnel_cidrs: [],
  mss_clamp: null,
  captive_portal_gateway: null,
  handshake_stale_after_seconds: 150,
}

describe('custom design tokens', () => {
  /**
   * The interface paints almost every surface with tokens MUI does not ship —
   * `state.*`, `surfaceContainer.*`, the `container` pair on each accent. They
   * are reachable from `sx` only because they are declared inside
   * `colorSchemes`; declared anywhere else they resolve to nothing and the
   * surface silently renders transparent. This asserts they reach the DOM.
   */
  it('resolves the augmented palette paths into CSS variables', () => {
    const { container } = mount(
      <Box
        data-testid="probe"
        sx={{
          bgcolor: 'state.up.container',
          color: 'surfaceContainer.low',
          borderColor: 'tertiary.container',
        }}
      />,
    )

    const probe = container.querySelector('[data-testid="probe"]')!
    const emotionClass = Array.from(probe.classList).find(name => name.startsWith('css-'))
    const stylesheet = Array.from(document.querySelectorAll('style'))
      .map(node => node.textContent)
      .join('\n')
    const rule = stylesheet.split('}').find(block => emotionClass && block.includes(emotionClass))

    expect(rule).toContain('state-up-container')
    expect(rule).toContain('surfaceContainer-low')
    expect(rule).toContain('tertiary-container')
  })
})

describe('AppShell', () => {
  it('titles the view from the navigation model rather than from the view', () => {
    mount(
      <AppShell
        nav="security"
        onNav={vi.fn()}
        status={STATUS}
        currentState="up"
        error={null}
        wsStatus="connected"
      >
        <div />
      </AppShell>,
    )

    const item = navItem('security')
    expect(screen.getByRole('heading', { name: item.title })).toBeTruthy()
    expect(screen.getByText(item.description)).toBeTruthy()
  })

  it('offers every destination and reports the one that was chosen', () => {
    const onNav = vi.fn()
    mount(
      <AppShell
        nav="overview"
        onNav={onNav}
        status={STATUS}
        currentState="up"
        error={null}
        wsStatus="connected"
      >
        <div />
      </AppShell>,
    )

    // Scoped to the rail: a destination label may legitimately repeat as the
    // heading of the view it opens.
    const rail = within(screen.getByRole('navigation'))
    for (const item of NAV_ITEMS) {
      expect(rail.getByText(item.label), item.id).toBeTruthy()
    }

    fireEvent.click(rail.getByText(navItem('clients').label))
    expect(onNav).toHaveBeenCalledWith('clients')
  })

  it('keeps the tunnel state visible from every view', () => {
    mount(
      <AppShell
        nav="system"
        onNav={vi.fn()}
        status={STATUS}
        currentState="failed"
        error={null}
        wsStatus="connected"
      >
        <div />
      </AppShell>,
    )

    // An operator who navigated away from the dashboard must still be told
    // the tunnel dropped.
    expect(screen.getByText('Échec')).toBeTruthy()
  })

  it('cycles the color scheme and keeps the current one nameable', () => {
    // Both schemes are first-class, so the control has three positions and
    // must always say which one is active — an unlabelled sun/moon toggle
    // cannot express "follow the system".
    render(
      <ThemeProvider theme={heliosTheme} defaultMode="system">
        <AppShell
          nav="overview"
          onNav={vi.fn()}
          status={STATUS}
          currentState="up"
          error={null}
          wsStatus="connected"
        >
          <div />
        </AppShell>
      </ThemeProvider>,
    )

    expect(screen.getByLabelText('Thème système')).toBeTruthy()
    fireEvent.click(screen.getByLabelText('Thème système'))
    expect(screen.getByLabelText('Thème clair')).toBeTruthy()
    fireEvent.click(screen.getByLabelText('Thème clair'))
    expect(screen.getByLabelText('Thème sombre')).toBeTruthy()
  })

  it('announces a simulating daemon and a dead event stream', () => {
    mount(
      <AppShell
        nav="overview"
        onNav={vi.fn()}
        status={{ ...STATUS, dry_run: true }}
        currentState="down"
        error="orchestrateur injoignable"
        wsStatus="disconnected"
      >
        <div />
      </AppShell>,
    )

    expect(screen.getByText('Simulation')).toBeTruthy()
    // Distinct from the tunnel's own "Hors ligne", which sits beside it.
    expect(screen.getByText('Flux coupé')).toBeTruthy()
    expect(screen.getByText('Hors ligne')).toBeTruthy()
    expect(screen.getByRole('alert').textContent).toContain('orchestrateur injoignable')
  })
})

describe('StateBanner', () => {
  it('states the tunnel state in words, not only in color', () => {
    mount(<StateBanner state="captive_portal" uptime="00:04:12" />)

    expect(screen.getByText('Portail captif')).toBeTruthy()
    expect(screen.getByText('00:04:12')).toBeTruthy()
  })
})

describe('EventLog', () => {
  it('says it is waiting rather than showing an empty frame', () => {
    mount(<EventLog events={[]} />)
    expect(screen.getByText(/En attente d’événements/)).toBeTruthy()
  })

  it('renders a state change with the label the rest of the console uses', () => {
    mount(<EventLog events={[{ type: 'state_changed', state: 'up', ts: '10:00:00' }]} />)

    expect(screen.getByText('10:00:00')).toBeTruthy()
    expect(screen.getByText('Handshake actif')).toBeTruthy()
  })

  it('colors a line by what it means', () => {
    expect(describeEvent({ type: 'log', level: 'error', message: 'boum', ts: '1' }).color).toBe(
      'error.main',
    )
    expect(describeEvent({ type: 'log', level: 'info', message: 'ok', ts: '1' }).color).toBe(
      'text.secondary',
    )
    expect(describeEvent({ type: 'state_changed', state: 'failed', ts: '1' }).color).toBe(
      'state.failed.main',
    )
    expect(
      describeEvent({ type: 'split_tunnel_changed', cidrs: [], ts: '1' }).text,
    ).toBe('split-tunnel désactivé')
  })
})
