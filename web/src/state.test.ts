import { describe, expect, it } from 'vitest'
import { TUNNEL_STATE, toneColors } from './state'
import type { TunnelState } from './types'

const ALL_STATES: TunnelState[] = ['up', 'connecting', 'down', 'failed', 'captive_portal']

describe('tunnel state semantics', () => {
  it('describes every state the daemon can report', () => {
    for (const state of ALL_STATES) {
      const semantics = TUNNEL_STATE[state]
      expect(semantics, state).toBeTruthy()
      expect(semantics.label.length, `${state} — libellé`).toBeGreaterThan(0)
      expect(semantics.detail.length, `${state} — détail`).toBeGreaterThan(0)
    }
  })

  it('releases the kill-switch for `up` and for nothing else', () => {
    // The gateway invariant: only TunnelState::Up lets traffic through. This
    // used to be re-derived in three views, and a fourth view added later
    // would have re-derived it a fourth time.
    expect(TUNNEL_STATE.up.killSwitchEngaged).toBe(false)

    for (const state of ALL_STATES.filter(candidate => candidate !== 'up')) {
      expect(TUNNEL_STATE[state].killSwitchEngaged, state).toBe(true)
    }
  })

  it('never announces allowed traffic while the kill-switch holds', () => {
    for (const state of ALL_STATES) {
      const semantics = TUNNEL_STATE[state]
      if (semantics.killSwitchEngaged) {
        expect(semantics.trafficLabel.toLowerCase(), state).not.toContain('autorisé')
      }
    }
  })

  it('builds palette paths that match the theme augmentation', () => {
    expect(toneColors('up')).toEqual({
      main: 'state.up.main',
      container: 'state.up.container',
      onContainer: 'state.up.onContainer',
    })
    expect(toneColors('captivePortal').main).toBe('state.captivePortal.main')
  })
})
