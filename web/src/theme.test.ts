import { describe, expect, it } from 'vitest'
import { heliosTheme } from './theme'
import { TUNNEL_STATE } from './state'
import type { TunnelState } from './types'

/**
 * Guards the one defect a design system fails at silently.
 *
 * A token defined in one color scheme and forgotten in the other does not
 * throw and does not break the build: it renders as an empty value, so the
 * surface falls back to transparent — in exactly one scheme, which is
 * invariably the one nobody had open while working. Every token this
 * interface paints with is therefore asserted in both.
 */

const SCHEMES = ['light', 'dark'] as const

function paletteOf(scheme: (typeof SCHEMES)[number]) {
  const palette = heliosTheme.colorSchemes[scheme]?.palette
  if (!palette) throw new Error(`schéma absent : ${scheme}`)
  return palette
}

describe('Helios color schemes', () => {
  it('defines both schemes as CSS variables', () => {
    expect(heliosTheme.vars).toBeTruthy()
    expect(heliosTheme.colorSchemes.light).toBeTruthy()
    expect(heliosTheme.colorSchemes.dark).toBeTruthy()
  })

  it.each(SCHEMES)('gives every tunnel state a complete tone in the %s scheme', scheme => {
    const palette = paletteOf(scheme)
    const states = Object.keys(TUNNEL_STATE) as TunnelState[]

    for (const state of states) {
      const tone = palette.state[TUNNEL_STATE[state].tone]
      expect(tone, `état ${state}`).toBeTruthy()
      expect(tone.main, `état ${state} — main`).toMatch(/^#[0-9A-Fa-f]{6}$/)
      expect(tone.container, `état ${state} — container`).toMatch(/^#[0-9A-Fa-f]{6}$/)
      expect(tone.onContainer, `état ${state} — onContainer`).toMatch(/^#[0-9A-Fa-f]{6}$/)
    }
  })

  it.each(SCHEMES)('gives every accent a container pair in the %s scheme', scheme => {
    const palette = paletteOf(scheme)

    for (const name of ['primary', 'secondary', 'success', 'warning', 'error', 'info'] as const) {
      expect(palette[name].container, `${name} — container`).toMatch(/^#[0-9A-Fa-f]{6}$/)
      expect(palette[name].onContainer, `${name} — onContainer`).toMatch(/^#[0-9A-Fa-f]{6}$/)
    }
    expect(palette.tertiary.container).toMatch(/^#[0-9A-Fa-f]{6}$/)
    expect(palette.tertiary.onContainer).toMatch(/^#[0-9A-Fa-f]{6}$/)
  })

  it.each(SCHEMES)('provides the whole surface ladder in the %s scheme', scheme => {
    const { surfaceContainer } = paletteOf(scheme)

    for (const rung of ['lowest', 'low', 'main', 'high', 'highest'] as const) {
      expect(surfaceContainer[rung], `échelon ${rung}`).toMatch(/^#[0-9A-Fa-f]{6}$/)
    }
  })

  it('holds the navigation rail at the same night in both schemes', () => {
    // The rail is the console's fixed instrument. If it ever followed the
    // color scheme it would dissolve into the light one, taking the mark and
    // the product's identity with it — and the light scheme would be a pale
    // field of panels again, which is what this palette exists to fix.
    expect(paletteOf('light').rail).toEqual(paletteOf('dark').rail)
  })

  it('keeps the state family out of the brand family', () => {
    // The two families must never share a pigment: a brand accent that happens
    // to equal the "protected" green would let decoration read as a security
    // claim, which is the confusion `state.ts` exists to prevent.
    for (const scheme of SCHEMES) {
      const palette = paletteOf(scheme)
      const brand = [palette.primary.main, palette.secondary.main, palette.tertiary.main]
      expect(brand).not.toContain(palette.state.up.main)
    }
  })
})
