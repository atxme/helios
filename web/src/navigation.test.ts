import { describe, expect, it } from 'vitest'
import { NAV_ITEMS, navItem } from './navigation'

describe('console navigation', () => {
  it('keeps its destinations unique and addressable', () => {
    const ids = NAV_ITEMS.map(item => item.id)
    expect(new Set(ids).size).toBe(ids.length)

    for (const item of NAV_ITEMS) {
      expect(navItem(item.id)).toBe(item)
    }
  })

  it('stays within what a navigation rail can hold', () => {
    // MD3 caps a rail at seven destinations; an eighth is a signal to group,
    // not to shrink the labels until they fit.
    expect(NAV_ITEMS.length).toBeLessThanOrEqual(7)
  })

  it('gives every destination a heading and a brief', () => {
    for (const item of NAV_ITEMS) {
      expect(item.title.length, item.id).toBeGreaterThan(0)
      expect(item.description.length, item.id).toBeGreaterThan(0)
      // Rail labels sit under a 56 px indicator and must not wrap.
      expect(item.label.length, item.id).toBeLessThanOrEqual(12)
    }
  })

  it('fails loudly on a destination it does not know', () => {
    // @ts-expect-error — exactly the call the type system already refuses; the
    // guard exists for the case where NavId and NAV_ITEMS drift apart.
    expect(() => navItem('inexistant')).toThrow(/destination inconnue/)
  })
})
