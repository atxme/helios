import { describe, expect, it } from 'vitest'

import { isReloadChord, keepsNativeContextMenu, lockShell, type ShellTarget } from './shell'

/** `window` double: retains listeners so they can be triggered. */
function fakeTarget() {
  const handlers = new Map<string, (event: Event) => void>()
  const target: ShellTarget = {
    addEventListener: (type, handler) => void handlers.set(type, handler),
    removeEventListener: (type) => void handlers.delete(type),
  }

  /** Triggers a listener and says whether the event was prevented. */
  const fire = (type: string, event: Record<string, unknown>): boolean => {
    let prevented = false
    const handler = handlers.get(type)
    if (!handler) return false
    handler({ ...event, preventDefault: () => void (prevented = true) } as unknown as Event)
    return prevented
  }

  return { target, fire, installed: () => [...handlers.keys()].sort() }
}

/** Right-click target: only `closest` matters for the lock. */
const inEditable = { closest: (selector: string) => (selector.includes('input') ? {} : null) }
const inPage = { closest: () => null }

describe('shell lockdown', () => {
  it('sets then removes its two listeners', () => {
    const { target, installed } = fakeTarget()
    const release = lockShell(target)
    expect(installed()).toEqual(['contextmenu', 'keydown'])
    release()
    expect(installed()).toEqual([])
  })

  it('removes the page context menu', () => {
    const { target, fire } = fakeTarget()
    lockShell(target)

    // This is the menu that carries "Refresh".
    expect(fire('contextmenu', { target: inPage })).toBe(true)
  })

  it('leaves the edit menu of input fields', () => {
    const { target, fire } = fakeTarget()
    lockShell(target)

    // Pasting a WireGuard key via right-click must stay possible; WebView2
    // presents cut/copy/paste there, not "Refresh".
    expect(fire('contextmenu', { target: inEditable })).toBe(false)
    expect(keepsNativeContextMenu(inEditable)).toBe(true)
    expect(keepsNativeContextMenu(inPage)).toBe(false)
    // A target without `closest` (the document, `window`) is not a field.
    expect(keepsNativeContextMenu(null)).toBe(false)
    expect(keepsNativeContextMenu({})).toBe(false)
  })

  it('blocks the four reload shortcuts', () => {
    const { target, fire } = fakeTarget()
    lockShell(target)

    expect(fire('keydown', { key: 'F5' })).toBe(true)
    expect(fire('keydown', { key: 'F5', ctrlKey: true })).toBe(true)
    expect(fire('keydown', { key: 'r', ctrlKey: true })).toBe(true)
    expect(fire('keydown', { key: 'R', ctrlKey: true, shiftKey: true })).toBe(true)
    expect(fire('keydown', { key: 'r', metaKey: true })).toBe(true)
  })

  it('does not touch ordinary keystrokes', () => {
    const { target, fire } = fakeTarget()
    lockShell(target)

    // Without this test, an "r" forbidden from input would go unnoticed
    // until the first WireGuard key to copy in.
    expect(fire('keydown', { key: 'r' })).toBe(false)
    expect(fire('keydown', { key: 'R', shiftKey: true })).toBe(false)
    // Ctrl+C and Ctrl+Z are both used in the UI.
    expect(fire('keydown', { key: 'c', ctrlKey: true })).toBe(false)
    expect(fire('keydown', { key: 'z', ctrlKey: true })).toBe(false)
    expect(isReloadChord({ key: 'v', ctrlKey: true })).toBe(false)
  })
})
