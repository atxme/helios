import { describe, expect, it } from 'vitest'

import { isReloadChord, keepsNativeContextMenu, lockShell, type ShellTarget } from './shell'

/** Double de `window` : retient les écouteurs pour pouvoir les déclencher. */
function fakeTarget() {
  const handlers = new Map<string, (event: Event) => void>()
  const target: ShellTarget = {
    addEventListener: (type, handler) => void handlers.set(type, handler),
    removeEventListener: (type) => void handlers.delete(type),
  }

  /** Déclenche un écouteur et dit si l'événement a été annulé. */
  const fire = (type: string, event: Record<string, unknown>): boolean => {
    let prevented = false
    const handler = handlers.get(type)
    if (!handler) return false
    handler({ ...event, preventDefault: () => void (prevented = true) } as unknown as Event)
    return prevented
  }

  return { target, fire, installed: () => [...handlers.keys()].sort() }
}

/** Cible de clic droit : seul `closest` compte pour le verrou. */
const inEditable = { closest: (selector: string) => (selector.includes('input') ? {} : null) }
const inPage = { closest: () => null }

describe('verrouillage du shell', () => {
  it('pose puis retire ses deux écouteurs', () => {
    const { target, installed } = fakeTarget()
    const release = lockShell(target)
    expect(installed()).toEqual(['contextmenu', 'keydown'])
    release()
    expect(installed()).toEqual([])
  })

  it('supprime le menu contextuel de la page', () => {
    const { target, fire } = fakeTarget()
    lockShell(target)

    // C'est ce menu-là qui porte « Actualiser ».
    expect(fire('contextmenu', { target: inPage })).toBe(true)
  })

  it('laisse le menu d’édition des champs de saisie', () => {
    const { target, fire } = fakeTarget()
    lockShell(target)

    // Coller une clé WireGuard au clic droit doit rester possible ; WebView2 y
    // présente couper/copier/coller, pas « Actualiser ».
    expect(fire('contextmenu', { target: inEditable })).toBe(false)
    expect(keepsNativeContextMenu(inEditable)).toBe(true)
    expect(keepsNativeContextMenu(inPage)).toBe(false)
    // Une cible sans `closest` (le document, `window`) n'est pas un champ.
    expect(keepsNativeContextMenu(null)).toBe(false)
    expect(keepsNativeContextMenu({})).toBe(false)
  })

  it('bloque les quatre raccourcis de rechargement', () => {
    const { target, fire } = fakeTarget()
    lockShell(target)

    expect(fire('keydown', { key: 'F5' })).toBe(true)
    expect(fire('keydown', { key: 'F5', ctrlKey: true })).toBe(true)
    expect(fire('keydown', { key: 'r', ctrlKey: true })).toBe(true)
    expect(fire('keydown', { key: 'R', ctrlKey: true, shiftKey: true })).toBe(true)
    expect(fire('keydown', { key: 'r', metaKey: true })).toBe(true)
  })

  it('ne touche pas aux frappes ordinaires', () => {
    const { target, fire } = fakeTarget()
    lockShell(target)

    // Sans ce test, un « r » interdit de saisie passerait inaperçu jusqu'à la
    // première clé WireGuard à recopier.
    expect(fire('keydown', { key: 'r' })).toBe(false)
    expect(fire('keydown', { key: 'R', shiftKey: true })).toBe(false)
    // Ctrl+C et Ctrl+Z servent tous les deux dans l'IHM.
    expect(fire('keydown', { key: 'c', ctrlKey: true })).toBe(false)
    expect(fire('keydown', { key: 'z', ctrlKey: true })).toBe(false)
    expect(isReloadChord({ key: 'v', ctrlKey: true })).toBe(false)
  })
})
