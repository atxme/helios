/**
 * WebView shell lockdown: Orion is an application, not a web page.
 *
 * WebView2 brings its browser reflexes — a context menu with "Refresh", F5,
 * Ctrl+R. Reloading isn't harmless there: the frontend is the sole source of
 * truth on what the user sees of the tunnel, and a reload resets it to zero
 * without telling the Rust core anything. A profile being edited disappears,
 * the session log is lost, the nature of the negotiated PSK — never
 * persisted, by design — is no longer known to anyone. The tunnel itself
 * stays mounted: the UI reopens claiming "Disconnected" over a very much
 * alive adapter. It's an interface lie about the very thing it reports on.
 *
 * ## What remains allowed, and why
 *
 * The context menu survives in **input fields**. Pasting a 44-character
 * WireGuard key via right-click is a normal gesture, and WebView2 presents
 * the edit menu there — cut/copy/paste — not the page's: "Refresh" doesn't
 * appear in it. Removing it everywhere would cost this ergonomics without
 * closing anything more.
 *
 * Elsewhere, text stays selectable and Ctrl+C works; the log has its
 * "Copy" and "Export" buttons anyway, which don't depend on the browser's
 * clipboard.
 *
 * ## Module shape
 *
 * The decision is isolated in two pure predicates and the listening target
 * is a parameter. The module is therefore entirely testable without a DOM —
 * the project doesn't ship jsdom, and this lock doesn't justify adding one.
 */

/** Selector for contexts where the native menu is an edit menu. */
const EDITABLE =
  'input, textarea, [contenteditable=""], [contenteditable="true"]'

/**
 * Listening target: `window` in production, a double in tests.
 *
 * Deliberately narrower than `Window` — this module only needs to set and
 * remove two listeners.
 */
export interface ShellTarget {
  addEventListener(
    type: string,
    handler: (event: Event) => void,
    options?: AddEventListenerOptions,
  ): void
  removeEventListener(
    type: string,
    handler: (event: Event) => void,
    options?: EventListenerOptions,
  ): void
}

/**
 * Should a right-click keep the native menu?
 *
 * Duck-typed on `closest` rather than `instanceof Element`: the question is
 * "does this target know how to walk up its ancestors?", and asking it this
 * way makes the predicate verifiable without a DOM.
 */
export function keepsNativeContextMenu(target: unknown): boolean {
  const node = target as { closest?: (selector: string) => unknown } | null
  if (typeof node?.closest !== 'function') return false
  return node.closest(EDITABLE) != null
}

/**
 * Does the keyboard event request a reload?
 *
 * Covers the four chords: F5, Ctrl+F5, Ctrl+R and Ctrl+Shift+R. `metaKey`
 * ensures macOS parity, even though Orion isn't shipped there today.
 */
export function isReloadChord(event: {
  key: string
  ctrlKey?: boolean
  metaKey?: boolean
}): boolean {
  if (event.key === 'F5') return true
  return Boolean(event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'r'
}

/**
 * Installs the guardrails and returns a way to remove them.
 *
 * The return value isn't decorative: it makes the lock reversible, hence
 * testable, and lets React clean up properly where `StrictMode` mounts twice.
 */
export function lockShell(target: ShellTarget): () => void {
  const onContextMenu = (event: Event) => {
    if (!keepsNativeContextMenu(event.target)) event.preventDefault()
  }

  const onKeyDown = (event: Event) => {
    if (isReloadChord(event as KeyboardEvent)) event.preventDefault()
  }

  // `capture`: intercept before an input field or MUI reacts.
  target.addEventListener('contextmenu', onContextMenu)
  target.addEventListener('keydown', onKeyDown, { capture: true })

  return () => {
    target.removeEventListener('contextmenu', onContextMenu)
    target.removeEventListener('keydown', onKeyDown, { capture: true })
  }
}
