/**
 * Clipboard, with the fallback WebView2 makes necessary.
 *
 * `navigator.clipboard` is refused in some WebView2 contexts — a non-secure
 * origin, a window that has lost focus. Without the textarea fallback the
 * button fails silently, which is the worst outcome for a value one copies
 * precisely because one is about to compare it somewhere else.
 */
export async function copyText(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text)
    return
  } catch {
    const area = document.createElement('textarea')
    area.value = text
    area.setAttribute('readonly', '')
    area.style.position = 'fixed'
    area.style.opacity = '0'
    document.body.appendChild(area)
    area.select()
    try {
      document.execCommand('copy')
    } finally {
      document.body.removeChild(area)
    }
  }
}
