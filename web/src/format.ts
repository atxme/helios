/**
 * Turning machine numbers into something an operator reads at a glance.
 *
 * Every function here is total and pure — `null` in, an em dash out — because
 * the daemon reports plenty of values as "not observed", and a formatter that
 * threw on those would take a whole view down with it.
 */

/** Byte counters, in the units WireGuard tooling uses. */
export function formatBytes(bytes: number | null): string {
  if (bytes === null) return '—'
  if (bytes < 1024) return `${bytes} o`
  const units = ['Kio', 'Mio', 'Gio', 'Tio']
  let value = bytes / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ${units[unit]}`
}

/** Throughput, per second. */
export function formatBps(bps: number): string {
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} Mb/s`
  if (bps >= 1_000) return `${Math.round(bps / 1_000)} kb/s`
  return `${bps} b/s`
}

/** Packet rate. */
export function formatPps(pps: number): string {
  if (pps >= 1_000) return `${(pps / 1_000).toFixed(1)}k p/s`
  return `${pps} p/s`
}

/**
 * An age, spoken the way someone would say it out loud.
 *
 * Deliberately coarse above a minute: nobody acts differently on "il y a 4 min
 * 12 s" than on "il y a 4 min", and the extra digits make a table flicker on
 * every refresh.
 */
export function formatAge(seconds: number | null): string {
  if (seconds === null) return 'jamais'
  if (seconds < 5) return "à l’instant"
  if (seconds < 60) return `il y a ${seconds} s`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `il y a ${minutes} min`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `il y a ${hours} h`
  return `il y a ${Math.floor(hours / 24)} j`
}

/** `hh:mm:ss`, zero-padded, for a counter that ticks on screen. */
export function formatDuration(seconds: number): string {
  const pad = (value: number) => String(value).padStart(2, '0')
  const safe = Math.max(0, Math.floor(seconds))
  return `${pad(Math.floor(safe / 3600))}:${pad(Math.floor((safe / 60) % 60))}:${pad(safe % 60)}`
}

/** A WireGuard key, shortened but still comparable by eye. */
export function shortKey(key: string): string {
  return key.length <= 20 ? key : `${key.slice(0, 8)}…${key.slice(-6)}`
}
