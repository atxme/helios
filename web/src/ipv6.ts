/**
 * What the gateway's IPv6 tunnel state means, in one place.
 *
 * `GET /api/status` reports it as `"installed"`, `"not_configured"` or
 * `{"unavailable": {"reason": …}}` (ADRESSAGE-IPV6.md §6.2). The last one is a
 * degraded state that must be visible: the gateway runs IPv4-only, and the
 * clients' IPv6 VIPs are not routed.
 *
 * The input is read as `unknown` on purpose. A daemon newer than this console
 * may add a reason, and a status from a daemon older than the IPv6 tunnel has
 * no `ipv6` at all: neither may take the System view down, and neither may be
 * shown as an installed IPv6.
 */

export type Ipv6Kind = 'installed' | 'not_configured' | 'unavailable'

export interface Ipv6Semantics {
  kind: Ipv6Kind
  /** The value in the configuration row. */
  label: string
  /** For `unavailable`: why, in French, with the figures the daemon gave. */
  reason: string | null
}

/** Shown when the daemon names a reason this console does not know. */
export const UNKNOWN_IPV6_REASON =
  'Raison non reconnue par cette interface ; le journal de heliosd la donne en clair.'

function text(value: unknown): string | null {
  if (typeof value === 'string' && value.length > 0) return value
  if (typeof value === 'number' && Number.isFinite(value)) return String(value)
  return null
}

/** One French sentence per `Ipv6Unavailable` variant, or the generic one. */
export function describeIpv6Reason(unavailable: unknown): string {
  if (typeof unavailable !== 'object' || unavailable === null) return UNKNOWN_IPV6_REASON
  const fields = unavailable as Record<string, unknown>

  switch (fields.reason) {
    case 'tunnel_mtu_too_small': {
      const mtu = text(fields.tunnel_mtu)
      const minimum = text(fields.minimum)
      if (mtu === null || minimum === null) break
      return `Le MTU du tunnel (${mtu} octets) est inférieur aux ${minimum} octets qu’exige IPv6 (RFC 8200).`
    }
    case 'disabled_by_kernel': {
      const setting = text(fields.setting)
      if (setting === null) break
      return `Le noyau a désactivé IPv6 (${setting} = 1).`
    }
    case 'no_kernel_support': {
      const path = text(fields.path)
      if (path === null) break
      return `Le noyau n’a pas de pile IPv6 (${path} n’existe pas).`
    }
    case 'address_refused': {
      const address = text(fields.address)
      const detail = text(fields.detail)
      if (address === null || detail === null) break
      return `La montée de l’interface avec ${address} a échoué (${detail}) ; elle est montée sans.`
    }
  }
  return UNKNOWN_IPV6_REASON
}

export function describeIpv6(status: unknown): Ipv6Semantics {
  // Absent: a daemon older than the IPv6 tunnel, which has none to report.
  if (status === undefined || status === null || status === 'not_configured') {
    return { kind: 'not_configured', label: 'non configurée', reason: null }
  }
  if (status === 'installed') {
    return { kind: 'installed', label: 'installée', reason: null }
  }
  // `{"unavailable": …}`, or a shape this console does not know. The latter
  // reads as degraded rather than installed: claiming an IPv6 that may not be
  // routed is the one wrong answer.
  const unavailable =
    typeof status === 'object' && 'unavailable' in status
      ? (status as { unavailable: unknown }).unavailable
      : null
  return { kind: 'unavailable', label: 'indisponible', reason: describeIpv6Reason(unavailable) }
}
