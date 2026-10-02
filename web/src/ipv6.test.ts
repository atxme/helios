import { describe, expect, it } from 'vitest'
import { UNKNOWN_IPV6_REASON, describeIpv6 } from './ipv6'

/**
 * The three shapes `GET /api/status` gives `ipv6`, exactly as serde writes
 * `aether::net::Ipv6TunnelStatus` — and the ones it might give tomorrow.
 */

describe('IPv6 tunnel state semantics', () => {
  it('reads the two unit variants', () => {
    expect(describeIpv6('installed')).toEqual({ kind: 'installed', label: 'installée', reason: null })
    expect(describeIpv6('not_configured')).toEqual({
      kind: 'not_configured',
      label: 'non configurée',
      reason: null,
    })
  })

  it('reads a daemon older than the IPv6 tunnel as not configured', () => {
    expect(describeIpv6(undefined).kind).toBe('not_configured')
    expect(describeIpv6(null).kind).toBe('not_configured')
  })

  it('names every reason the daemon can give, with its figures', () => {
    const cases: Array<[unknown, string]> = [
      [
        { reason: 'tunnel_mtu_too_small', tunnel_mtu: 1200, minimum: 1280 },
        'Le MTU du tunnel (1200 octets) est inférieur aux 1280 octets qu’exige IPv6 (RFC 8200).',
      ],
      [
        { reason: 'disabled_by_kernel', setting: 'net.ipv6.conf.all.disable_ipv6' },
        'Le noyau a désactivé IPv6 (net.ipv6.conf.all.disable_ipv6 = 1).',
      ],
      [
        { reason: 'no_kernel_support', path: '/proc/sys/net/ipv6' },
        'Le noyau n’a pas de pile IPv6 (/proc/sys/net/ipv6 n’existe pas).',
      ],
      [
        { reason: 'address_refused', address: 'fd3c:91a2:7e04::1/64', detail: 'EADDRNOTAVAIL' },
        'La montée de l’interface avec fd3c:91a2:7e04::1/64 a échoué (EADDRNOTAVAIL) ; elle est montée sans.',
      ],
    ]
    for (const [unavailable, reason] of cases) {
      expect(describeIpv6({ unavailable })).toEqual({ kind: 'unavailable', label: 'indisponible', reason })
    }
  })

  it('degrades an unknown or malformed reason to the generic text, never a crash', () => {
    for (const unavailable of [
      { reason: 'firmware_said_no' },
      { reason: 'disabled_by_kernel' },
      { reason: 'tunnel_mtu_too_small', tunnel_mtu: 'beaucoup', minimum: null },
      {},
      null,
      'texte',
    ]) {
      expect(describeIpv6({ unavailable })).toEqual({
        kind: 'unavailable',
        label: 'indisponible',
        reason: UNKNOWN_IPV6_REASON,
      })
    }
  })

  it('never reads an unknown shape as an installed IPv6', () => {
    for (const status of ['partially_installed', 42, { degraded: {} }, []]) {
      const semantics = describeIpv6(status)
      expect(semantics.kind, JSON.stringify(status)).toBe('unavailable')
      expect(semantics.reason).toBe(UNKNOWN_IPV6_REASON)
    }
  })
})
