import { describe, expect, it } from 'vitest'

import {
  gatewayPrefix,
  gatewayPrefixV6,
  leavesIpv6Uncaptured,
  matchPreset,
  presetPrefixes,
  splitPrefixes,
  type SplitTunnelSource,
} from './splitTunnel'

const source = (overrides: Partial<SplitTunnelSource> = {}): SplitTunnelSource => ({
  heliosd_url: 'http://100.64.0.1:8080',
  ssh_target: null,
  address_v6: null,
  ...overrides,
})

describe('splitPrefixes', () => {
  it('trims and drops empty entries, like the core does', () => {
    expect(splitPrefixes(' 10.0.0.0/8 ,, 192.168.1.0/24 , ')).toEqual([
      '10.0.0.0/8',
      '192.168.1.0/24',
    ])
  })
})

describe('gatewayPrefix', () => {
  it('reads the internal Helios URL first', () => {
    expect(gatewayPrefix(source())).toBe('100.64.0.1/32')
  })

  it('falls back to the SSH destination', () => {
    expect(gatewayPrefix(source({ heliosd_url: null, ssh_target: 'admin@100.64.0.9' }))).toBe(
      '100.64.0.9/32',
    )
  })

  it('gives an IPv6 gateway a host prefix of its own', () => {
    expect(gatewayPrefix(source({ heliosd_url: 'http://[fd00::1]:8080' }))).toBe('fd00::1/128')
  })

  // A name is not an address: Orion's DNS is not tunnelled, so nothing here
  // can turn it into a route.
  it('ignores a named host and assumes the documented gateway address', () => {
    expect(gatewayPrefix(source({ heliosd_url: 'http://gateway.internal:8080' }))).toBe(
      '100.64.0.1/32',
    )
  })

  it('assumes the documented gateway address when the profile names none', () => {
    expect(gatewayPrefix(source({ heliosd_url: null, ssh_target: null }))).toBe('100.64.0.1/32')
  })

  it('refuses a malformed octet rather than writing it as a prefix', () => {
    expect(gatewayPrefix(source({ heliosd_url: 'http://100.64.0.999:8080' }))).toBe(
      '100.64.0.1/32',
    )
  })
})

describe('presetPrefixes', () => {
  // Both families, in the core's canonical spelling: `::/0` is what makes
  // WireGuard drop IPv6 instead of letting it leave in clear.
  it('captures everything, IPv6 included', () => {
    expect(presetPrefixes('full', source())).toBe('0.0.0.0/0, ::/0')
  })

  it('captures the gateway alone', () => {
    expect(presetPrefixes('gateway', source())).toBe('100.64.0.1/32')
  })

  // Without the gateway's own prefix the negotiated release would leave the
  // tunnel in clear, and `orion_core` refuses to send it at all.
  it('keeps the gateway in the private-network list', () => {
    expect(presetPrefixes('private', source())).toBe(
      '100.64.0.1/32, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16',
    )
  })
})

// `ADRESSAGE-IPV6.md` §2.4: the gateway is `::1` of the tunnel `/64`. The
// expected texts are the RFC 5952 form `std` gives the gateway's own address
// (`TunnelPrefixV6::gateway`), so a preset matches what the gateway prints.
describe('gatewayPrefixV6', () => {
  it('takes the /64 of the address and puts the gateway at ::1', () => {
    const cases: [string | null, string | null][] = [
      ['fd3c:91a2:7e04::2/128', 'fd3c:91a2:7e04::1/128'],
      ['fd3c:91a2:7e04:0:f545:e478:e88:7a7f/128', 'fd3c:91a2:7e04::1/128'],
      ['FD3C:91A2:7E04:0000::2/128', 'fd3c:91a2:7e04::1/128'],
      [' fd3c:91a2:7e04::2/128 ', 'fd3c:91a2:7e04::1/128'],
      ['fd00:1:2:3::4/128', 'fd00:1:2:3::1/128'],
      ['fd00::2/128', 'fd00::1/128'],
      ['0:1::5/128', '0:1::1/128'],
      // Not a /128 host, not an IPv6 address, or nothing at all: no gateway.
      ['fd3c:91a2:7e04::/64', null],
      ['fd3c:91a2:7e04::2', null],
      ['100.64.1.2/32', null],
      ['fe80::2%eth0/128', null],
      ['fd3c::2::3/128', null],
      ['fd3c:91a2:7e04:0:0:0:0:0:2/128', null],
      ['', null],
      [null, null],
    ]
    for (const [address, expected] of cases) {
      expect(gatewayPrefixV6(address), JSON.stringify(address)).toBe(expected)
    }
  })
})

describe('the gateway preset with an IPv6 address', () => {
  const dual = source({ address_v6: 'fd3c:91a2:7e04::2/128' })

  it('reaches the gateway in both families', () => {
    expect(presetPrefixes('gateway', dual)).toBe('100.64.0.1/32, fd3c:91a2:7e04::1/128')
  })

  // Without `address_v6` nothing changes, and a malformed one is left to the
  // core's field message rather than turned into a route.
  it('is the IPv4 preset without a usable IPv6 address', () => {
    expect(presetPrefixes('gateway', source())).toBe('100.64.0.1/32')
    expect(presetPrefixes('gateway', source({ address_v6: 'fd3c::/64' }))).toBe('100.64.0.1/32')
  })

  it('leaves the other presets as they were', () => {
    expect(presetPrefixes('full', dual)).toBe(presetPrefixes('full', source()))
    expect(presetPrefixes('private', dual)).toBe(presetPrefixes('private', source()))
  })

  it('is recognised by matchPreset, and only for this profile', () => {
    for (const preset of ['full', 'gateway', 'private'] as const) {
      expect(matchPreset(presetPrefixes(preset, dual), dual)).toBe(preset)
    }
    expect(matchPreset('fd3c:91a2:7e04::1/128, 100.64.0.1/32', dual)).toBe('gateway')
    // The IPv4-only gateway list is not «the gateway alone» for a dual-stack
    // profile, nor the dual-stack one for an IPv4-only profile.
    expect(matchPreset('100.64.0.1/32', dual)).toBe('custom')
    expect(matchPreset('100.64.0.1/32, fd3c:91a2:7e04::1/128', source())).toBe('custom')
    expect(leavesIpv6Uncaptured(presetPrefixes('gateway', dual))).toBe(false)
  })
})

describe('matchPreset', () => {
  it('recognises each preset it produced', () => {
    for (const preset of ['full', 'gateway', 'private'] as const) {
      expect(matchPreset(presetPrefixes(preset, source()), source())).toBe(preset)
    }
  })

  it('recognises a preset written in another order or spacing', () => {
    expect(
      matchPreset('192.168.0.0/16,172.16.0.0/12 , 10.0.0.0/8 , 100.64.0.1/32', source()),
    ).toBe('private')
  })

  it('recognises the full tunnel in either order', () => {
    expect(matchPreset('0.0.0.0/0, ::/0', source())).toBe('full')
    expect(matchPreset('::/0,0.0.0.0/0', source())).toBe('full')
  })

  // The full tunnel stored before `::/0` joined the default is not «Tout»
  // any more: lighting that button would tell the user IPv6 is captured.
  it('no longer reads the IPv4-only full tunnel as the full preset', () => {
    expect(matchPreset('0.0.0.0/0', source())).toBe('custom')
  })

  it('reports anything else as hand-written', () => {
    expect(matchPreset('192.168.1.0/24', source())).toBe('custom')
    expect(matchPreset('10.0.0.0/8, 172.16.0.0/12', source())).toBe('custom')
    expect(matchPreset('', source())).toBe('custom')
  })

  // The gateway preset follows the profile: the same list stops being "the
  // gateway alone" once the profile points at another one.
  it('follows the gateway the profile names', () => {
    expect(matchPreset('100.64.0.1/32', source({ heliosd_url: 'http://100.64.0.9:8080' }))).toBe(
      'custom',
    )
  })
})

// The same cases as `only_an_ipv4_only_full_tunnel_is_flagged` in
// `orion-core`: this is a mirror of `tunnel_capture`, and the two suites are
// what keeps it one.
describe('leavesIpv6Uncaptured', () => {
  it('flags the IPv4-only full tunnel and nothing else', () => {
    const cases: [string, boolean][] = [
      ['0.0.0.0/0', true],
      ['0.0.0.0/0, ::/0', false],
      ['100.64.0.1/32, 10.0.0.0/8', false],
      ['::/0', false],
      ['0.0.0.0/0, fd00::/8', true],
      ['::/0,0.0.0.0/0', false],
      [' 0.0.0.0/0 ,, ', true],
      ['  ::/0 , 10.0.0.0/8,0.0.0.0/0 ', false],
      ['10.1.2.3/0, 0::/0', false],
      ['0.0.0.0', false],
      ['0.0.0.0/0, ::/zero', true],
      ['', false],
    ]
    for (const [value, expected] of cases) {
      expect(leavesIpv6Uncaptured(value), JSON.stringify(value)).toBe(expected)
    }
  })

  it('agrees with the presets it sits beside', () => {
    expect(leavesIpv6Uncaptured(presetPrefixes('full', source()))).toBe(false)
    expect(leavesIpv6Uncaptured(presetPrefixes('private', source()))).toBe(false)
    expect(leavesIpv6Uncaptured(presetPrefixes('gateway', source()))).toBe(false)
  })
})
