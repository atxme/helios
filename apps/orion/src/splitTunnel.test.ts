import { describe, expect, it } from 'vitest'

import {
  gatewayPrefix,
  matchPreset,
  presetPrefixes,
  splitPrefixes,
  type SplitTunnelSource,
} from './splitTunnel'

const source = (overrides: Partial<SplitTunnelSource> = {}): SplitTunnelSource => ({
  heliosd_url: 'http://100.64.0.1:8080',
  ssh_target: null,
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
  it('captures everything', () => {
    expect(presetPrefixes('full', source())).toBe('0.0.0.0/0')
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
