/**
 * Split tunnelling, expressed as choices rather than as a prefix list.
 *
 * `AllowedIPs` is WireGuard's cryptographic routing table and the profile
 * screen has always let it be typed, character by character. It still does —
 * a corporate profile routes subnets no preset can guess, and taking the
 * field away to gain three buttons would trade the general case for the
 * frequent one.
 *
 * What the buttons add is the frequent one. Moving between "everything goes
 * through the tunnel" and "only the gateway does" is a routine decision —
 * switch it on to reach an internal service, switch it off to stop paying the
 * tunnel for the rest — and it was, until now, a prefix to remember and
 * retype in both directions.
 *
 * # These helpers hold no validation
 *
 * They build and recognise values; whether a value is acceptable stays with
 * `orion-core::inspect_profile`, which the screen already queries on every
 * edit. Duplicating the grammar here is how the UI ends up approving a route
 * WireGuard never installs.
 */

import type { ClientProfile } from './types'

/**
 * Gateway address assumed when the profile names none.
 *
 * Mirrors `aether::config::DEFAULT_WG_ADDRESS`, the address every Helios
 * gateway carries unless its operator changed it. A guess, and it is written
 * into a field the user is looking at: if it is wrong for this gateway, the
 * value is on screen and editable at the same moment it appears.
 */
const DEFAULT_GATEWAY_HOST = '100.64.0.1'

/**
 * RFC 1918 ranges — what "reach the network behind the gateway" means when
 * the client has no way of knowing which subnets live there.
 *
 * A profile does not carry the gateway's LAN: nothing in `ClientProfile`
 * describes it, and nothing in the negotiation announces it. Sending the
 * three private ranges captures any of them, at a cost the screen states
 * where the choice is made — the machine's *own* LAN goes through the tunnel
 * too.
 */
const PRIVATE_RANGES = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'] as const

/** Every prefix, v4. */
const EVERYTHING = '0.0.0.0/0'

/**
 * The choice a prefix list expresses.
 *
 * `custom` is not a fourth value to write: it is what the other three fail to
 * recognise, which is exactly the case the text field exists for.
 */
export type SplitTunnelPreset = 'full' | 'gateway' | 'private' | 'custom'

/** Presets that produce a value, in the order the screen offers them. */
export const SPLIT_TUNNEL_PRESETS: Exclude<SplitTunnelPreset, 'custom'>[] = [
  'full',
  'gateway',
  'private',
]

/** What the profile needs to carry for a preset to be built from it. */
export type SplitTunnelSource = Pick<ClientProfile, 'heliosd_url' | 'ssh_target'>

/**
 * Splits a prefix list the way `orion_core::profile_import::split_cidr_list`
 * does, so the screen and the core read one list identically.
 */
export function splitPrefixes(value: string): string[] {
  return value
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0)
}

function isIpv4(host: string): boolean {
  const octets = host.split('.')
  if (octets.length !== 4) return false
  return octets.every(
    (octet) =>
      /^\d{1,3}$/.test(octet) && Number(octet) <= 255 && (octet === '0' || !octet.startsWith('0')),
  )
}

function isIpv6(host: string): boolean {
  return host.includes(':') && /^[0-9a-fA-F:.]+$/.test(host)
}

/** Host part of an `http://host:port` origin, brackets stripped for IPv6. */
function hostOfUrl(url: string | null): string | null {
  if (!url) return null
  try {
    const hostname = new URL(url).hostname
    return hostname.replace(/^\[|\]$/g, '') || null
  } catch {
    return null
  }
}

/** Host part of a `user@host` SSH destination. */
function hostOfSshTarget(target: string | null): string | null {
  if (!target) return null
  const host = target.includes('@') ? target.slice(target.lastIndexOf('@') + 1) : target
  return host.length > 0 ? host : null
}

function hostPrefix(host: string): string | null {
  if (isIpv4(host)) return `${host}/32`
  if (isIpv6(host)) return `${host}/128`
  return null
}

/**
 * The single prefix that routes the gateway and nothing else.
 *
 * Read from what the profile already states about the gateway's inside
 * address — the internal Helios URL first, since `orion_core` requires that
 * one to be an IP literal covered by `AllowedIPs`, then the SSH destination.
 * A name resolves to nothing here: a prefix is an address, and Orion's DNS is
 * not tunnelled.
 */
export function gatewayPrefix(source: SplitTunnelSource): string {
  const fromUrl = hostOfUrl(source.heliosd_url)
  const fromSsh = hostOfSshTarget(source.ssh_target)
  for (const host of [fromUrl, fromSsh]) {
    if (!host) continue
    const prefix = hostPrefix(host)
    if (prefix) return prefix
  }
  return `${DEFAULT_GATEWAY_HOST}/32`
}

/** The list a preset writes into the field. */
export function presetPrefixes(
  preset: Exclude<SplitTunnelPreset, 'custom'>,
  source: SplitTunnelSource,
): string {
  switch (preset) {
    case 'full':
      return EVERYTHING
    case 'gateway':
      return gatewayPrefix(source)
    case 'private':
      // The gateway's own prefix leads the list: without it the key
      // negotiation's post-commit release, which `orion_core` only sends to an
      // address inside `AllowedIPs`, would have nowhere to go.
      return [gatewayPrefix(source), ...PRIVATE_RANGES].join(', ')
  }
}

/**
 * Which preset a list expresses, `custom` if none.
 *
 * Compared as a set: a user who wrote the same prefixes in another order made
 * the same decision, and a button that refuses to light up for it would read
 * as the value having been rejected.
 */
export function matchPreset(value: string, source: SplitTunnelSource): SplitTunnelPreset {
  const written = [...splitPrefixes(value)].sort()
  for (const preset of SPLIT_TUNNEL_PRESETS) {
    const expected = [...splitPrefixes(presetPrefixes(preset, source))].sort()
    if (
      written.length === expected.length &&
      written.every((entry, index) => entry === expected[index])
    ) {
      return preset
    }
  }
  return 'custom'
}
