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

/**
 * Every prefix, both families — mirrors `orion_core::DEFAULT_ALLOWED_IPS`.
 *
 * `::/0` even though the gateway routes no IPv6: what the adapter captures
 * and cannot deliver, WireGuard drops. With `0.0.0.0/0` alone, a dual-stack
 * machine sent its IPv6 around the tunnel, in clear.
 */
const EVERYTHING = '0.0.0.0/0, ::/0'

/**
 * The choice a prefix list expresses.
 *
 * `custom` is not a fourth value to write: it is what the other three fail to
 * recognise, which is exactly the case the text field exists for.
 */
export type SplitTunnelPreset = 'full' | 'gateway' | 'private' | 'custom'

/**
 * Presets that produce a value, in the order the screen offers them.
 *
 * Widest first: the list reads as a tunnel being closed down, and the default
 * a new profile carries is the one at the top.
 */
export const SPLIT_TUNNEL_PRESETS: Exclude<SplitTunnelPreset, 'custom'>[] = [
  'full',
  'private',
  'gateway',
]

/** What the profile needs to carry for a preset to be built from it. */
export type SplitTunnelSource = Pick<ClientProfile, 'heliosd_url' | 'ssh_target' | 'address_v6'>

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

/**
 * Groups of an IPv6 address, the `::` expanded: eight numbers, or `null`.
 *
 * Only the forms a tunnel address can take — hexadecimal groups and at most
 * one `::`. No embedded IPv4, no zone: `orion-core` refuses both in an
 * `address_v6`, so they never describe a gateway here.
 */
function ipv6Groups(host: string): number[] | null {
  if (!/^[0-9a-fA-F:]+$/.test(host)) return null
  const halves = host.split('::')
  if (halves.length > 2) return null
  const parse = (part: string) => (part === '' ? [] : part.split(':'))
  const head = parse(halves[0])
  const tail = halves.length === 2 ? parse(halves[1]) : []
  const missing = 8 - head.length - tail.length
  if (halves.length === 2 ? missing < 1 : missing !== 0) return null
  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill('0'), ...tail]
  if (!groups.every((group) => /^[0-9a-fA-F]{1,4}$/.test(group))) return null
  return groups.map((group) => parseInt(group, 16))
}

/**
 * The gateway's own IPv6 `/128`, when the profile has an IPv6 address.
 *
 * Fixed by `ADRESSAGE-IPV6.md` §2.4: the tunnel prefix is a `/64` and the
 * gateway is its host `::1`. So the gateway is the profile's `/64` with
 * `::1` as host — no field names it, and none has to. A missing or malformed
 * `address_v6` gives `null`: the core reports the field, and the preset stays
 * the IPv4 one.
 *
 * Written in the compressed form `std` renders on the gateway
 * (`fd3c:91a2:7e04::1/128`), so a preset read back from the core matches.
 */
export function gatewayPrefixV6(addressV6: string | null): string | null {
  if (!addressV6) return null
  const [host, prefixLength, ...rest] = addressV6.trim().split('/')
  if (rest.length > 0 || prefixLength !== '128') return null
  const groups = ipv6Groups(host)
  if (!groups) return null
  const gateway = [...groups.slice(0, 4), 0, 0, 0, 1].map((group) => group.toString(16))
  return `${compressIpv6(gateway)}/128`
}

/**
 * RFC 5952 text of eight lowercase hexadecimal groups: the longest run of at
 * least two zero groups, leftmost on a tie, becomes `::`.
 */
function compressIpv6(groups: string[]): string {
  let runStart = -1
  let runLength = 0
  let index = 0
  while (index < groups.length) {
    let end = index
    while (end < groups.length && groups[end] === '0') end += 1
    if (end - index > runLength) {
      runStart = index
      runLength = end - index
    }
    index = Math.max(end, index + 1)
  }
  if (runLength < 2) return groups.join(':')
  const before = groups.slice(0, runStart).join(':')
  const after = groups.slice(runStart + runLength).join(':')
  return `${before}::${after}`
}

/** The list a preset writes into the field. */
export function presetPrefixes(
  preset: Exclude<SplitTunnelPreset, 'custom'>,
  source: SplitTunnelSource,
): string {
  switch (preset) {
    case 'full':
      return EVERYTHING
    case 'gateway': {
      // Both of the gateway's addresses when the profile has IPv6: «the
      // gateway alone» must still reach it over IPv6 (`ping -6`), and the
      // gateway is `::1` of the profile's `/64` (§2.4). Without `address_v6`
      // the preset is exactly what it was.
      const v6 = gatewayPrefixV6(source.address_v6)
      return v6 ? `${gatewayPrefix(source)}, ${v6}` : gatewayPrefix(source)
    }
    case 'private':
      // The gateway's own prefix leads the list: without it the key
      // negotiation's post-commit release, which `orion_core` only sends to an
      // address inside `AllowedIPs`, would have nowhere to go.
      return [gatewayPrefix(source), ...PRIVATE_RANGES].join(', ')
  }
}

/**
 * The list captures all of IPv4 and lets IPv6 out.
 *
 * The full tunnel every profile carried before `::/0` joined the default: it
 * no longer reads as «Tout» (`matchPreset` finds `custom`), and the editor
 * warns on it rather than rewriting it — the stored list is the user's.
 *
 * A mirror of `orion_core::profile_import::tunnel_capture`, for the one case
 * the core cannot answer in time: the draft being typed. The stored profile's
 * verdict arrives from the core as `ipv6_uncaptured_full_tunnel`. Same rule,
 * same cases pinned by both test suites: an entry whose prefix length is zero
 * captures its whole family, and no other entry counts. A split tunnel is not
 * flagged — narrowing the capture is a decision, not a leak.
 *
 * The host checks here are looser than the core's IPv6 parser, so the two
 * agree on every list `inspect_profile` accepts; on a list it refuses, the
 * screen shows the core's error instead of this warning.
 */
export function leavesIpv6Uncaptured(value: string): boolean {
  let ipv4 = false
  let ipv6 = false
  for (const entry of splitPrefixes(value)) {
    const slash = entry.indexOf('/')
    if (slash < 0) continue
    const host = entry.slice(0, slash)
    const length = entry.slice(slash + 1)
    // `u8::from_str`, which the core uses: optional `+`, decimal digits.
    if (!/^\+?\d+$/.test(length) || Number(length) !== 0) continue
    if (isIpv4(host)) ipv4 = true
    else if (isIpv6(host)) ipv6 = true
  }
  return ipv4 && !ipv6
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
