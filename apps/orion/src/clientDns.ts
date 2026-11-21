/**
 * The tunnel's resolver list, as the profile editor reads it.
 *
 * Mirror of the rule `aether::client_dns` applies on save: IPv4, public
 * unicast, no repeat, at most three. The engine judges the list again; this
 * only refuses at the keyboard what it would refuse on save. Keep the two in
 * step.
 */

export const CLIENT_DNS_MAX = 3

/**
 * The field's text as a list. Empty means no list (`null`), never one empty
 * entry. Entries are trimmed but not judged: {@link clientDnsError} does that.
 */
export function parseClientDns(text: string): string[] | null {
  if (text.trim() === '') return null
  return text.split(',').map((entry) => entry.trim())
}

/** The first thing wrong with a list, for the field. `null` = acceptable. */
export function clientDnsError(dns: string[] | null): string | null {
  if (dns === null) return null
  for (const entry of dns) {
    if (!isPublicIpv4(entry)) return `Adresse IPv4 publique attendue : ${entry}`
  }
  const repeated = dns.find((entry, index) => dns.indexOf(entry) !== index)
  if (repeated !== undefined) return `Adresse en double : ${repeated}`
  if (dns.length > CLIENT_DNS_MAX) return `${CLIENT_DNS_MAX} adresses au plus`
  return null
}

/**
 * A dotted quad without leading zeros, outside the private, shared, loopback,
 * link-local, reserved and multicast blocks.
 */
function isPublicIpv4(address: string): boolean {
  const octets = address.split('.')
  if (octets.length !== 4) return false
  if (!octets.every((octet) => /^(0|[1-9]\d{0,2})$/.test(octet) && Number(octet) <= 255)) {
    return false
  }
  const [a, b] = octets.map(Number)
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false
  if (a === 100 && b >= 64 && b <= 127) return false
  if (a === 169 && b === 254) return false
  if (a === 172 && b >= 16 && b <= 31) return false
  if (a === 192 && b === 168) return false
  return true
}
