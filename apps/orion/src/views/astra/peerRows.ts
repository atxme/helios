import type { PeerCertificateRead, PeersOverview, Reach } from '../../types'

/**
 * The states of the Postes tab. They are computed from the reads at each opening and never
 * stored on this machine (spec §5.1).
 */
export const STATE = {
  ACTIVE: 'Actif',
  RENEWING: 'Renouvellement en cours',
  CUT: 'Coupé, révocation à signer',
  REVOKED: 'Révoqué',
  REVOKED_NOT_INFORMED: 'Révoqué, gateway pas encore informée',
  UNKNOWN: 'État inconnu',
} as const

/** Said on a row whose key Astra already has a revocation open for, with no record here. */
export const PENDING_AT_ASTRA = 'Révocation déjà ouverte chez Astra.'

/** The line of the workstation this screen runs on: its cut is made at the gateway. */
export const ownLine = (name: string) => `Se coupe sur la gateway : helios peer revoke ${name}.`

export interface PeerRow {
  key: string
  name: string
  /** The admission date: shown only when two rows carry the same name. */
  addedAt?: number
  state: string
  /** The expiry of the active certificate. */
  notAfter: number
  own: boolean
  action: 'revoke' | 'resume' | null
  /** Why there is no action, or what the row is about, when it is more than its state. */
  reason?: string
}

const valueOf = <T>(reach: Reach<T>): T | null => (reach.state === 'ok' ? reach.value : null)

/**
 * The state of one registry peer. The admission is matched by WireGuard key, never by name.
 * A peer revoked at Astra reads as not yet informed while the gateway still admits it or its
 * registry certificate is not revoked: Astra may have recorded a revocation the gateway lacks
 * (spec §5.7). Revoked reads only once the gateway holds it too.
 * Without Astra's list, an admitted peer reads as active and a cut one as unknown: revoked and
 * cut cannot be told apart from here.
 */
function stateOf(
  peer: PeerCertificateRead,
  admitted: Set<string> | null,
  revoked: Set<string> | null,
): string {
  if (admitted === null) return STATE.UNKNOWN
  const isAdmitted = admitted.has(peer.wg_public_key)
  const active = peer.renewing ? STATE.RENEWING : STATE.ACTIVE
  if (revoked === null) return isAdmitted ? active : STATE.UNKNOWN
  if (revoked.has(peer.wg_public_key)) {
    return isAdmitted || !peer.revoked ? STATE.REVOKED_NOT_INFORMED : STATE.REVOKED
  }
  return isAdmitted ? active : STATE.CUT
}

/** What a row can do. A row with a local decision resumes whatever its state. */
function actionOf(
  row: { key: string; name: string; state: string; own: boolean },
  o: PeersOverview,
  pending: Set<string> | null,
): Pick<PeerRow, 'action' | 'reason'> {
  if (row.own) return { action: null, reason: ownLine(row.name) }
  if (o.local_pending === row.key) return { action: 'resume' }
  if (pending?.has(row.key)) return { action: null, reason: PENDING_AT_ASTRA }
  if (row.state === STATE.ACTIVE || row.state === STATE.RENEWING) return { action: 'revoke' }
  if (row.state === STATE.CUT) return { action: 'resume' }
  return { action: null }
}

/** One row per registry peer, revoked ones included. No certificate read means no row. */
export function peerRows(o: PeersOverview): PeerRow[] {
  const peers = valueOf(o.certificates)
  if (!peers) return []
  const admittedList = valueOf(o.admitted)
  const admitted = admittedList ? new Set(admittedList.map((peer) => peer.wg_public_key)) : null
  const revokedList = valueOf(o.astra_revoked)
  const revoked = revokedList ? new Set(revokedList) : null
  const pendingList = valueOf(o.pending_revocations)
  const pending = pendingList ? new Set(pendingList) : null

  const rows = peers.map((peer) => {
    const key = peer.wg_public_key
    const own = o.own_key !== null && key === o.own_key
    const base = {
      key,
      name: peer.name,
      state: stateOf(peer, admitted, revoked),
      notAfter: peer.not_after,
      own,
    }
    return { ...base, ...actionOf(base, o, pending), addedAt: peer.not_before }
  })

  const namesUsed = new Map<string, number>()
  for (const row of rows) namesUsed.set(row.name, (namesUsed.get(row.name) ?? 0) + 1)
  return rows.map(({ addedAt, ...row }) =>
    (namesUsed.get(row.name) ?? 0) > 1 ? { ...row, addedAt } : row,
  )
}
