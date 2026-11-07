import type {
  CampaignScope,
  GatewayDomainRead,
  OperatorAuthorityStatus,
  OperatorPendingOperation,
  Reach,
  RotationJournalView,
  RotationsOverview,
} from '../../types'

export type RotationAction =
  | 'finish_ca_tls'
  | 'resume'
  | 'renew_fleet'
  | 'replace_ca_pq'
  | 'replace_ca_tls'
  | 'renew_delegation'

export interface RotationRow {
  action: RotationAction
  title: string
  state: string
  due: boolean
  disabledReason: string | null
  /** The verb on the row's button. */
  button: string
}

export interface Prerequisite {
  label: string
  ok: boolean
  /** The corrective action in a word; `null` when nothing can be done from here. */
  fix: string | null
  fixAction: 'send_vault_copy' | null
  /** What was found, when it is more than red or green (« Absente », « Ancienne »). */
  detail: string | null
}

const DAY = 86_400
/**
 * « Expire bientôt »: the screen's own threshold. It is a prompt for the operator, not a
 * rule of the authority, which renews on its own schedule.
 */
export const EXPIRING_SOON_SECS = 30 * DAY

export const OVERLAP_PQ = 'Recouvrement CA-PQ en cours'
export const AUTHORITY_UNREAD = 'Autorité non lue'
const OVERLAP_TLS = 'Recouvrement CA TLS en cours'
const ROTATION_PENDING = 'Rotation à reprendre'
const VAULT_AHEAD = 'Le coffre a une époque d’avance'

const TITLES: Record<RotationAction, string> = {
  finish_ca_tls: 'Terminer la rotation CA TLS',
  resume: 'Reprendre une rotation',
  renew_fleet: 'Renouveler les postes',
  replace_ca_pq: 'Remplacer la CA-PQ',
  replace_ca_tls: 'Remplacer la CA TLS',
  renew_delegation: 'Renouveler la délégation',
}

const BUTTONS: Record<RotationAction, string> = {
  finish_ca_tls: 'Terminer',
  resume: 'Reprendre',
  renew_fleet: 'Renouveler',
  replace_ca_pq: 'Remplacer',
  replace_ca_tls: 'Remplacer',
  renew_delegation: 'Renouveler',
}

const SCOPES: Record<RotationAction, CampaignScope | null> = {
  finish_ca_tls: null,
  resume: null,
  renew_fleet: 'fleet_leafs',
  replace_ca_pq: 'trust_authorities',
  replace_ca_tls: 'trust_authorities',
  renew_delegation: 'issuer_delegation',
}

const STAGES: Record<RotationJournalView['stage'], string> = {
  signed: 'Signée',
  accepted: 'Acceptée',
  applied: 'Appliquée',
  installed: 'Installée',
}

const KINDS: Record<RotationJournalView['kind'], string> = {
  ca_pq: 'CA-PQ',
  ca_tls: 'CA TLS',
}

/** The value of a read, when it went through. */
export function valueOf<T>(reach: Reach<T>): T | null {
  return reach.state === 'ok' ? reach.value : null
}

/**
 * Fingerprints reach the page in two spellings: grouped by four with spaces on the vault
 * side, plain hexadecimal everywhere else. Compared only once both are plain.
 */
export function plainFingerprint(value: string): string {
  return value.replace(/\s+/g, '').toLowerCase()
}

const sameFingerprint = (a: string, b: string) => plainFingerprint(a) === plainFingerprint(b)

export function formatDate(seconds: number): string {
  return new Intl.DateTimeFormat('fr-FR', { dateStyle: 'medium', timeZone: 'Europe/Paris' }).format(
    new Date(seconds * 1_000),
  )
}

export function formatDateTime(seconds: number): string {
  return new Intl.DateTimeFormat('fr-FR', {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZone: 'Europe/Paris',
  }).format(new Date(seconds * 1_000))
}

/**
 * The instant the screen reasons from: the gateway's clock when it gave one. The
 * operator's own clock only stands in when the gateway did not answer with its time.
 */
export function effectiveNow(o: RotationsOverview, local: number): number {
  return valueOf(o.domain)?.now_unix ?? local
}

/** Why a read that did not go through did not, in a few words. */
export function reachLabel(reach: Reach<unknown>): string | null {
  switch (reach.state) {
    case 'ok':
      return null
    case 'not_admin':
      return 'Poste non administrateur'
    case 'astra_unavailable':
      return 'Astra indisponible'
    case 'throttled':
      return 'Gateway saturée'
    case 'unreachable':
      return 'Gateway injoignable'
    // A 404 is an older gateway, but any refusal looks the same from here.
    case 'refused':
      return `Gateway ancienne ou refus (${reach.value})`
  }
}

/** Why a CA-PQ overlap, or not knowing about one, suspends a launch; `null` when it does not. */
export function overlapReason(caPqOverlap: boolean | null): string | null {
  if (caPqOverlap === true) return OVERLAP_PQ
  if (caPqOverlap === null) return AUTHORITY_UNREAD
  return null
}

/**
 * The live operation of the scope an action opens, if the gateway lists one.
 *
 * The two CA rotations share a scope: the campaign covers both authorities and the CA-PQ
 * signature binds which one, so the row shows the operation's reason and nothing signed
 * can be the wrong one.
 */
export function liveOperation(
  o: RotationsOverview,
  action: RotationAction,
  local: number = Math.floor(Date.now() / 1000),
): OperatorPendingOperation | null {
  const scope = SCOPES[action]
  const pending = valueOf(o.pending)
  if (!scope || !pending) return null
  // An operation past its expiry on the gateway's clock is no longer one to resume.
  const now = effectiveNow(o, local)
  return pending.find((operation) => operation.scope === scope && operation.expires_at > now) ?? null
}

/** The activation keys the vault holds, whichever their role. */
export function keyCount(o: RotationsOverview): number {
  return (o.vault?.slots ?? []).filter((slot) => slot.state === null || slot.state === 'active')
    .length
}

/** A CA TLS overlap is open: the gateway says so, or the rotation awaits its end. */
function caTlsWindowOpen(o: RotationsOverview): boolean {
  return valueOf(o.domain)?.client_tls_ca_transition_pending === true || o.caTlsCloseAt !== null
}

function finishRow(o: RotationsOverview, now: number): RotationRow | null {
  if (o.caTlsCloseAt === null || now < o.caTlsCloseAt) return null
  return {
    action: 'finish_ca_tls',
    title: TITLES.finish_ca_tls,
    state: `À faire · fin le ${formatDate(o.caTlsCloseAt)}`,
    due: true,
    disabledReason: null,
    button: BUTTONS.finish_ca_tls,
  }
}

function resumeRow(o: RotationsOverview, now: number): RotationRow | null {
  if (!o.resumable) return null
  const journal = o.journal
  let state = 'À reprendre'
  if (journal) {
    const parts = [KINDS[journal.kind], STAGES[journal.stage]]
    if (journal.stage !== 'installed') {
      parts.push(
        now >= journal.activationAt
          ? `délai dépassé le ${formatDateTime(journal.activationAt)}`
          : `installation avant le ${formatDateTime(journal.activationAt)}`,
      )
    }
    state = parts.join(' · ')
  }
  return {
    action: 'resume',
    title: TITLES.resume,
    state,
    due: true,
    disabledReason: null,
    button: BUTTONS.resume,
  }
}

function fleetRow(o: RotationsOverview, now: number): RotationRow {
  const domain = valueOf(o.domain)
  let state: string
  let due = false
  if (!domain) {
    state = reachLabel(o.domain) ?? 'Postes non lus'
  } else {
    const count = domain.peers.length
    const noun = count > 1 ? 'postes' : 'poste'
    if (count === 0) {
      state = `0 ${noun}`
    } else {
      const nearest = Math.min(...domain.peers.map((peer) => peer.not_after))
      due = nearest - now < EXPIRING_SOON_SECS
      state = due
        ? `${count} ${noun} · Expire bientôt (${formatDate(nearest)})`
        : `${count} ${noun} · échéance le ${formatDate(nearest)}`
    }
  }
  return {
    action: 'renew_fleet',
    title: TITLES.renew_fleet,
    state,
    due,
    // An approval under the local document is refused after the touch, during the overlap.
    disabledReason: overlapReason(o.caPqOverlap),
    button: BUTTONS.renew_fleet,
  }
}

/** One CA rotation at a time: the reason the other is not offered, if there is one. */
function replaceBlock(o: RotationsOverview): string | null {
  if (o.caPqOverlap === true) return OVERLAP_PQ
  if (caTlsWindowOpen(o)) return OVERLAP_TLS
  if (o.resumable) return ROTATION_PENDING
  if (o.caPqOverlap === null) return AUTHORITY_UNREAD
  return null
}

function keysLabel(o: RotationsOverview): string {
  if (o.vaultError === 'illisible') return 'Coffre illisible'
  if (o.vaultError === 'emplacement') return 'Emplacement illisible'
  if (!o.vault?.exists) return 'Coffre absent'
  const count = keyCount(o)
  return `${count} ${count > 1 ? 'clés' : 'clé'}`
}

function replacePqRow(o: RotationsOverview): RotationRow {
  const retireAt = valueOf(o.domain)?.ca_retire_active_at ?? null
  const state =
    o.caPqOverlap === true
      ? retireAt !== null
        ? `Recouvrement jusqu’au ${formatDate(retireAt)}`
        : OVERLAP_PQ
      : keysLabel(o)
  return {
    action: 'replace_ca_pq',
    title: TITLES.replace_ca_pq,
    state,
    due: false,
    disabledReason: replaceBlock(o),
    button: BUTTONS.replace_ca_pq,
  }
}

function replaceTlsRow(o: RotationsOverview): RotationRow {
  let state: string
  if (caTlsWindowOpen(o)) {
    // The relay's certificate names the outgoing CA in a window: it is not an expiry.
    state =
      o.caTlsCloseAt !== null
        ? `Recouvrement jusqu’au ${formatDate(o.caTlsCloseAt)}`
        : OVERLAP_TLS
  } else if (o.localCaTlsNotAfter !== null) {
    state = `Expire le ${formatDate(o.localCaTlsNotAfter)} · ${keysLabel(o)}`
  } else {
    state = keysLabel(o)
  }
  return {
    action: 'replace_ca_tls',
    title: TITLES.replace_ca_tls,
    state,
    due: false,
    disabledReason: replaceBlock(o),
    button: BUTTONS.replace_ca_tls,
  }
}

function delegationRow(o: RotationsOverview, now: number): RotationRow {
  const authority = valueOf(o.authority)
  const domain = valueOf(o.domain)
  const issuer = authority?.issuer ?? null
  const notes: string[] = []
  let due = false
  let disabledReason: string | null = null

  if (!authority) {
    notes.push(reachLabel(o.authority) ?? AUTHORITY_UNREAD)
  } else if (!issuer) {
    notes.push('Aucune délégation')
  } else {
    notes.push(`échéance le ${formatDate(issuer.not_after)}`)
    if (issuer.not_after - now < EXPIRING_SOON_SECS) due = true
    if (issuer.serving_epoch !== issuer.recorded_epoch) {
      notes.push(
        issuer.serving_epoch === null
          ? `époque servie absente, inscrite ${issuer.recorded_epoch}`
          : `époque servie ${issuer.serving_epoch}, inscrite ${issuer.recorded_epoch}`,
      )
    }
    if (domain) {
      const behind =
        issuer.ca_epoch !== domain.ca_epoch || issuer.ca_tls_epoch !== domain.ca_tls_epoch
      const same =
        o.localCaEpoch === domain.ca_epoch &&
        (o.localCaTlsEpoch === null || o.localCaTlsEpoch === domain.ca_tls_epoch)
      if (behind && same) due = true
      if (behind) notes.push('ne suit plus la CA')
    }
  }

  if (domain) {
    const ahead =
      (o.localCaEpoch !== null && o.localCaEpoch > domain.ca_epoch) ||
      (o.localCaTlsEpoch !== null && o.localCaTlsEpoch > domain.ca_tls_epoch)
    if (ahead) {
      disabledReason = VAULT_AHEAD
      due = false
    }
  }
  // Its request came only in the answer to the opening: an open delegation cannot be
  // resumed, and a new opening is offered once the window closes.
  const open = liveOperation(o, 'renew_delegation', now)
  if (open) disabledReason ??= `Opération ouverte jusqu’au ${formatDateTime(open.expires_at)}`
  // Every approval under the local document is refused during a CA-PQ overlap.
  disabledReason ??= overlapReason(o.caPqOverlap)

  const state = due ? `À faire · ${notes.join(' · ')}` : notes.join(' · ')
  return {
    action: 'renew_delegation',
    title: TITLES.renew_delegation,
    state,
    due,
    disabledReason,
    button: BUTTONS.renew_delegation,
  }
}

/** The rows in the order of the spec; a row to do comes first, the order kept otherwise. */
export function rotationRows(o: RotationsOverview, local: number): RotationRow[] {
  const now = effectiveNow(o, local)
  const rows = [
    finishRow(o, now),
    resumeRow(o, now),
    fleetRow(o, now),
    replacePqRow(o),
    replaceTlsRow(o),
    delegationRow(o, now),
  ].filter((row): row is RotationRow => row !== null)
  return [...rows.filter((row) => row.due), ...rows.filter((row) => !row.due)]
}

function adminPrerequisites(o: RotationsOverview): [Prerequisite, Prerequisite] {
  const state = o.pending.state
  const reached = state === 'ok' || state === 'throttled'
  const down = state === 'unreachable' || state === 'refused'
  const detail = down ? reachLabel(o.pending) : null
  return [
    {
      label: 'Administrateur du tunnel',
      ok: reached || state === 'astra_unavailable',
      fix: state === 'not_admin' ? 'Utiliser un poste administrateur' : down ? 'Vérifier' : null,
      fixAction: null,
      detail: state === 'not_admin' ? null : detail,
    },
    {
      label: 'Service Astra',
      ok: reached,
      fix: state === 'astra_unavailable' ? 'Démarrer Astra' : down ? 'Vérifier' : null,
      fixAction: null,
      detail: state === 'astra_unavailable' ? null : detail,
    },
  ]
}

function vaultPrerequisite(o: RotationsOverview): Prerequisite {
  const ok = o.vault?.exists === true
  let fix: string | null = null
  let detail: string | null = null
  if (!ok) {
    if (o.vaultError === 'illisible') detail = 'Illisible'
    else if (o.vaultError === 'emplacement') detail = 'Emplacement illisible'
    else detail = 'Absent'
    fix = o.vaultError === null ? 'Créer le coffre' : 'Vérifier l’emplacement'
  }
  return { label: 'Coffre présent', ok, fix, fixAction: null, detail }
}

function keysPrerequisite(o: RotationsOverview): Prerequisite {
  const ok = o.vault?.credentials_complete === true && keyCount(o) >= 2
  return {
    label: 'Deux clés enregistrées',
    ok,
    fix: ok ? null : 'Enregistrer une seconde clé',
    fixAction: null,
    detail: null,
  }
}

function copyPrerequisite(o: RotationsOverview): Prerequisite {
  const label = 'Copie du coffre'
  const authority: OperatorAuthorityStatus | null = valueOf(o.authority)
  if (!authority) {
    return { label, ok: false, fix: null, fixAction: null, detail: reachLabel(o.authority) }
  }
  const held = authority.vault_copy_fingerprint
  const local = o.localVaultFingerprint
  if (held !== null && local !== null && sameFingerprint(held, local)) {
    return { label, ok: true, fix: null, fixAction: null, detail: null }
  }
  // Nothing to send when the vault itself cannot be read.
  const sendable = local !== null
  return {
    label,
    ok: false,
    fix: sendable ? 'Envoyer' : null,
    fixAction: sendable ? 'send_vault_copy' : null,
    detail: held === null ? 'Absente' : 'Ancienne',
  }
}

function domainPrerequisite(o: RotationsOverview): Prerequisite {
  const label = 'Domaine concordant'
  const domain: GatewayDomainRead | null = valueOf(o.domain)
  const authority = valueOf(o.authority)
  const vaultAnchor = o.vault?.domain?.ca_pq_fingerprint ?? null
  if (!domain && !authority) {
    return { label, ok: false, fix: 'Vérifier', fixAction: null, detail: reachLabel(o.domain) }
  }
  if (vaultAnchor === null) {
    return { label, ok: false, fix: 'Vérifier le coffre', fixAction: null, detail: 'Coffre sans domaine' }
  }
  // The current anchor, or the next one while a CA-PQ overlap is running.
  const served = [
    domain?.ca_fingerprint,
    domain?.next_ca_fingerprint,
    authority?.ca_fingerprint,
    authority?.next_ca_fingerprint,
  ].filter((anchor): anchor is string => typeof anchor === 'string' && anchor !== '')
  const ok = served.some((anchor) => sameFingerprint(anchor, vaultAnchor))
  return {
    label,
    ok,
    fix: ok ? null : 'Vérifier le domaine',
    fixAction: null,
    detail: ok ? null : 'Autre domaine',
  }
}

/** The checks before an action, one line each. A red line stops the next step. */
export function prerequisites(o: RotationsOverview, action: RotationAction): Prerequisite[] {
  const [admin, astra] = adminPrerequisites(o)
  const lines: Prerequisite[] = [
    {
      label: 'Tunnel connecté',
      ok: o.tunnel,
      fix: o.tunnel ? null : 'Connecter',
      fixAction: null,
      detail: null,
    },
    admin,
    astra,
    vaultPrerequisite(o),
  ]
  if (action === 'replace_ca_pq' || action === 'replace_ca_tls') {
    lines.push(keysPrerequisite(o), copyPrerequisite(o))
  }
  // The door asks for the copy of the vault for every scope but the workstations'.
  if (action === 'renew_delegation') lines.push(copyPrerequisite(o))
  lines.push(domainPrerequisite(o))
  return lines
}

export const allGreen = (lines: Prerequisite[]) => lines.every((line) => line.ok)

/**
 * The sentence of a stop that gives its cause and its recourse. `astra-signer rotate-ca-pq`
 * is named only for a rotation signed offline: for one Orion carries, the command could
 * conflict with it.
 */
export function stopSentence(
  refusal: 'domain_conflict' | 'install_deadline_passed' | 'gateway_names_no_anchor',
  journal: RotationJournalView | null,
): string {
  if (refusal === 'install_deadline_passed') {
    // The cut date is where Astra moves alone and the gateway stays on the old anchor.
    return journal
      ? `Délai dépassé le ${formatDateTime(journal.activationAt)}. ` +
          `Coupure le ${formatDateTime(journal.notAfter)}. Intervention manuelle requise.`
      : 'Délai dépassé. Intervention manuelle requise.'
  }
  if (refusal === 'gateway_names_no_anchor') {
    // Not an update as the only cause: an up-to-date gateway with no CA TLS reads the same.
    return journal?.kind === 'ca_pq'
      ? 'Gateway sans CA-PQ suivante, ou mise à jour requise. Rotation conservée.'
      : 'Gateway sans CA TLS, ou mise à jour requise. Rotation conservée.'
  }
  return journal?.kind === 'ca_pq' && journal.offline
    ? 'Domaine en désaccord. Intervention manuelle requise : astra-signer rotate-ca-pq.'
    : 'Domaine en désaccord. Intervention manuelle requise.'
}

/**
 * What a journal in flight says wherever the operator is, with no session to carry it:
 * the install deadline, or the cut that passed. Blocking when no repair exists any more.
 */
export function journalLine(
  journal: RotationJournalView,
  now: number,
): { text: string; blocking: boolean } {
  const kind = KINDS[journal.kind]
  if (journal.stage === 'installed') {
    return { text: `Rotation ${kind} · copie du coffre en attente`, blocking: false }
  }
  if (now >= journal.activationAt) {
    return { text: stopSentence('install_deadline_passed', journal), blocking: true }
  }
  return {
    text: `Rotation ${kind} · à installer avant le ${formatDateTime(journal.activationAt)}`,
    blocking: false,
  }
}
