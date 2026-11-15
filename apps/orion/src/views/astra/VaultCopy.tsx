import { useCallback, useEffect, useState, useSyncExternalStore } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Paper from '@mui/material/Paper'
import Typography from '@mui/material/Typography'

import * as api from '../../api'
import type { OperationKind, OperatorStatus, RotationsOverview, VaultCopyOutcome } from '../../types'
import { PrerequisiteLine } from './PrerequisiteLine'
import { valueOf, vaultCopyPrerequisite } from './rotationRows'

/** The gestures that re-sign the credential document (spec §5.9). */
const KEY_CHANGES: OperationKind[] = ['add_key', 'remove_key', 'mark_key']

export const COPY_SENT = 'Copie du coffre et document de credentials envoyés à Astra'
const DOCUMENT_WAITS = 'Copie envoyée · document de credentials en attente (rotation en cours)'
const HELD_BACK = 'Copie retenue par une opération en cours · à renvoyer ensuite'
/** During a CA-PQ overlap, a document newer than Astra's waits for the overlap's end (N2). */
const DOCUMENT_WAITS_OVERLAP = 'Document en attente de la fin du recouvrement'
export const STALE_REFUSAL =
  'Astra tient un coffre plus récent que celui de ce poste, ou qui a divergé. Récupérez le coffre à jour sur le poste qui le tient.'
const REPLACE_BUTTON = 'Remplacer quand même'
const REPLACE_WARNING =
  'La copie d’Astra sera remplacée par ce coffre. À ne faire que si vous savez que la copie d’Astra est fausse.'

/** What a send came to, said: a copy held back or a document left out is never silent. */
function outcomeLine(outcome: VaultCopyOutcome): { text: string; complete: boolean } {
  if (outcome.state === 'held_back') return { text: HELD_BACK, complete: false }
  if (outcome.state === 'stale') return { text: STALE_REFUSAL, complete: false }
  if (outcome.document_waits) return { text: DOCUMENT_WAITS, complete: false }
  return { text: COPY_SENT, complete: true }
}

/**
 * A send held back, refused as stale or failed and not yet delivered, with the vault it was meant
 * for and the session that sent it. A stale refusal is offered the forced replacement instead of a
 * retry. It is kept outside the components, as the sent-once set is, so the line and its buttons
 * survive a change of view.
 */
type Unsettled = { text: string; vault: string | null; sessionId: string | null; stale: boolean }

let unsettled: Unsettled | null = null
const unsettledListeners = new Set<() => void>()

function setUnsettled(next: Unsettled | null) {
  unsettled = next
  for (const listener of unsettledListeners) listener()
}

/**
 * A copy for this vault, or a retry from this session, reached Astra: the entry it settles goes.
 * An entry is never cleared by another vault's copy.
 */
function clearUnsettled(vault: string | null, sessionId: string | null) {
  const current = unsettled
  if (!current) return
  const sameVault = vault !== null && current.vault === vault
  const sameSession = sessionId !== null && current.sessionId === sessionId
  if (sameVault || sameSession) setUnsettled(null)
}

function subscribeUnsettled(listener: () => void) {
  unsettledListeners.add(listener)
  return () => {
    unsettledListeners.delete(listener)
  }
}

function useUnsettled(): Unsettled | null {
  return useSyncExternalStore(subscribeUnsettled, () => unsettled)
}

/** For tests only: the store outlives a rendered view, so each test starts with none. */
export function resetForTests(): void {
  setUnsettled(null)
}

/** The local vault's fingerprint, and whether a forced replacement is offered (nothing to resume). */
type VaultRead = { vault: string | null; canReplace: boolean }

async function readVault(): Promise<VaultRead> {
  try {
    const found = await api.operatorRotationsOverview()
    return { vault: found.localVaultFingerprint ?? null, canReplace: !found.resumable }
  } catch {
    return { vault: null, canReplace: false }
  }
}

/**
 * Sends the vault copy through the manual send, or forces it over a newer copy Astra holds. A send
 * held back, refused as stale or failed stays on the line until a send for the same vault goes
 * through; the outcome of one that reached Astra is returned.
 */
async function sendVaultCopy(
  vault: string | null,
  sessionId: string | null,
  replaceNewer = false,
): Promise<{ text: string; complete: boolean } | null> {
  try {
    const outcome = await api.operatorSendVaultCopy(replaceNewer)
    if (outcome.state === 'held_back') {
      setUnsettled({ text: HELD_BACK, vault, sessionId, stale: false })
    } else if (outcome.state === 'stale') {
      setUnsettled({ text: STALE_REFUSAL, vault, sessionId, stale: true })
    } else {
      clearUnsettled(vault, sessionId)
    }
    return outcomeLine(outcome)
  } catch (cause) {
    setUnsettled({
      text: `Copie non envoyée à Astra : ${String(cause)}`,
      vault,
      sessionId,
      stale: false,
    })
    return null
  }
}

/**
 * The entry kept for a send. A stale one offers « Remplacer quand même », and only when no rotation
 * is to be resumed, since the backend refuses a forced send then; otherwise it offers a retry.
 */
function UnsettledAlert({
  text,
  stale,
  canReplace,
  sending,
  onRetry,
  onReplace,
}: {
  text: string
  stale: boolean
  canReplace: boolean
  sending: boolean
  onRetry: () => void
  onReplace: () => void
}) {
  const replace = stale && canReplace
  return (
    <Alert
      severity="warning"
      variant="outlined"
      sx={{ mt: 1, fontSize: 11.5, alignItems: 'center' }}
      action={
        stale ? (
          replace ? (
            <Button
              size="small"
              color="inherit"
              disabled={sending}
              onClick={onReplace}
              sx={{ fontSize: 11, whiteSpace: 'nowrap' }}
            >
              {REPLACE_BUTTON}
            </Button>
          ) : null
        ) : (
          <Button
            size="small"
            color="inherit"
            disabled={sending}
            onClick={onRetry}
            sx={{ fontSize: 11, whiteSpace: 'nowrap' }}
          >
            Réessayer l’envoi
          </Button>
        )
      }
    >
      {text}
      {replace && (
        <Typography component="span" sx={{ display: 'block', mt: 0.5, fontSize: 11 }}>
          {REPLACE_WARNING}
        </Typography>
      )}
    </Alert>
  )
}

/** Sessions whose key change was already sent: a view mounted again sends it once only. */
const sentAfter = new Set<string>()

/**
 * After a key added, removed or marked: Orion sends the vault copy, and the credential
 * document with it when it is newer than Astra's, through the manual send. Astra would
 * otherwise go on serving the document in which a lost key is still active.
 */
export function KeyChangeCopy({ status }: { status: OperatorStatus }) {
  const applies = status.gesture === 'done' && KEY_CHANGES.includes(status.operation)
  const pending = useUnsettled()
  const [vault, setVault] = useState<string | null>(null)
  const [canReplace, setCanReplace] = useState(false)
  const [line, setLine] = useState<{ text: string; complete: boolean } | null>(null)
  const [sending, setSending] = useState(false)

  const send = useCallback(
    async (replaceNewer = false) => {
      setSending(true)
      const found = await readVault()
      setVault(found.vault)
      setCanReplace(found.canReplace)
      setLine(await sendVaultCopy(found.vault, status.session_id, replaceNewer))
      setSending(false)
    },
    [status.session_id],
  )

  useEffect(() => {
    if (!applies) return
    void readVault().then((found) => {
      setVault(found.vault)
      setCanReplace(found.canReplace)
    })
  }, [applies])

  useEffect(() => {
    if (!applies || sentAfter.has(status.session_id)) return
    sentAfter.add(status.session_id)
    void send()
  }, [applies, status.session_id, send])

  if (!applies) return null
  // An entry of this session, or of this vault, is what this screen answers for.
  const unsent =
    pending !== null &&
    (pending.sessionId === status.session_id || (vault !== null && pending.vault === vault))
  if (unsent && pending) {
    return (
      <UnsettledAlert
        text={pending.text}
        stale={pending.stale}
        canReplace={canReplace}
        sending={sending}
        onRetry={() => void send()}
        onReplace={() => void send(true)}
      />
    )
  }
  if (!line) {
    return sending ? (
      <Typography color="text.secondary" sx={{ mt: 1, fontSize: 11.5 }}>
        Envoi de la copie du coffre à Astra…
      </Typography>
    ) : null
  }
  return (
    <Alert
      severity={line.complete ? 'success' : 'warning'}
      variant="outlined"
      sx={{ mt: 1, fontSize: 11.5 }}
    >
      {line.text}
    </Alert>
  )
}

/**
 * Whether a document newer than Astra's waits for a CA-PQ overlap to end: during the overlap
 * the send leaves the document out, and Astra adopts its own at the promotion.
 */
function documentWaitsForOverlap(o: RotationsOverview): boolean {
  const authority = valueOf(o.authority)
  const local = o.localCredentialRegistryEpoch
  if (!authority || !authority.next_ca_fingerprint || local === null) return false
  const served = authority.credential_registry_epoch
  return served === null || local > served
}

/**
 * « Copie du coffre » in Coffre et clés: the line the rotations read, with its « Envoyer ».
 * Shown once the tunnel is up; without it nothing here can be sent.
 */
export function VaultCopyLine() {
  const [overview, setOverview] = useState<RotationsOverview | null>(null)
  const [busy, setBusy] = useState(false)
  const [subscriptionError, setSubscriptionError] = useState<string | null>(null)
  const pending = useUnsettled()

  const read = useCallback(async () => {
    try {
      const found = await api.operatorRotationsOverview()
      if (!found) return
      setOverview(found)
      // A current copy has arrived, by whichever route: a send that failed before is not owed.
      if (vaultCopyPrerequisite(found).ok) clearUnsettled(found.localVaultFingerprint ?? null, null)
    } catch {
      // Unread stays unshown: this line is a reminder, the Rotations tab reports reads.
    }
  }, [])

  useEffect(() => {
    void read()
  }, [read])

  // The edge into `Up` is the one Rust takes a rotation up on (spec §5.4): the line reads again.
  useEffect(() => {
    let cancelled = false
    let unlisten: (() => void) | undefined
    void api
      .onEvent((event) => {
        if (event.type === 'state_changed' && event.state === 'up') void read()
      })
      .then((stop) => {
        if (cancelled) stop()
        else unlisten = stop
      })
      .catch((cause) => {
        if (!cancelled) setSubscriptionError(String(cause))
      })
    return () => {
      cancelled = true
      unlisten?.()
    }
  }, [read])

  if (!overview?.tunnel || !overview.vault?.exists) return null
  const prerequisite = vaultCopyPrerequisite(overview)
  const line = documentWaitsForOverlap(overview)
    ? { ...prerequisite, detail: DOCUMENT_WAITS_OVERLAP }
    : prerequisite
  const vault = overview.localVaultFingerprint ?? null
  // Only an entry for this vault: another vault's failure is not this line's to show.
  const unsent = pending !== null && vault !== null && pending.vault === vault ? pending : null

  const sendCopy = async (replaceNewer = false) => {
    setBusy(true)
    await sendVaultCopy(vault, null, replaceNewer)
    await read()
    setBusy(false)
  }

  return (
    <Paper variant="outlined" sx={{ p: 1.75 }}>
      <Typography component="h3" sx={{ fontSize: 12.5, fontWeight: 700, mb: 0.5 }}>
        Astra
      </Typography>
      <Box component="ul" sx={{ m: 0, p: 0 }}>
        <PrerequisiteLine line={line} busy={busy} onFix={() => void sendCopy()} />
      </Box>
      {unsent && (
        <UnsettledAlert
          text={unsent.text}
          stale={unsent.stale}
          canReplace={!overview.resumable}
          sending={busy}
          onRetry={() => void sendCopy()}
          onReplace={() => void sendCopy(true)}
        />
      )}
      {subscriptionError && (
        <Alert severity="error" variant="outlined" sx={{ mt: 1, fontSize: 11.5 }}>
          {`Suivi du tunnel impossible : ${subscriptionError}`}
        </Alert>
      )}
    </Paper>
  )
}
