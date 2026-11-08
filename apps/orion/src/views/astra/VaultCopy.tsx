import { useCallback, useEffect, useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Paper from '@mui/material/Paper'
import Typography from '@mui/material/Typography'

import * as api from '../../api'
import type { OperationKind, OperatorStatus, RotationsOverview, VaultCopyOutcome } from '../../types'
import { PrerequisiteLine } from './RotationsPanel'
import { vaultCopyPrerequisite } from './rotationRows'

/** The gestures that re-sign the credential document (spec §5.9). */
const KEY_CHANGES: OperationKind[] = ['add_key', 'remove_key', 'mark_key']

export const COPY_SENT = 'Copie du coffre et document de credentials envoyés à Astra'
const DOCUMENT_WAITS = 'Copie envoyée · document de credentials en attente (rotation en cours)'
const HELD_BACK = 'Copie retenue par une opération en cours · à renvoyer ensuite'

/** What a send came to, said: a copy held back or a document left out is never silent. */
function outcomeLine(outcome: VaultCopyOutcome): { text: string; complete: boolean } {
  if (outcome.state === 'held_back') return { text: HELD_BACK, complete: false }
  if (outcome.document_waits) return { text: DOCUMENT_WAITS, complete: false }
  return { text: COPY_SENT, complete: true }
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
  const [line, setLine] = useState<{ text: string; complete: boolean } | null>(null)
  const [failed, setFailed] = useState<string | null>(null)
  const [sending, setSending] = useState(false)

  const send = useCallback(async () => {
    setSending(true)
    setFailed(null)
    try {
      setLine(outcomeLine(await api.operatorSendVaultCopy()))
    } catch (cause) {
      setLine(null)
      setFailed(String(cause))
    } finally {
      setSending(false)
    }
  }, [])

  useEffect(() => {
    if (!applies || sentAfter.has(status.session_id)) return
    sentAfter.add(status.session_id)
    void send()
  }, [applies, status.session_id, send])

  if (!applies) return null
  if (failed) {
    return (
      <Alert
        severity="warning"
        variant="outlined"
        sx={{ mt: 1, fontSize: 11.5, alignItems: 'center' }}
        action={
          <Button
            size="small"
            color="inherit"
            disabled={sending}
            onClick={() => void send()}
            sx={{ fontSize: 11, whiteSpace: 'nowrap' }}
          >
            Réessayer l’envoi
          </Button>
        }
      >
        {`Copie non envoyée à Astra : ${failed}`}
      </Alert>
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
 * « Copie du coffre » in Coffre et clés: the line the rotations read, with its « Envoyer ».
 * Shown once the tunnel is up; without it nothing here can be sent.
 */
export function VaultCopyLine() {
  const [overview, setOverview] = useState<RotationsOverview | null>(null)
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const read = useCallback(async () => {
    try {
      const found = await api.operatorRotationsOverview()
      if (found) setOverview(found)
    } catch {
      // Unread stays unshown: this line is a reminder, the Rotations tab reports reads.
    }
  }, [])

  useEffect(() => {
    void read()
  }, [read])

  if (!overview?.tunnel || !overview.vault?.exists) return null
  const line = vaultCopyPrerequisite(overview)

  const sendCopy = async () => {
    setBusy(true)
    setNotice(null)
    setError(null)
    try {
      const said = outcomeLine(await api.operatorSendVaultCopy())
      if (!said.complete) setNotice(said.text)
      await read()
    } catch (cause) {
      setError(String(cause))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Paper variant="outlined" sx={{ p: 1.75 }}>
      <Typography component="h3" sx={{ fontSize: 12.5, fontWeight: 700, mb: 0.5 }}>
        Astra
      </Typography>
      <Box component="ul" sx={{ m: 0, p: 0 }}>
        <PrerequisiteLine line={line} busy={busy} onFix={() => void sendCopy()} />
      </Box>
      {notice && (
        <Alert severity="info" variant="outlined" sx={{ mt: 1, fontSize: 11.5 }}>
          {notice}
        </Alert>
      )}
      {error && (
        <Alert severity="error" variant="outlined" sx={{ mt: 1, fontSize: 11.5 }}>
          {error}
        </Alert>
      )}
    </Paper>
  )
}
