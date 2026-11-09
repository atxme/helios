import { useCallback, useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import CircularProgress from '@mui/material/CircularProgress'
import Paper from '@mui/material/Paper'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { Check, KeyRound, X } from 'lucide-react'

import * as api from '../../api'
import { GRAPHITE, PINE, RULE } from '../../theme'
import type {
  OperatorPendingOperation,
  OperatorStatus,
  RotationsOverview,
} from '../../types'
import {
  allGreen,
  liveOperation,
  prerequisites,
  reachLabel,
  rotationRows,
} from './rotationRows'
import type { Prerequisite, RotationAction, RotationRow } from './rotationRows'

/**
 * The overview is the one thing read here. It already carries `pending`, so nothing else
 * is polled beside it, and a read never starts before the previous one has settled.
 */
const POLL_MS = 15_000

/** The amber of a row to do, as in the mockup the operator approved. */
const DUE_BORDER = '#B45309'
const DUE_BACKGROUND = '#FFFBEB'

const DEFAULT_REASON: Partial<Record<RotationAction, string>> = {
  renew_fleet: 'Renouvellement des postes',
  renew_delegation: 'Renouvellement de la délégation',
}

/** What a step is given to run once every prerequisite is green. */
export interface RotationStepContext {
  action: RotationAction
  overview: RotationsOverview
  /** A campaign of this action already open at Astra; resumed rather than opened again. */
  existingOperation: OperatorPendingOperation | null
  /** The label of the first key, for `requested_by`. */
  operatorLabel: string
  /**
   * Hands a ceremony over to the screen. `existingOperation` is the campaign of the
   * rotation to lead at the approval, when one was already open.
   */
  onCeremony: (status: OperatorStatus, existingOperation?: string | null) => void
  /** Reads the overview again, once the read in flight has ended. */
  refresh: () => Promise<RotationsOverview | null>
}

function operatorLabelOf(o: RotationsOverview): string {
  const slot = o.vault?.slots.find((candidate) => candidate.state === null || candidate.state === 'active')
  return slot?.label.trim() || 'operator'
}

export function PrerequisiteLine({
  line,
  busy,
  onFix,
}: {
  line: Prerequisite
  busy: boolean
  onFix: (line: Prerequisite) => void
}) {
  return (
    <Box component="li" sx={{ listStyle: 'none', py: 0.4 }}>
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          flexWrap: 'wrap',
          minWidth: 0,
          gap: 0.75,
          fontSize: 12.5,
        }}
      >
        {line.ok ? (
          <Check size={14} color={PINE} aria-label="Conforme" role="img" />
        ) : (
          <X size={14} color="#B91C1C" aria-label="Non conforme" role="img" />
        )}
        <Box component="span" sx={{ minWidth: 0, overflowWrap: 'anywhere' }}>
          {line.label}
        </Box>
        {line.detail && (
          <Typography component="span" color="text.secondary" sx={{ fontSize: 11.5 }}>
            {line.detail}
          </Typography>
        )}
        {line.fixAction === 'send_vault_copy' && (
          <Button
            size="small"
            variant="outlined"
            disabled={busy}
            onClick={() => onFix(line)}
            sx={{ ml: 'auto', minHeight: 26, fontSize: 11.5 }}
          >
            {line.fix}
          </Button>
        )}
      </Box>
      {!line.ok && line.fix && line.fixAction === null && (
        <Typography color="text.secondary" sx={{ ml: 2.75, fontSize: 11.5 }}>
          {line.fix}
        </Typography>
      )}
    </Box>
  )
}

/**
 * The Rotations tab: one row per action, then the prerequisites of the row chosen.
 *
 * The steps after the prerequisites belong to the ceremony: the CA rotations are given
 * through `renderStep`. Renewing the workstations and the delegation open a campaign
 * here, which is their whole step.
 */
export function RotationsPanel({
  onCeremony,
  onOverview,
  renderStep,
  resumeStop,
}: {
  onCeremony: (status: OperatorStatus, existingOperation?: string | null) => void
  /** Every read, so the rest of the screen follows without a read of its own. */
  onOverview?: (overview: RotationsOverview) => void
  renderStep?: (context: RotationStepContext) => ReactNode
  /** Where an automatic resumption stopped, said in its row: it never takes the tab. */
  resumeStop?: string | null
}) {
  const [overview, setOverview] = useState<RotationsOverview | null>(null)
  const [readError, setReadError] = useState<string | null>(null)
  const [selected, setSelected] = useState<RotationAction | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [reason, setReason] = useState('')
  const onOverviewRef = useRef(onOverview)
  onOverviewRef.current = onOverview
  const reading = useRef<Promise<RotationsOverview | null> | null>(null)
  const alive = useRef(true)

  // A read in flight is shared: a second caller waits for it instead of starting another.
  const read = useCallback((): Promise<RotationsOverview | null> => {
    if (reading.current) return reading.current
    const started = api
      .operatorRotationsOverview()
      .then((found) => {
        if (!alive.current) return null
        setOverview(found)
        setReadError(null)
        onOverviewRef.current?.(found)
        return found
      })
      .catch((cause) => {
        if (alive.current) setReadError(String(cause))
        return null
      })
      .finally(() => {
        reading.current = null
      })
    reading.current = started
    return started
  }, [])

  // After a change the read must start once the one in flight has ended: that one may have
  // begun before the change and would show the old state.
  const readAfter = useCallback(async () => {
    if (reading.current) await reading.current
    return read()
  }, [read])

  useEffect(() => {
    alive.current = true
    // Per effect: under StrictMode the first run's chain must end with its own cleanup,
    // not resume because `alive` is true again after the remount.
    let stopped = false
    let timer: number | undefined
    const tick = () => {
      void read().then(() => {
        if (!stopped) timer = window.setTimeout(tick, POLL_MS)
      })
    }
    tick()
    return () => {
      stopped = true
      alive.current = false
      window.clearTimeout(timer)
    }
  }, [read])

  const now = Math.floor(Date.now() / 1000)
  const rows = overview ? rotationRows(overview, now) : []
  const chosen = overview && selected ? rows.find((row) => row.action === selected) : undefined
  const lines = overview && chosen ? prerequisites(overview, chosen.action) : []
  const green = allGreen(lines)
  const existing = overview && chosen ? liveOperation(overview, chosen.action, now) : null
  // The row can turn impossible after it was chosen: its step is then not offered.
  const open = green && chosen?.disabledReason === null

  const choose = (action: RotationAction) => {
    setError(null)
    setNotice(null)
    setReason(DEFAULT_REASON[action] ?? '')
    setSelected((current) => (current === action ? null : action))
  }

  const sendCopy = async () => {
    setBusy(true)
    setError(null)
    setNotice(null)
    try {
      const outcome = await api.operatorSendVaultCopy()
      // Held back is an answer, not a failure: the same copy passes later.
      if (outcome.state === 'held_back') setNotice('En attente : copie retenue')
      else if (outcome.document_waits) setNotice('En attente : document de credentials retenu')
      await readAfter()
    } catch (cause) {
      setError(String(cause))
    } finally {
      setBusy(false)
    }
  }

  // Opens what the row asks, then hands over to the ceremony. After any refusal the
  // operations are read again: an operation already open is resumed, not reported.
  const proceed = async (row: RotationRow) => {
    if (!overview) return
    setBusy(true)
    setError(null)
    setNotice(null)
    try {
      if (row.action === 'renew_fleet') {
        // Read again first: the poll may be old, and a campaign open since is led, not met
        // as a refusal.
        const fresh = await readAfter()
        const current = fresh ? liveOperation(fresh, row.action) : existing
        const operationId =
          current?.operation_id ??
          (
            await api.operatorOpenCampaign(
              { action: 'fleet_leafs' },
              reason.trim() || DEFAULT_REASON.renew_fleet!,
              operatorLabelOf(overview),
            )
          ).operation_id
        onCeremony(
          await api.beginOperatorCeremony({ kind: 'approve_campaign', operation_id: operationId }),
        )
      } else if (row.action === 'renew_delegation') {
        // The request exists only in the answer to the opening: a ceremony that cannot
        // start would lose it, so the opening waits for one that can.
        const running = await api.operatorCeremonyStatus()
        if (
          running &&
          !(typeof running.gesture === 'string' && ['done', 'failed', 'cancelled'].includes(running.gesture))
        ) {
          setNotice('Cérémonie en cours')
          return
        }
        const opened = await api.operatorOpenCampaign(
          { action: 'issuer_delegation' },
          reason.trim() || DEFAULT_REASON.renew_delegation!,
          operatorLabelOf(overview),
        )
        if (!opened.delegation_request) throw new Error('demande de délégation absente')
        onCeremony(
          await api.beginIssuerCeremony({
            gesture: 'authorize_issuer',
            operation_id: opened.operation_id,
            request: opened.delegation_request,
          }),
        )
      }
    } catch (cause) {
      const fresh = await readAfter()
      const live = fresh && liveOperation(fresh, row.action, now)
      if (live) setNotice('Opération déjà ouverte')
      else setError(String(cause))
    } finally {
      setBusy(false)
    }
  }

  if (!overview) {
    return readError ? (
      <Alert severity="error" variant="outlined" sx={{ fontSize: 11.5 }}>
        {readError}
      </Alert>
    ) : (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 3 }}>
        <CircularProgress size={18} aria-label="Lecture en cours" />
      </Box>
    )
  }

  const unread = [
    ['Domaine', reachLabel(overview.domain)],
    ['Autorité', reachLabel(overview.authority)],
    ['Opérations', reachLabel(overview.pending)],
  ].filter((entry): entry is [string, string] => entry[1] !== null)

  return (
    <>
      {unread.length > 0 && (
        <Typography color="text.secondary" sx={{ fontSize: 11.5, mb: 1 }}>
          {unread.map(([name, label]) => `${name} : ${label}`).join(' · ')}
        </Typography>
      )}
      {readError && (
        <Alert severity="warning" variant="outlined" sx={{ mb: 1, fontSize: 11.5 }}>
          {readError}
        </Alert>
      )}
      {rows.map((row) => {
        const live = liveOperation(overview, row.action, now)
        const resumable = live !== null && row.action !== 'renew_delegation'
        return (
          <Paper
            key={row.action}
            component="section"
            aria-label={row.title}
            variant="outlined"
            sx={{
              mb: 1,
              px: 1.5,
              py: 1.25,
              borderColor: row.due ? DUE_BORDER : RULE,
              bgcolor: row.due ? DUE_BACKGROUND : 'background.paper',
            }}
          >
            <Typography sx={{ fontSize: 13, fontWeight: 700 }}>{row.title}</Typography>
            <Typography
              sx={{
                fontSize: 11.5,
                color: row.due ? DUE_BORDER : GRAPHITE,
                fontWeight: row.due ? 700 : 400,
              }}
            >
              {row.state}
            </Typography>
            {live && row.disabledReason === null && (
              <Typography color="text.secondary" sx={{ fontSize: 11.5 }}>
                {`Opération ouverte · ${live.reason}`}
              </Typography>
            )}
            {row.detail && (
              <Typography color="text.secondary" sx={{ fontSize: 11, overflowWrap: 'anywhere' }}>
                {row.detail}
              </Typography>
            )}
            {row.action === 'resume' && resumeStop && (
              <Typography sx={{ fontSize: 11.5, color: '#B91C1C', fontWeight: 600 }}>
                {resumeStop}
              </Typography>
            )}
            {row.disabledReason && row.disabledReason !== row.state && (
              <Typography color="text.secondary" sx={{ fontSize: 11.5 }}>
                {row.disabledReason}
              </Typography>
            )}
            <Button
              size="small"
              variant={row.due ? 'contained' : 'outlined'}
              disabled={busy || row.disabledReason !== null}
              aria-expanded={row.action === selected}
              onClick={() => choose(row.action)}
              sx={{ mt: 0.75, minHeight: 28, fontSize: 12 }}
            >
              {resumable ? 'Reprendre' : row.button}
            </Button>
          </Paper>
        )
      })}

      {chosen && (
        <Paper component="section" aria-label="Prérequis" variant="outlined" sx={{ px: 1.5, py: 1.25 }}>
          <Typography component="h3" sx={{ fontSize: 12.5, fontWeight: 700, mb: 0.5 }}>
            Prérequis
          </Typography>
          <Box component="ul" sx={{ m: 0, p: 0 }}>
            {lines.map((line) => (
              <PrerequisiteLine
                key={line.label}
                line={line}
                busy={busy}
                onFix={() => void sendCopy()}
              />
            ))}
          </Box>
          <Button
            size="small"
            variant="outlined"
            disabled={busy}
            onClick={() => void readAfter()}
            sx={{ mt: 0.75, minHeight: 28, fontSize: 12 }}
          >
            Vérifier
          </Button>

          {(chosen.action === 'renew_fleet' || chosen.action === 'renew_delegation') && (
            <Box sx={{ mt: 1.25 }}>
              {!existing && (
                <TextField
                  label="Motif"
                  value={reason}
                  onChange={(event) => setReason(event.target.value)}
                  size="small"
                  fullWidth
                  disabled={busy || !open}
                  sx={{ mb: 1 }}
                />
              )}
              <Button
                size="small"
                variant="contained"
                disabled={busy || !open}
                startIcon={<KeyRound size={14} aria-hidden />}
                onClick={() => void proceed(chosen)}
                sx={{ minHeight: 30, fontSize: 12 }}
              >
                {existing ? 'Reprendre l’opération ouverte' : 'Continuer'}
              </Button>
            </Box>
          )}
          {renderStep &&
            open &&
            chosen.action !== 'renew_fleet' &&
            chosen.action !== 'renew_delegation' && (
              <Box sx={{ mt: 1.25 }}>
                {renderStep({
                  action: chosen.action,
                  overview,
                  existingOperation: existing,
                  operatorLabel: operatorLabelOf(overview),
                  onCeremony,
                  refresh: readAfter,
                })}
              </Box>
            )}
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
      )}
    </>
  )
}
