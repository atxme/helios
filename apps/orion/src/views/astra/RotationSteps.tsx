import { useState } from 'react'
import type { ReactNode } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import CircularProgress from '@mui/material/CircularProgress'
import Paper from '@mui/material/Paper'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { Check, Circle, KeyRound, X } from 'lucide-react'

import * as api from '../../api'
import { GRAPHITE, PINE, RULE } from '../../theme'
import type {
  CaRotationManifest,
  OperatorStatus,
  RotationJournalView,
  RotationTerms,
} from '../../types'
import {
  Row,
  gestureSentence,
  groupedHex,
  purposeOf,
  refusalSentence,
  retryLabel,
  rowsOf,
} from '../OperatorCeremony'
import type { RotationStepContext } from './RotationsPanel'
import {
  INSTALL_DEADLINE_TO_CHECK,
  formatDate,
  formatDateTime,
  formatTime,
  liveOperation,
  valueOf,
} from './rotationRows'

/**
 * What follows the prerequisites of a CA rotation: the key step, the approval and the
 * follow-up.
 *
 * # Why the steps live in the ceremony and not in the row
 *
 * The row can turn impossible while a rotation runs (a resumption appears, an overlap
 * begins), and `RotationsPanel` then unmounts whatever it was showing. `RotationSteps`
 * therefore only starts the ceremony and hands over; the key step, the approval and the
 * follow-up are drawn by [`RotationCeremony`] from the ceremony's own status, wherever
 * that is shown.
 */

const TERMS_DEFAULT = { prepare_days: 7, overlap_days: 30, validity_days: 1825 }
/** The authority's own limit on a campaign's reason. */
const REASON_MAX_CHARS = 1024
/** Two distinct keys, each touched to validate and again to approve. */
const KEYS = [1, 2] as const

const ENDED = ['done', 'failed', 'cancelled']

const REASONS = {
  rotate_anchor: 'Remplacement de la CA-PQ',
  rotate_client_tls_ca: 'Remplacement de la CA TLS',
} as const

const NAMES = { rotate_anchor: 'CA-PQ', rotate_client_tls_ca: 'CA TLS' } as const

/** Whether a status belongs to a CA rotation: the only ceremonies these steps draw. */
export function isRotationStatus(status: OperatorStatus): boolean {
  return status.operation === 'rotate_anchor' || status.operation === 'rotate_client_tls_ca'
}

type RotationOperation = keyof typeof NAMES

const isEnded = (status: OperatorStatus) =>
  typeof status.gesture === 'string' && ENDED.includes(status.gesture)

const GESTURES = {
  replace_ca_pq: { gesture: 'replace_ca_pq' },
  replace_ca_tls: { gesture: 'replace_ca_tls' },
  finish_ca_tls: { gesture: 'finish_ca_tls' },
  resume: { gesture: 'resume' },
} as const

const START_LABELS = {
  replace_ca_pq: 'Continuer',
  replace_ca_tls: 'Continuer',
  finish_ca_tls: 'Terminer',
  resume: 'Reprendre',
} as const

/**
 * Starts a CA rotation gesture and hands the ceremony over.
 *
 * The campaign of a replacement is not opened here, nor at the keys: it opens at
 * « Approuver ». What is read here is `pending`, before any key, so that a campaign
 * already open is led rather than met as a refusal once the keys were spent.
 */
export function RotationSteps({
  action,
  existingOperation,
  refresh,
  onCeremony,
}: RotationStepContext) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const kind = action as keyof typeof GESTURES
  const opensCampaign = kind === 'replace_ca_pq' || kind === 'replace_ca_tls'

  if (!(kind in GESTURES)) return null

  const start = async () => {
    setBusy(true)
    setError(null)
    try {
      let existing: string | null = null
      if (opensCampaign) {
        const fresh = await refresh()
        if (!fresh || valueOf(fresh.pending) === null) {
          setError('Opérations non lues')
          return
        }
        existing = liveOperation(fresh, action)?.operation_id ?? null
      }
      onCeremony(await api.beginRotationCeremony(GESTURES[kind]), existing)
    } catch (cause) {
      setError(String(cause))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Box>
      {existingOperation && (
        <Typography color="text.secondary" sx={{ mb: 0.75, fontSize: 11.5 }}>
          {`Opération ouverte · ${existingOperation.reason} · jusqu’au ${formatDateTime(existingOperation.expires_at)}`}
        </Typography>
      )}
      <Button
        size="small"
        variant="contained"
        disabled={busy}
        startIcon={<KeyRound size={14} aria-hidden />}
        onClick={() => void start()}
        sx={{ minHeight: 30, fontSize: 12 }}
      >
        {existingOperation && opensCampaign ? 'Reprendre l’opération ouverte' : START_LABELS[kind]}
      </Button>
      {error && (
        <Alert severity="error" variant="outlined" sx={{ mt: 1, fontSize: 11.5 }}>
          {error}
        </Alert>
      )}
    </Box>
  )
}

/** The journal when the screen has one, else what the manifest already says of it. */
function datesOf(
  journal: RotationJournalView | null | undefined,
  manifest: CaRotationManifest | null,
): RotationJournalView | null {
  if (journal) return journal
  if (!manifest) return null
  return {
    kind: manifest.affected_ca,
    stage: 'signed',
    activationAt: manifest.activation_at,
    notAfter: manifest.not_after,
    nextFingerprint: manifest.next_anchor_fingerprint ?? '',
    offline: false,
  }
}

function caManifest(status: OperatorStatus): CaRotationManifest | null {
  return status.manifest?.operation === 'ca_rotation' ? status.manifest : null
}

const STAGE_ORDER = { signed: 0, accepted: 1, applied: 2, installed: 3 } as const

type StepState = 'done' | 'todo' | 'waiting' | 'reading'

const STEP_TEXT: Record<StepState, string> = {
  done: 'Fait',
  todo: 'À faire',
  waiting: 'En attente',
  reading: 'Lecture',
}

function Step({ label, state }: { label: string; state: StepState }) {
  return (
    <Box
      component="li"
      aria-label={label}
      sx={{ listStyle: 'none', display: 'flex', alignItems: 'center', gap: 0.75, py: 0.3, fontSize: 12.5 }}
    >
      {state === 'done' ? (
        <Check size={14} color={PINE} aria-hidden />
      ) : (
        <Circle size={14} color={GRAPHITE} aria-hidden />
      )}
      <Box component="span">{label}</Box>
      <Typography component="span" color="text.secondary" sx={{ ml: 'auto', fontSize: 11.5 }}>
        {STEP_TEXT[state]}
      </Typography>
    </Box>
  )
}

/**
 * Signed, deposited, installed, and the vault copy. What the ceremony published and what
 * the journal says are both read, the further one winning: a resumption's status says
 * less than its journal.
 */
function FollowUp({
  status,
  journal,
  now,
}: {
  status: OperatorStatus
  journal: RotationJournalView | null | undefined
  now: number
}) {
  const manifest = caManifest(status)
  const dates = datesOf(journal, manifest)
  const done = status.gesture === 'done'
  const reached = journal ? STAGE_ORDER[journal.stage] : 0
  const signed = (status.remote !== 'local' && status.remote !== 'awaiting_operator') || !!journal
  const deposited = done || status.remote === 'deposited' || reached >= STAGE_ORDER.accepted
  const installed = done || reached >= STAGE_ORDER.installed

  let copy: StepState = 'todo'
  if (done) copy = journal === undefined ? 'reading' : journal === null ? 'done' : 'waiting'
  else if (installed) copy = 'waiting'

  const incoming = manifest?.next_anchor_fingerprint || journal?.nextFingerprint || null
  // From the journal and this clock alone: the resumption's own refusal is the dead end,
  // said by the ceremony.
  const toCheck =
    dates !== null &&
    !installed &&
    now >= dates.activationAt &&
    status.refusal?.refusal !== 'install_deadline_passed'

  return (
    <Box sx={{ mt: 1.25, pt: 1.25, borderTop: `1px solid ${RULE}` }}>
      <Box component="ul" sx={{ m: 0, p: 0 }}>
        <Step label="Signée" state={signed || deposited ? 'done' : 'todo'} />
        <Step label="Déposée" state={deposited ? 'done' : 'todo'} />
        <Step label="Installée sur la gateway" state={installed ? 'done' : 'todo'} />
        <Step label="Copie du coffre" state={copy} />
      </Box>
      {dates && !installed && (
        <Typography sx={{ mt: 0.75, fontSize: 11.5, fontWeight: 600 }}>
          {`À installer avant le ${formatDateTime(dates.activationAt)}`}
        </Typography>
      )}
      {dates && (
        <Typography color="text.secondary" sx={{ fontSize: 11.5 }}>
          {`Fin de rotation le ${formatDate(dates.notAfter)}`}
        </Typography>
      )}
      {incoming && (
        <Box sx={{ mt: 0.75 }}>
          <Typography color="text.disabled" sx={{ fontSize: 10.5, textTransform: 'uppercase' }}>
            Empreinte entrante
          </Typography>
          <Typography sx={{ fontFamily: 'monospace', fontSize: 11, overflowWrap: 'anywhere' }}>
            {groupedHex(incoming)}
          </Typography>
        </Box>
      )}
      {toCheck && (
        <Alert severity="warning" variant="outlined" sx={{ mt: 1, fontSize: 11.5 }}>
          {INSTALL_DEADLINE_TO_CHECK}
        </Alert>
      )}
    </Box>
  )
}

/** One key of the key step, in the state the mockup the operator approved gives it. */
function KeyRow({
  index,
  label,
  state,
  reason,
  action,
}: {
  index: number
  label: string | null
  state: 'validated' | 'current' | 'retry' | 'processing' | 'waiting' | 'approved' | 'touch'
  reason: string | null
  action: { text: string; disabled: boolean; onClick: () => void } | null
}) {
  const border =
    state === 'retry' ? '#B91C1C' : state === 'validated' || state === 'approved' ? PINE : RULE
  return (
    <Box
      component="li"
      aria-label={`Clé ${index}`}
      sx={{
        listStyle: 'none',
        display: 'flex',
        alignItems: 'center',
        gap: 1,
        border: `1px solid ${border}`,
        borderRadius: 1,
        px: 1.25,
        py: 0.75,
        mb: 0.75,
      }}
    >
      <Box sx={{ minWidth: 0, flex: 1 }}>
        <Typography component="b" sx={{ display: 'block', fontSize: 12.5 }}>{`Clé ${index}`}</Typography>
        <Typography
          component="span"
          color={state === 'retry' ? 'error' : 'text.secondary'}
          sx={{ display: 'block', fontSize: 11.5, overflowWrap: 'anywhere' }}
        >
          {state === 'validated'
            ? label
            : state === 'retry'
              ? reason
              : state === 'current'
                ? 'À valider'
                : state === 'processing'
                  ? 'Lecture…'
                  : state === 'approved'
                    ? 'Approuvée'
                    : state === 'touch'
                      ? 'Brancher et toucher la clé'
                      : 'En attente'}
        </Typography>
      </Box>
      {state === 'validated' && (
        <Typography component="span" sx={{ color: PINE, fontSize: 12, fontWeight: 700 }}>
          ✓ Validée
        </Typography>
      )}
      {state === 'processing' && <CircularProgress size={14} aria-label="Lecture en cours" />}
      {action && (
        <Button
          size="small"
          variant="outlined"
          disabled={action.disabled}
          onClick={action.onClick}
          sx={{ minHeight: 28, fontSize: 12 }}
        >
          {action.text}
        </Button>
      )}
    </Box>
  )
}

interface Draft {
  reason: string
  prepare: string
  overlap: string
  validity: string
}

/** What is wrong with the terms, before any call; `null` when they can be sent. */
function termsError(draft: Draft, tls: boolean): string | null {
  const reason = draft.reason.trim()
  if (reason.length === 0) return 'Motif : requis'
  if (draft.reason.length > REASON_MAX_CHARS) return `Motif : ${REASON_MAX_CHARS} caractères au plus`
  const whole = (value: string) => value.trim() !== '' && Number.isSafeInteger(Number(value))
  if (!whole(draft.prepare) || Number(draft.prepare) < 1) return 'Préparation : 1 jour au moins'
  if (!whole(draft.overlap) || Number(draft.overlap) < 1) return 'Recouvrement : 1 jour au moins'
  if (tls && (!whole(draft.validity) || Number(draft.validity) < 1)) {
    return 'Validité CA TLS : 1 jour au moins'
  }
  return null
}

export function RotationCeremony({
  status,
  onStatus,
  onDismiss,
  journal,
  existingOperation = null,
  existingExpiresAt = null,
  now = Math.floor(Date.now() / 1000),
}: {
  status: OperatorStatus
  onStatus: (next: OperatorStatus) => void
  onDismiss?: () => void
  /** `undefined` while the journal is being read again after the ceremony ended. */
  journal?: RotationJournalView | null
  /** A campaign already open at the authority, to be led by the approval. */
  existingOperation?: string | null
  /** When that campaign ends: with seconds left, the keys are spent for nothing. */
  existingExpiresAt?: number | null
  /** Seconds, for the deadline; the operator's clock when not given. */
  now?: number
}) {
  const operation = status.operation as RotationOperation
  const name = NAMES[operation]
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [proceeded, setProceeded] = useState(false)
  const [folded, setFolded] = useState(true)
  const [draft, setDraft] = useState<Draft>({
    reason: REASONS[operation],
    prepare: String(TERMS_DEFAULT.prepare_days),
    overlap: String(TERMS_DEFAULT.overlap_days),
    validity: String(TERMS_DEFAULT.validity_days),
  })
  const [invalid, setInvalid] = useState<string | null>(null)

  const act = async (action: 'continue' | 'cancel') => {
    setBusy(true)
    setError(null)
    try {
      onStatus(await api.advanceOperatorCeremony(action, status.revision))
    } catch (cause) {
      setError(String(cause))
    } finally {
      setBusy(false)
    }
  }

  const approve = async () => {
    const tls = operation === 'rotate_client_tls_ca'
    const wrong = termsError(draft, tls)
    setInvalid(wrong)
    if (wrong) return
    const terms: RotationTerms = {
      existing_operation: existingOperation,
      reason: draft.reason.trim(),
      requested_by: status.keys?.[0]?.label ?? 'operator',
      prepare_days: Number(draft.prepare),
      overlap_days: Number(draft.overlap),
      validity_days: Number(draft.validity),
    }
    setBusy(true)
    setError(null)
    try {
      onStatus(await api.approveRotationCeremony(terms, status.revision))
    } catch (cause) {
      setError(String(cause))
    } finally {
      setBusy(false)
    }
  }

  const gesture = status.gesture
  const awaiting = typeof gesture === 'object' && 'awaiting_key' in gesture ? gesture.awaiting_key : null
  const processing =
    typeof gesture === 'object' && 'processing_key' in gesture ? gesture.processing_key : null
  const purpose = purposeOf(gesture)
  const keys = status.keys ?? []
  const manifest = caManifest(status)
  const ended = isEnded(status)
  const prepared = status.remote !== 'local' && status.remote !== 'awaiting_operator'
  const finishing = purpose === 'promotion' || (manifest !== null && !manifest.campaign)

  type Stage = 'ended' | 'follow' | 'touches' | 'keys' | 'wait'
  let stage: Stage
  if (ended) stage = 'ended'
  else if (prepared) stage = 'follow'
  else if (manifest) stage = 'touches'
  else if (purpose === 'validate_key' || processing || keys.length > 0 || status.key_retry) {
    stage = 'keys'
  } else stage = 'wait'

  const known = journal ? journal.kind : (manifest?.affected_ca ?? null)
  const knownName = known === 'ca_pq' ? 'CA-PQ' : known === 'ca_tls' ? 'CA TLS' : null
  const title = finishing
    ? 'Terminer la rotation CA TLS'
    : stage === 'keys' || stage === 'touches'
      ? `Remplacer la ${name}`
      : // Until the journal is read a resumption does not know which CA it carries.
        knownName
        ? `Rotation ${knownName}`
        : 'Rotation'

  const canPress = awaiting !== null && status.allowed.includes('continue') && !busy
  const canCancel = status.allowed.includes('cancel')
  const retry = status.key_retry
    ? retryLabel(status.key_retry, purpose)
    : null
  const opened = status.remote !== 'local'

  const cancelButton = canCancel && (
    <Button
      size="small"
      variant="outlined"
      color="inherit"
      disabled={busy}
      startIcon={<X size={14} aria-hidden />}
      onClick={() => void act('cancel')}
      sx={{ minHeight: 30, fontSize: 11.5 }}
    >
      Annuler
    </Button>
  )

  let body: ReactNode = null
  if (stage === 'wait') {
    body = (
      <Typography sx={{ mt: 1.25, fontSize: 11.5 }}>
        {gestureSentence(status.gesture, status.operation, opened)}
      </Typography>
    )
  } else if (stage === 'keys') {
    const reviewing = keys.length >= KEYS.length && !awaiting && !processing
    const showApproval =
      reviewing &&
      (proceeded ||
        status.key_retry?.refusal === 'terms_refused' ||
        gesture === 'verifying')
    if (showApproval) {
      const tls = operation === 'rotate_client_tls_ca'
      const field = (key: keyof Draft, label: string) => (
        <TextField
          label={label}
          value={draft[key]}
          onChange={(event) => setDraft({ ...draft, [key]: event.target.value })}
          size="small"
          disabled={busy || gesture !== 'idle'}
          fullWidth
          sx={{ mb: 1 }}
          slotProps={{ htmlInput: key === 'reason' ? {} : { inputMode: 'numeric' } }}
        />
      )
      body = (
        <Box sx={{ mt: 1.25 }}>
          <Box component="ul" sx={{ m: 0, p: 0, mb: 0.75 }}>
            {keys.map((key, position) => (
              <Box
                component="li"
                key={key.slot}
                aria-label={`Clé ${position + 1} validée`}
                sx={{ listStyle: 'none', display: 'flex', gap: 1, fontSize: 12, py: 0.2 }}
              >
                <Check size={14} color={PINE} aria-hidden />
                <Box component="span">{key.label}</Box>
              </Box>
            ))}
          </Box>
          {existingOperation ? (
            <Box sx={{ mb: 1 }}>
              <Typography sx={{ fontSize: 12, fontWeight: 600 }}>Opération ouverte</Typography>
              {existingExpiresAt !== null && (
                <Typography color="text.secondary" sx={{ fontSize: 11.5 }}>
                  {`Ouverte jusqu’au ${formatDateTime(existingExpiresAt)}`}
                </Typography>
              )}
            </Box>
          ) : (
            field('reason', 'Motif')
          )}
          <Button
            size="small"
            variant="text"
            color="inherit"
            aria-expanded={!folded}
            onClick={() => setFolded(!folded)}
            sx={{ mb: 1, minHeight: 26, fontSize: 11.5 }}
          >
            Modifier
          </Button>
          {!folded && (
            <Box>
              {field('prepare', 'Préparation (jours)')}
              {field('overlap', 'Recouvrement (jours)')}
              {tls && field('validity', 'Validité CA TLS (jours)')}
            </Box>
          )}
          <Typography color="text.secondary" sx={{ mb: 1, fontSize: 11.5 }}>
            Garder la clé 2 branchée
          </Typography>
          {retry && status.key_retry?.refusal === 'terms_refused' && (
            <Alert severity="warning" variant="outlined" sx={{ mb: 1, fontSize: 11.5 }}>
              {retry}
            </Alert>
          )}
          {invalid && (
            <Alert severity="warning" variant="outlined" sx={{ mb: 1, fontSize: 11.5 }}>
              {invalid}
            </Alert>
          )}
          <Box sx={{ display: 'flex', gap: 1 }}>
            <Button
              size="small"
              variant="contained"
              disabled={busy || gesture !== 'idle'}
              onClick={() => void approve()}
              sx={{ minHeight: 30, fontSize: 11.5 }}
            >
              Approuver
            </Button>
            {cancelButton}
          </Box>
        </Box>
      )
    } else {
      const current = awaiting?.index ?? processing?.index ?? keys.length + 1
      body = (
        <Box sx={{ mt: 1.25 }}>
          <Box component="ul" sx={{ m: 0, p: 0 }}>
            {KEYS.map((index) => {
              const validated = keys[index - 1]
              if (validated) {
                return (
                  <KeyRow
                    key={index}
                    index={index}
                    label={validated.label}
                    state="validated"
                    reason={null}
                    action={null}
                  />
                )
              }
              if (index !== current || reviewing) {
                return (
                  <KeyRow key={index} index={index} label={null} state="waiting" reason={null} action={null} />
                )
              }
              if (processing) {
                return (
                  <KeyRow key={index} index={index} label={null} state="processing" reason={null} action={null} />
                )
              }
              const again = retry !== null
              return (
                <KeyRow
                  key={index}
                  index={index}
                  label={null}
                  state={again ? 'retry' : 'current'}
                  reason={retry}
                  action={{
                    text: again ? 'Réessayer' : 'Valider',
                    disabled: !canPress,
                    onClick: () => void act('continue'),
                  }}
                />
              )
            })}
          </Box>
          <Box sx={{ display: 'flex', gap: 1, mt: 0.5 }}>
            <Button
              size="small"
              variant="contained"
              disabled={!reviewing || busy}
              onClick={() => setProceeded(true)}
              sx={{ minHeight: 30, fontSize: 11.5 }}
            >
              Continuer
            </Button>
            {cancelButton}
          </Box>
        </Box>
      )
    }
  } else if (stage === 'touches') {
    const of = awaiting?.of ?? processing?.of ?? 1
    const approvedBy = new Set((status.approved ?? []).map((key) => key.label))
    const signing = gesture === 'signing'
    body = (
      <Box sx={{ mt: 1.25 }}>
        {manifest && (
          <Box sx={{ pb: 1, mb: 1, borderBottom: `1px solid ${RULE}` }}>
            {rowsOf(manifest).map(([label, value]) => (
              <Row key={label} label={label} value={value} />
            ))}
          </Box>
        )}
        {signing ? (
          <Typography sx={{ fontSize: 12 }}>Signature en cours</Typography>
        ) : (
          <>
            {of > 1 && keys.length > 0 ? (
              <Box component="ul" sx={{ m: 0, p: 0 }}>
                {keys.map((key, position) => (
                  <KeyRow
                    key={key.slot}
                    index={position + 1}
                    label={null}
                    state={approvedBy.has(key.label) ? 'approved' : 'touch'}
                    reason={null}
                    action={null}
                  />
                ))}
              </Box>
            ) : (
              <Typography sx={{ fontSize: 12 }}>Brancher et toucher la clé</Typography>
            )}
            {processing && (
              <Typography color="text.secondary" sx={{ mt: 0.5, fontSize: 11.5 }}>
                Lecture…
              </Typography>
            )}
            {retry && (
              <Typography color="error" sx={{ mt: 0.5, fontSize: 11.5 }}>
                {retry}
              </Typography>
            )}
          </>
        )}
        <Box sx={{ display: 'flex', gap: 1, mt: 1 }}>
          {!signing && status.allowed.includes('continue') && (
            <Button
              size="small"
              variant="contained"
              disabled={!canPress}
              startIcon={<KeyRound size={14} aria-hidden />}
              onClick={() => void act('continue')}
              sx={{ minHeight: 30, fontSize: 11.5 }}
            >
              {finishing ? 'Terminer avec la clé' : retry ? 'Réessayer' : 'Approuver avec la clé'}
            </Button>
          )}
          {cancelButton}
        </Box>
      </Box>
    )
  } else if (stage === 'follow') {
    body = (
      <>
        <FollowUp status={status} journal={journal} now={now} />
        {manifest && (
          <Box sx={{ mt: 1.25, pt: 1.25, borderTop: `1px solid ${RULE}` }}>
            {rowsOf(manifest).map(([label, value]) => (
              <Row key={label} label={label} value={value} />
            ))}
          </Box>
        )}
      </>
    )
  } else {
    const shownJournal = journal ?? datesOf(journal, manifest)
    const refusal = status.refusal
    // A rotation is in flight when something was signed or a journal says so, and not
    // because a manifest with dates was shown: « Terminer » and a campaign abandoned
    // during the touches carry dates and have signed nothing.
    const inFlight = prepared || !!journal
    body = (
      <>
        {inFlight && <FollowUp status={status} journal={journal} now={now} />}
        {refusal && status.gesture !== 'done' && (
          <Alert
            severity={refusal.refusal === 'cancelled' ? 'info' : 'error'}
            variant="outlined"
            sx={{ mt: 1, fontSize: 11.5 }}
          >
            {refusal.refusal === 'cancelled'
              ? gestureSentence('cancelled', status.operation, opened)
              : refusalSentence(refusal, shownJournal, status.operation, opened)}
          </Alert>
        )}
        {status.gesture === 'done' && !prepared && !manifest && (
          <Alert severity="info" variant="outlined" sx={{ mt: 1, fontSize: 11.5 }}>
            Rien à reprendre
          </Alert>
        )}
        {status.gesture === 'done' && ((prepared && journal === null) || (!prepared && manifest)) && (
          <Alert severity="success" variant="outlined" sx={{ mt: 1, fontSize: 11.5 }}>
            Rotation terminée
          </Alert>
        )}
        {manifest && (
          <Box sx={{ mt: 1.25, pt: 1.25, borderTop: `1px solid ${RULE}` }}>
            {rowsOf(manifest).map(([label, value]) => (
              <Row key={label} label={label} value={value} />
            ))}
          </Box>
        )}
        {onDismiss && (
          <Button
            size="small"
            variant="outlined"
            color="inherit"
            disabled={busy}
            onClick={onDismiss}
            sx={{ mt: 1, minHeight: 30, fontSize: 11.5 }}
          >
            Retour aux opérations
          </Button>
        )}
      </>
    )
  }

  return (
    <Paper variant="outlined" sx={{ px: 1.75, py: 1.5 }}>
      <Typography component="h3" sx={{ fontSize: 13, fontWeight: 650 }}>
        {title}
      </Typography>
      {status.idle_until !== undefined && !ended && (
        <Typography color="text.secondary" sx={{ fontSize: 11.5 }}>
          {`Délai jusqu’à ${formatTime(status.idle_until)}`}
        </Typography>
      )}
      {body}
      {error && (
        <Alert severity="error" variant="outlined" sx={{ mt: 0.75, fontSize: 11.5 }}>
          {error}
        </Alert>
      )}
    </Paper>
  )
}
