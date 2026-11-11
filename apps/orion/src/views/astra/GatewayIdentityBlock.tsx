import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Checkbox from '@mui/material/Checkbox'
import FormControlLabel from '@mui/material/FormControlLabel'
import Paper from '@mui/material/Paper'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { KeyRound } from 'lucide-react'

import * as api from '../../api'
import { DUE_BACKGROUND, DUE_BORDER, RULE } from '../../theme'
import type {
  GatewayGesture,
  OperatorStatus,
  RevocationReasonChoice,
  RotationsOverview,
} from '../../types'
import { MotifChoice } from './RotationSteps'
import { PrerequisiteLine } from './PrerequisiteLine'
import { GATEWAY_LABELS, gatewayRow } from './gatewayRows'
import type { GatewayAction } from './gatewayRows'
import { allGreen, prerequisites } from './rotationRows'

/** The terms a gateway renewal is sent with: the gateway's own defaults. */
const RENEW_TERMS = { prepare_days: 7, overlap_days: 7, validity_days: 365 } as const
const HOURS_MAX = 168
const REASON_MAX_CHARS = 200
const ROLLBACK_HOURS_DEFAULT = '24'

const MOTIFS: { value: RevocationReasonChoice; label: string }[] = [
  { value: 'stolen_or_lost', label: 'Volé ou perdu' },
  { value: 'compromised', label: 'Compromis' },
  { value: 'no_longer_used', label: 'Plus utilisé' },
  { value: 'replaced', label: 'Remplacé' },
]

type Mode = 'with' | 'without'

const MODES: { value: Mode; label: string }[] = [
  { value: 'with', label: 'Avec remplaçant' },
  { value: 'without', label: 'Sans remplaçant' },
]

/** What a rollback's hours and reason must be, before any call: `null` when they can be sent. */
function rollbackError(hours: string, reason: string): string | null {
  const whole = hours.trim() !== '' && Number.isSafeInteger(Number(hours))
  if (!whole || Number(hours) < 1 || Number(hours) > HOURS_MAX) {
    return `Durée : de 1 à ${HOURS_MAX} heures`
  }
  const trimmed = reason.trim()
  if (trimmed.length === 0 || trimmed.length > REASON_MAX_CHARS) {
    return `Motif : de 1 à ${REASON_MAX_CHARS} caractères`
  }
  return null
}

/**
 * The « Identité de la gateway » block at the top of the Rotations tab: the gateway's own
 * identity, what it is in, and the gestures that act on it. Each gesture is started here and
 * handed to the ceremony, whose keys and follow-up are drawn by the Astra view.
 */
export function GatewayIdentityBlock({
  overview,
  now,
  onCeremony,
  refresh,
}: {
  overview: RotationsOverview
  now: number
  onCeremony: (status: OperatorStatus) => void
  /** Reads the overview again, after a gesture that opens no ceremony. */
  refresh: () => Promise<unknown>
}) {
  const row = gatewayRow(overview, now)
  const waiting = overview.gatewayPending
  const toSign = waiting?.kind === 'revocation' && waiting.revocation_to_sign
  const lines = prerequisites(overview, 'renew_fleet')
  const green = allGreen(lines)

  const [selected, setSelected] = useState<GatewayAction | null>(null)
  // A refresh may take the chosen action away (a resumption ended, a rollback expired): its flow closes.
  const offered = row.actions.join(',')
  useEffect(() => {
    setSelected((current) => (current !== null && !offered.split(',').includes(current) ? null : current))
  }, [offered])
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [rotateTls, setRotateTls] = useState(false)
  const [keyLost, setKeyLost] = useState(false)
  const [keyLossConfirmed, setKeyLossConfirmed] = useState(false)
  const [hours, setHours] = useState(ROLLBACK_HOURS_DEFAULT)
  const [reason, setReason] = useState('')
  const [motif, setMotif] = useState<RevocationReasonChoice | null>(null)
  const [chosenMode, setMode] = useState<Mode | null>('with')
  const [withoutConfirmed, setWithoutConfirmed] = useState(false)
  const [invalid, setInvalid] = useState<string | null>(null)

  const choose = (action: GatewayAction) => {
    setError(null)
    setInvalid(null)
    setSelected((current) => (current === action ? null : action))
  }

  // A gesture opens its ceremony, which the Astra view then draws. A discard opens none.
  const launch = async (gesture: GatewayGesture) => {
    setBusy(true)
    setError(null)
    try {
      await api.beginGatewayCeremony(gesture)
      if (gesture.gesture === 'discard') {
        await refresh()
        setSelected(null)
        return
      }
      const status = await api.operatorCeremonyStatus()
      if (status) onCeremony(status)
      else setError('Aucune cérémonie ouverte.')
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setBusy(false)
    }
  }

  const renew = () =>
    void launch({
      gesture: 'renew',
      rotate_tls: rotateTls,
      key_recovery: keyLost,
      ...RENEW_TERMS,
    })

  const rollback = () => {
    const wrong = rollbackError(hours, reason)
    setInvalid(wrong)
    if (wrong) return
    void launch({ gesture: 'rollback', hours: Number(hours), reason: reason.trim() })
  }

  // With a replacement the revocation runs two rounds, each with its own keys; a round that
  // only revokes is one. A waiting replacement fixes the mode: it is already deposited.
  // While a transition is staged or overlapping, heliosd prepares no replacement: the choice is
  // then left to the operator, and « sans remplaçant » is never taken for them.
  const noReplacement = row.replacementReason !== null
  const mode: Mode | null = noReplacement && chosenMode === 'with' ? null : chosenMode
  const withReplacement = toSign || mode === 'with'
  const decided = toSign || mode !== null
  const touches =
    mode === 'with' && !toSign
      ? 'Deux séries de touches : le remplaçant, puis la révocation.'
      : 'Une série de touches : la révocation.'

  const revoke = () => {
    if (!motif || !decided) return
    void launch({ gesture: 'revoke', reason: motif, with_replacement: withReplacement })
  }

  // Each flow below needs its prerequisites green, except the discard, which takes no key.
  const flowOpen = selected === 'discard' || green

  let flow: ReactNode = null
  if (selected === 'renew') {
    flow = (
      <>
        <FormControlLabel
          control={
            <Checkbox
              checked={rotateTls}
              disabled={busy}
              onChange={(event) => setRotateTls(event.target.checked)}
            />
          }
          label="Remplacer aussi la feuille TLS"
        />
        <FormControlLabel
          control={
            <Checkbox
              checked={keyLost}
              disabled={busy}
              onChange={(event) => {
                setKeyLost(event.target.checked)
                setKeyLossConfirmed(false)
              }}
            />
          }
          label="La clé de la gateway est perdue"
        />
        {keyLost && (
          <Paper component="section" aria-label="Confirmation" variant="outlined" sx={{ px: 1.5, py: 1, mb: 1 }}>
            <Typography sx={{ fontSize: 12, mb: 0.5 }}>
              Aucune preuve de continuité. Réservé à une clé disparue.
            </Typography>
            <FormControlLabel
              control={
                <Checkbox
                  checked={keyLossConfirmed}
                  disabled={busy}
                  onChange={(event) => setKeyLossConfirmed(event.target.checked)}
                />
              }
              label="Je confirme la perte de la clé"
            />
          </Paper>
        )}
        <Typography color="text.secondary" sx={{ mb: 1, fontSize: 11.5 }}>
          Termes : préparation 7 jours, recouvrement 7 jours, validité 365 jours.
        </Typography>
        <Button
          size="small"
          variant="contained"
          disabled={busy || (keyLost && !keyLossConfirmed)}
          startIcon={<KeyRound size={14} aria-hidden />}
          onClick={renew}
          sx={{ minHeight: 30, fontSize: 12 }}
        >
          Continuer
        </Button>
      </>
    )
  } else if (selected === 'abort') {
    flow = (
      <Paper component="section" aria-label="Confirmation" variant="outlined" sx={{ px: 1.5, py: 1 }}>
        <Typography sx={{ mb: 1, fontSize: 12 }}>L'époque reste consommée.</Typography>
        <Button
          size="small"
          variant="contained"
          disabled={busy}
          onClick={() => void launch({ gesture: 'abort' })}
          sx={{ minHeight: 30, fontSize: 12 }}
        >
          Confirmer l’annulation
        </Button>
      </Paper>
    )
  } else if (selected === 'rollback') {
    flow = (
      <>
        <TextField
          label="Durée (heures)"
          value={hours}
          onChange={(event) => setHours(event.target.value)}
          size="small"
          disabled={busy}
          fullWidth
          slotProps={{ htmlInput: { inputMode: 'numeric' } }}
          sx={{ mb: 1 }}
        />
        <TextField
          label="Motif"
          value={reason}
          onChange={(event) => setReason(event.target.value)}
          size="small"
          disabled={busy}
          fullWidth
          sx={{ mb: 1 }}
        />
        {invalid && (
          <Alert severity="warning" variant="outlined" sx={{ mb: 1, fontSize: 11.5 }}>
            {invalid}
          </Alert>
        )}
        <Button
          size="small"
          variant="contained"
          disabled={busy}
          onClick={rollback}
          sx={{ minHeight: 30, fontSize: 12 }}
        >
          Lancer le retour arrière
        </Button>
      </>
    )
  } else if (selected === 'revoke') {
    flow = (
      <>
        <MotifChoice
          legend="Motif"
          choices={MOTIFS}
          value={motif}
          disabled={busy}
          onChoose={setMotif}
        />
        {motif && !toSign && (
          <MotifChoice
            legend="Remplaçant"
            choices={MODES}
            value={mode}
            disabled={busy}
            unavailable={noReplacement ? { with: row.replacementReason ?? '' } : undefined}
            onChoose={(next) => {
              setMode(next)
              setWithoutConfirmed(false)
            }}
          />
        )}
        {motif && decided && (
          <Paper component="section" aria-label="Confirmation" variant="outlined" sx={{ px: 1.5, py: 1 }}>
            <Typography sx={{ mb: 0.75, fontSize: 12 }}>{touches}</Typography>
            {!withReplacement && (
              <>
                <Typography sx={{ mb: 0.5, fontSize: 12 }}>
                  La gateway ne servira plus. Le domaine devra être reconstruit.
                </Typography>
                <FormControlLabel
                  control={
                    <Checkbox
                      checked={withoutConfirmed}
                      disabled={busy}
                      onChange={(event) => setWithoutConfirmed(event.target.checked)}
                    />
                  }
                  label="Je confirme la révocation sans remplaçant"
                />
              </>
            )}
            <Button
              size="small"
              variant="contained"
              disabled={busy || (!withReplacement && !withoutConfirmed)}
              onClick={revoke}
              sx={{ minHeight: 30, fontSize: 12 }}
            >
              {GATEWAY_LABELS.revoke}
            </Button>
          </Paper>
        )}
      </>
    )
  } else if (selected === 'resume') {
    flow = (
      <Button
        size="small"
        variant="contained"
        disabled={busy}
        onClick={() => void launch({ gesture: 'resume' })}
        sx={{ minHeight: 30, fontSize: 12 }}
      >
        {GATEWAY_LABELS.resume}
      </Button>
    )
  } else if (selected === 'discard') {
    flow = (
      <Paper component="section" aria-label="Confirmation" variant="outlined" sx={{ px: 1.5, py: 1 }}>
        <Typography sx={{ mb: 1, fontSize: 12 }}>
          La décision signée sera perdue. L'époque reste consommée.
        </Typography>
        <Button
          size="small"
          variant="contained"
          disabled={busy}
          onClick={() => void launch({ gesture: 'discard' })}
          sx={{ minHeight: 30, fontSize: 12 }}
        >
          Jeter la décision en attente
        </Button>
      </Paper>
    )
  }

  return (
    <Paper
      component="section"
      aria-label="Identité de la gateway"
      variant="outlined"
      sx={{
        mb: 1.5,
        px: 1.5,
        py: 1.25,
        borderColor: row.due ? DUE_BORDER : RULE,
        bgcolor: row.due ? DUE_BACKGROUND : 'background.paper',
      }}
    >
      <Typography component="h3" sx={{ fontSize: 13, fontWeight: 700 }}>
        Identité de la gateway
      </Typography>
      <Typography sx={{ fontSize: 11.5, fontWeight: row.due ? 700 : 400, color: row.due ? DUE_BORDER : 'text.primary' }}>
        {row.state}
      </Typography>
      {row.detail && (
        <Typography color="text.secondary" sx={{ fontSize: 11.5, overflowWrap: 'anywhere' }}>
          {row.detail}
        </Typography>
      )}
      {row.restart && (
        <Alert severity="warning" variant="outlined" sx={{ mt: 0.75, fontSize: 11.5 }}>
          {row.restart}
          {row.restartMotif && (
            <Typography component="span" color="text.secondary" sx={{ display: 'block', mt: 0.25, fontSize: 10.5 }}>
              {`Détail technique : ${row.restartMotif}`}
            </Typography>
          )}
        </Alert>
      )}
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.75, mt: 0.75 }}>
        {row.actions.map((action) => (
          <Button
            key={action}
            size="small"
            variant={action === row.actions[0] && row.due ? 'contained' : 'outlined'}
            disabled={busy || (action === 'renew' && row.renewReason !== null)}
            aria-expanded={selected === action}
            onClick={() => choose(action)}
            sx={{ minHeight: 28, fontSize: 12 }}
          >
            {GATEWAY_LABELS[action]}
          </Button>
        ))}
      </Box>
      {row.renewReason && (
        <Typography color="text.secondary" sx={{ mt: 0.5, fontSize: 11.5 }}>
          {row.renewReason}
        </Typography>
      )}

      {selected && selected !== 'discard' && (
        <Paper component="section" aria-label="Prérequis de la gateway" variant="outlined" sx={{ mt: 1.25, px: 1.5, py: 1 }}>
          <Typography component="h4" sx={{ mb: 0.5, fontSize: 12.5, fontWeight: 700 }}>
            Prérequis
          </Typography>
          <Box component="ul" sx={{ m: 0, p: 0 }}>
            {lines.map((line) => (
              <PrerequisiteLine key={line.label} line={line} busy={busy} />
            ))}
          </Box>
        </Paper>
      )}
      {selected && flowOpen && <Box sx={{ mt: 1.25 }}>{flow}</Box>}
      {error && (
        <Alert severity="error" variant="outlined" sx={{ mt: 1, fontSize: 11.5 }}>
          {error}
        </Alert>
      )}
    </Paper>
  )
}
