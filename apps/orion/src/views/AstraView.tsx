import { useEffect, useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import CircularProgress from '@mui/material/CircularProgress'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { Check, KeyRound } from 'lucide-react'

import * as api from '../api'
import { GUTTER, MINT, PINE, RULE } from '../theme'
import type { AstraRotationInput, AstraRotationPhase, AstraRotationStatus } from '../types'

const EMPTY_INPUT: AstraRotationInput = {
  vault_path: '',
  heliosd_url: 'http://100.64.0.1:8080',
  operation_id: '',
  output_path: '',
}

type StepState = 'pending' | 'active' | 'done'

function stateOf(step: number, phase: AstraRotationPhase | 'idle'): StepState {
  const active =
    phase === 'idle' || phase === 'cancelled' || phase === 'failed' || phase === 'starting'
      ? 0
      : phase === 'awaiting_first_key' || phase === 'processing_first_key'
        ? 1
        : phase === 'awaiting_second_key' || phase === 'processing_second_key'
          ? 2
          : [
                'finalizing',
                'prepared',
                'deposited',
                'awaiting_promotion_key',
                'promoting',
                'promoted',
              ].includes(phase)
            ? 3
            : 0
  if (step < active || phase === 'deposited' || phase === 'promoted') return 'done'
  return step === active ? 'active' : 'pending'
}

function CeremonyStep({
  number,
  title,
  detail,
  state,
}: {
  number: number
  title: string
  detail: string
  state: StepState
}) {
  return (
    <Box sx={{ display: 'grid', gridTemplateColumns: '28px 1fr', gap: 1.25 }}>
      <Box
        aria-hidden
        sx={{
          display: 'grid',
          placeItems: 'center',
          width: 26,
          height: 26,
          borderRadius: '50%',
          border: 1,
          borderColor: state === 'pending' ? 'divider' : 'primary.main',
          bgcolor: state === 'done' ? 'primary.main' : state === 'active' ? MINT : 'transparent',
          color: state === 'done' ? 'primary.contrastText' : state === 'active' ? PINE : 'text.disabled',
          fontSize: 11,
          fontWeight: 700,
        }}
      >
        {state === 'done' ? <Check size={14} /> : number}
      </Box>
      <Box>
        <Typography sx={{ fontSize: 12.5, fontWeight: state === 'active' ? 700 : 600 }}>
          {title}
        </Typography>
        <Typography color={state === 'pending' ? 'text.disabled' : 'text.secondary'} sx={{ fontSize: 11, lineHeight: 1.5 }}>
          {detail}
        </Typography>
      </Box>
    </Box>
  )
}

/** Operator surface for the two distinct credentials required by ADR-008 §7.6. */
export function AstraView() {
  const [input, setInput] = useState<AstraRotationInput>(EMPTY_INPUT)
  const [status, setStatus] = useState<AstraRotationStatus | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const phase = status?.phase ?? 'idle'
  const cancellable = status?.can_cancel === true
  const locked = !['idle', 'failed', 'cancelled'].includes(phase)
  const valid = Object.values(input).every((value) => value.trim().length > 0)

  // A signer can outlive this view. Reading once restores its exact phase;
  // processing phases are then polled while Rust owns a blocking key gesture.
  useEffect(() => {
    let cancelled = false
    void api
      .astraCaTlsRotationStatus()
      .then((found) => {
        if (!cancelled && found.phase !== 'idle') setStatus(found)
      })
      .catch(() => {})
    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    const polling = [
      'starting',
      'processing_first_key',
      'processing_second_key',
      'finalizing',
      'promoting',
    ].includes(phase)
    if (!polling) return
    const timer = window.setTimeout(() => {
      void api
        .astraCaTlsRotationStatus()
        .then(setStatus)
        .catch((cause) => setError(String(cause)))
    }, 350)
    return () => window.clearTimeout(timer)
  }, [phase, status])

  const run = async (action: () => Promise<AstraRotationStatus>) => {
    setBusy(true)
    setError(null)
    try {
      setStatus(await action())
    } catch (cause) {
      setError(String(cause))
    } finally {
      setBusy(false)
    }
  }

  const update = (field: keyof AstraRotationInput, value: string) => {
    setInput((current) => ({ ...current, [field]: value }))
  }

  const cancel = async () => {
    await run(api.cancelAstraCaTlsRotation)
  }

  const primaryAction = () => {
    if (status?.can_continue) {
      void run(api.continueAstraCaTlsRotation)
      return
    }
    void run(() => api.startAstraCaTlsRotation(input))
  }

  const primaryLabel =
    phase === 'awaiting_first_key'
      ? 'Première clé branchée — continuer'
      : phase === 'awaiting_second_key'
        ? 'Seconde clé branchée — continuer'
        : phase === 'prepared'
          ? 'Réessayer le dépôt'
          : phase === 'awaiting_promotion_key'
            ? 'Clé de promotion branchée — continuer'
            : status?.can_continue
              ? 'Réessayer'
        : 'Démarrer la rotation'

  return (
    <Box sx={{ height: '100%', overflowY: 'auto', px: GUTTER, py: 1.5 }}>
      <Typography component="h2" sx={{ fontSize: 13, fontWeight: 700, mb: 0.5 }}>
        Astra
      </Typography>
      <Typography color="text.secondary" sx={{ fontSize: 11.5, lineHeight: 1.55, mb: 1.5 }}>
        Rotation de l’autorité CA-TLS cliente. L’opération doit déjà être ouverte dans
        Astra ; Orion guide ensuite les deux clés autorisées, une à la fois.
      </Typography>

      <Paper variant="outlined" sx={{ p: 1.75 }}>
        <Typography component="h3" sx={{ fontSize: 12.5, fontWeight: 700, mb: 1.25 }}>
          Paramètres de la rotation
        </Typography>
        <Stack spacing={1.25}>
          <TextField
            label="Coffre d’autorité"
            value={input.vault_path}
            onChange={(event) => update('vault_path', event.target.value)}
            placeholder="%APPDATA%\\astra\\authority-vault.json"
            disabled={locked || busy}
            size="small"
            fullWidth
          />
          <TextField
            label="URL heliosd"
            value={input.heliosd_url}
            onChange={(event) => update('heliosd_url', event.target.value)}
            disabled={locked || busy}
            size="small"
            fullWidth
          />
          <TextField
            label="Identifiant de l’opération"
            value={input.operation_id}
            onChange={(event) => update('operation_id', event.target.value)}
            placeholder="32 caractères hexadécimaux"
            disabled={locked || busy}
            size="small"
            fullWidth
          />
          <TextField
            label="Fichier de sortie"
            value={input.output_path}
            onChange={(event) => update('output_path', event.target.value)}
            placeholder="%USERPROFILE%\\Downloads\\ca-tls-transition.json"
            disabled={locked || busy}
            size="small"
            fullWidth
          />
        </Stack>
      </Paper>

      <Paper variant="outlined" sx={{ mt: 1.25, p: 1.75 }}>
        <Typography component="h3" sx={{ fontSize: 12.5, fontWeight: 700, mb: 1.5 }}>
          Cérémonie à deux clés
        </Typography>
        <Stack spacing={1.5} divider={<Box sx={{ ml: '13px !important', borderLeft: `1px solid ${RULE}`, height: 7 }} />}>
          <CeremonyStep
            number={1}
            title="Vérifier la campagne"
            detail="Astra lit la campagne existante et vérifie l’ancre actuellement en service."
            state={stateOf(0, phase)}
          />
          <CeremonyStep
            number={2}
            title="Première clé autorisée"
            detail={
              status?.first_key_label
                ? `Clé reconnue : ${status.first_key_label}`
                : 'Branchez la clé principale, puis continuez. Le système demandera son PIN et son contact.'
            }
            state={stateOf(1, phase)}
          />
          <CeremonyStep
            number={3}
            title="Seconde clé autorisée"
            detail={
              status?.second_key_label
                ? `Clé reconnue : ${status.second_key_label}`
                : 'Débranchez la première, branchez la clé de récupération, puis continuez.'
            }
            state={stateOf(2, phase)}
          />
        </Stack>

        {status?.phase === 'awaiting_first_key' && (
          <>
            {status.manifest && <CampaignManifest status={status} />}
            <Alert severity="info" variant="outlined" icon={<KeyRound size={17} />} sx={{ mt: 1.5, fontSize: 11.5 }}>
              {status.message} Branchez la première clé autorisée. Le système demandera le
              PIN et le contact après votre clic sur Continuer.
            </Alert>
          </>
        )}
        {status?.phase === 'awaiting_second_key' && (
          <Alert severity="info" variant="outlined" icon={<KeyRound size={17} />} sx={{ mt: 1.5, fontSize: 11.5 }}>
            {status.message} Débranchez la première clé, puis branchez la seconde. Le système
            demandera le PIN et le contact après votre clic sur Continuer.
          </Alert>
        )}
        {['starting', 'processing_first_key', 'processing_second_key', 'finalizing'].includes(
          phase,
        ) && (
          <Alert severity="info" variant="outlined" sx={{ mt: 1.5, fontSize: 11.5 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <CircularProgress size={14} />
              <span>{status?.message}</span>
            </Box>
          </Alert>
        )}
        {status?.phase === 'prepared' && (
          <Alert severity="warning" variant="outlined" sx={{ mt: 1.5, fontSize: 11.5 }}>
            {status.message} La transition est préparée sur disque, mais son dépôt n’est pas
            confirmé.
          </Alert>
        )}
        {status?.phase === 'deposited' && (
          <Alert severity="success" variant="outlined" sx={{ mt: 1.5, fontSize: 11.5 }}>
            Transition CA-TLS préparée et déposée{status.output_path ? ` dans ${status.output_path}` : ''}.
            La promotion CA-TLS reste requise à la fin de la fenêtre de recouvrement.
          </Alert>
        )}
        {status?.phase === 'awaiting_promotion_key' && (
          <Alert severity="info" variant="outlined" icon={<KeyRound size={17} />} sx={{ mt: 1.5, fontSize: 11.5 }}>
            {status.message}
          </Alert>
        )}
        {status?.phase === 'promoted' && (
          <Alert severity="success" variant="outlined" sx={{ mt: 1.5, fontSize: 11.5 }}>
            {status.message} Le coffre CA-TLS utilise maintenant la nouvelle époque.
          </Alert>
        )}
        {(status?.phase === 'failed' || error) && (
          <Alert severity="error" variant="outlined" sx={{ mt: 1.5, fontSize: 11.5 }}>
            {error ?? status?.message}
          </Alert>
        )}
        {status?.phase === 'cancelled' && (
          <Alert severity="info" variant="outlined" sx={{ mt: 1.5, fontSize: 11.5 }}>
            Rotation annulée. Aucune transition n’a été produite.
          </Alert>
        )}

        <Box sx={{ display: 'flex', gap: 1, mt: 1.5 }}>
          {!['deposited', 'promoted', 'starting', 'processing_first_key', 'processing_second_key', 'finalizing', 'promoting'].includes(phase) && (
            <Button
              variant="contained"
              onClick={primaryAction}
              disabled={
                busy ||
                (phase === 'awaiting_first_key' && !status?.manifest) ||
                (!status?.can_continue && !valid)
              }
              startIcon={busy ? <CircularProgress size={14} color="inherit" /> : undefined}
            >
              {primaryLabel}
            </Button>
          )}
          {cancellable && (
            <Button color="inherit" variant="outlined" onClick={() => void cancel()} disabled={busy}>
              Annuler
            </Button>
          )}
          {!cancellable && ['processing_first_key', 'processing_second_key'].includes(phase) && (
            <Typography color="text.secondary" sx={{ alignSelf: 'center', fontSize: 11 }}>
              Terminez ou annulez la demande de sécurité Windows pour continuer.
            </Typography>
          )}
        </Box>
      </Paper>
    </Box>
  )
}

function unixDate(seconds: number): string {
  return new Intl.DateTimeFormat('fr-FR', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(seconds * 1_000))
}

/** The campaign is read from the verified backend response, never rebuilt from form values. */
function CampaignManifest({ status }: { status: AstraRotationStatus }) {
  const manifest = status.manifest
  if (!manifest) return null
  const rows = [
    ['Autorité affectée', 'CA-TLS cliente'],
    ['Époque', `${manifest.current_ca_tls_epoch} → ${manifest.next_ca_tls_epoch}`],
    ['Activation', unixDate(manifest.activation_at)],
    ['Retrait', unixDate(manifest.not_after)],
    ['Cibles', String(manifest.target_count)],
    ['Motif', manifest.reason],
    ['Demandée par', manifest.requested_by],
    ['Ancre sortante', manifest.outgoing_anchor_fingerprint],
    ['Empreinte de campagne', manifest.fingerprint],
  ]
  return (
    <Box sx={{ mt: 1.5, borderTop: 1, borderColor: 'divider', pt: 1.5 }}>
      <Typography sx={{ mb: 1, fontSize: 11.5, fontWeight: 700 }}>
        Campagne vérifiée — contrôlez ces valeurs avant de continuer
      </Typography>
      <Box component="dl" sx={{ display: 'grid', gridTemplateColumns: '132px minmax(0, 1fr)', gap: '5px 12px', m: 0 }}>
        {rows.map(([label, value]) => (
          <Box key={label} sx={{ display: 'contents' }}>
            <Typography component="dt" color="text.secondary" sx={{ fontSize: 10.5 }}>
              {label}
            </Typography>
            <Typography
              component="dd"
              sx={{ m: 0, minWidth: 0, overflowWrap: 'anywhere', fontSize: 10.5, fontFamily: label.includes('Empreinte') || label.includes('Ancre') ? 'monospace' : 'inherit' }}
            >
              {value}
            </Typography>
          </Box>
        ))}
      </Box>
    </Box>
  )
}
