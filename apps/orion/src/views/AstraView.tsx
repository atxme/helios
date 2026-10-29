import type { ReactNode } from 'react'
import { useCallback, useEffect, useRef, useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import ButtonBase from '@mui/material/ButtonBase'
import CircularProgress from '@mui/material/CircularProgress'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { Check, KeyRound } from 'lucide-react'

import * as api from '../api'
import { OperatorCeremonyPanel } from './OperatorCeremony'
import { DomainPanel } from './astra/DomainPanel'
import { ArtifactDownloads } from './astra/ArtifactDownloads'
import { EnrollmentOperatorPanel } from './astra/EnrollmentOperatorPanel'
import { VaultPanel } from './astra/VaultPanel'
import { GUTTER, MINT, PINE, RULE } from '../theme'
import type {
  AstraRotationInput,
  AstraRotationPhase,
  AstraRotationStatus,
  CampaignScope,
  OperatorPendingOperation,
  OperatorStatus,
} from '../types'

const EMPTY_INPUT: AstraRotationInput = {
  vault_path: '',
  heliosd_url: 'http://100.64.0.1:8080',
  operation_id: '',
  output_path: '',
}

const HELPER_CAMPAIGN_SCOPES = new Set<CampaignScope>([
  'orion_profile',
  'orion_device',
  'fleet_leafs',
])

const TABS = [
  'Enrôlement',
  'Coffre et clés',
  'Domaine',
  'Approbations',
  'Rotations',
  'Gateways',
] as const
type AstraTab = (typeof TABS)[number]

function WaitingNote({ children }: { children: string }) {
  return (
    <Alert severity="info" variant="outlined" sx={{ fontSize: 11.5 }}>
      {children}
    </Alert>
  )
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
export function AstraView({
  onRecoveryReady,
}: {
  /** Resumes the client-owned half once Astra has released the recovery grant. */
  onRecoveryReady?: (operationId: string) => Promise<void>
} = {}) {
  const [input, setInput] = useState<AstraRotationInput>(EMPTY_INPUT)
  const [status, setStatus] = useState<AstraRotationStatus | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // A protocol-2 ceremony, when one is open. It can outlive this view — the
  // helper keeps working while the operator looks at another tab — so it is
  // read on mount rather than only created here.
  const [ceremony, setCeremony] = useState<OperatorStatus | null>(null)
  const [pending, setPending] = useState<OperatorPendingOperation[]>([])
  const [tab, setTab] = useState<AstraTab>('Enrôlement')
  const [finishingRecovery, setFinishingRecovery] = useState(false)
  const recoveryAttempt = useRef<string | null>(null)

  const finishRecovery = useCallback(
    (operationId: string, attempt: string, force = false) => {
      if (!onRecoveryReady || (!force && recoveryAttempt.current === attempt)) return
      recoveryAttempt.current = attempt
      setFinishingRecovery(true)
      setError(null)
      void onRecoveryReady(operationId)
        .catch((cause) => setError(String(cause)))
        .finally(() => setFinishingRecovery(false))
    },
    [onRecoveryReady],
  )

  useEffect(() => {
    let cancelled = false
    void api
      .operatorCeremonyStatus()
      .then((found) => {
        if (!cancelled) setCeremony(found)
      })
      .catch(() => {})
    void api
      .operatorPendingOperations()
      .then((found) => {
        if (!cancelled) setPending(found)
      })
      .catch(() => {})
    return () => {
      cancelled = true
    }
  }, [])

  // The command returns the first state after a press (usually
  // `processing_key`). The helper then continues on its own while Windows
  // owns the modal WebAuthn dialog, so later states must be observed here.
  // Without this poll a two-key campaign never displays its second prompt.
  useEffect(() => {
    if (!ceremony) return
    const terminal =
      typeof ceremony.gesture === 'string' &&
      ['done', 'failed', 'cancelled'].includes(ceremony.gesture)
    if (terminal) return
    const timer = window.setTimeout(() => {
      void api
        .operatorCeremonyStatus()
        .then((found) => {
          if (found && found.revision >= ceremony.revision) setCeremony(found)
        })
        .catch((cause) => setError(String(cause)))
    }, 350)
    return () => window.clearTimeout(timer)
  }, [ceremony])

  // The helper owns the operator half only. Once it has released the grant,
  // Orion must immediately resume the client session it kept in Rust: that
  // installs the candidate and relays the signed commit to the gateway. The
  // old screen lost this hand-off when switching tabs and forced a second
  // press on « Récupérer ».
  useEffect(() => {
    if (
      !onRecoveryReady ||
      ceremony?.operation !== 'recover_identity' ||
      ceremony.gesture !== 'done' ||
      !ceremony.operation_id
    ) {
      return
    }
    const attempt = `${ceremony.session_id}:${ceremony.operation_id}`
    finishRecovery(ceremony.operation_id, attempt)
  }, [ceremony, finishRecovery, onRecoveryReady])

  const dismissCeremony = async () => {
    setBusy(true)
    setError(null)
    try {
      await api.dismissOperatorCeremony()
      setCeremony(null)
      setPending(await api.operatorPendingOperations())
    } catch (cause) {
      setError(String(cause))
    } finally {
      setBusy(false)
    }
  }

  const openCampaign = async (operationId: string) => {
    setBusy(true)
    setError(null)
    try {
      setCeremony(
        await api.beginOperatorCeremony({
          kind: 'approve_campaign',
          operation_id: operationId,
        }),
      )
    } catch (cause) {
      setError(String(cause))
    } finally {
      setBusy(false)
    }
  }

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

  // A live protocol-2 ceremony owns the tab entirely. It is not a section
  // beside the CA-TLS form: an operator holding a security key must not be
  // shown, in the same view, a second ceremony they could start by mistake.
  if (ceremony) {
    return (
      <Box sx={{ height: '100%', overflowY: 'auto', px: GUTTER, py: 1.5 }}>
        <Typography component="h2" sx={{ fontSize: 13, fontWeight: 700, mb: 0.5 }}>
          Astra
        </Typography>
        <Typography color="text.secondary" sx={{ fontSize: 11.5, lineHeight: 1.55, mb: 1.5 }}>
          Une opération attend l’opérateur.
        </Typography>
        <OperatorCeremonyPanel
          status={ceremony}
          onStatus={setCeremony}
          onDismiss={() => void dismissCeremony()}
        />
        {(ceremony.operation === 'invite_enrollment' ||
          ceremony.operation === 'accept_enrollment' ||
          ceremony.operation === 'finalize_domain') && (
          <ArtifactDownloads gesture={ceremony.gesture} />
        )}
        {finishingRecovery && (
          <Alert severity="info" variant="outlined" sx={{ mt: 1.25, fontSize: 11.5 }}>
            Grant reçu : installation et commit de la nouvelle identité…
          </Alert>
        )}
        {error && (
          <>
            <Alert severity="error" variant="outlined" sx={{ mt: 1.25, fontSize: 11.5 }}>
              La cérémonie Astra a abouti, mais Orion n’a pas pu terminer la récupération :{' '}
              {error}
            </Alert>
            {ceremony.operation === 'recover_identity' &&
              ceremony.gesture === 'done' &&
              ceremony.operation_id && (
                <Button
                  size="small"
                  variant="outlined"
                  disabled={finishingRecovery}
                  onClick={() =>
                    finishRecovery(
                      ceremony.operation_id as string,
                      `${ceremony.session_id}:${ceremony.operation_id}`,
                      true,
                    )
                  }
                  sx={{ mt: 0.75, minHeight: 30, fontSize: 11.5 }}
                >
                  Réessayer la finalisation
                </Button>
              )}
          </>
        )}
      </Box>
    )
  }

  // Campaigns the domain opened and nobody has approved yet. Read from the
  // gateway in the tunnel: they are how an operator finds work without being
  // handed an identifier by whoever ran the command that created it.
  const approvals = (
    <>
        <Typography color="text.secondary" sx={{ fontSize: 11.5, lineHeight: 1.55, mb: 1.5 }}>
          {pending.length === 0
            ? 'Aucune opération n’attend l’opérateur.'
            : pending.length === 1
            ? 'Une opération attend l’opérateur.'
            : `${pending.length} opérations attendent l’opérateur.`}
        </Typography>
        <Stack spacing={1.25}>
          {pending.map((operation) => {
            const supported = HELPER_CAMPAIGN_SCOPES.has(operation.scope)
            return (
              <Paper key={operation.operation_id} variant="outlined" sx={{ px: 1.75, py: 1.5 }}>
                <Typography sx={{ fontSize: 12.5, fontWeight: 650 }}>
                  {operation.reason}
                </Typography>
                <Typography color="text.secondary" sx={{ mt: 0.25, fontSize: 11.5 }}>
                  Demandée par {operation.requested_by} — {operation.target_count} pair
                  {operation.target_count > 1 ? 's' : ''}, {operation.required_credentials} clé
                  {operation.required_credentials > 1 ? 's' : ''} distincte
                  {operation.required_credentials > 1 ? 's' : ''}
                </Typography>
                <Typography
                  color="text.disabled"
                  sx={{ mt: 0.25, fontSize: 10.5, fontFamily: 'monospace' }}
                >
                  {operation.operation_id}
                </Typography>
                <Typography color="text.disabled" sx={{ mt: 0.25, fontSize: 11 }}>
                  jusqu’au {new Date(operation.expires_at * 1000).toLocaleString()}
                </Typography>
                <Button
                  size="small"
                  variant="contained"
                  disabled={busy || !supported}
                  startIcon={<KeyRound size={14} aria-hidden />}
                  onClick={() => void openCampaign(operation.operation_id)}
                  sx={{ mt: 1, minHeight: 30, fontSize: 11.5 }}
                >
                  Ouvrir la cérémonie
                </Button>
                {!supported && (
                  <Alert severity="warning" variant="outlined" sx={{ mt: 1, fontSize: 11.5 }}>
                    Cette cérémonie n’est pas encore disponible dans Orion.
                  </Alert>
                )}
              </Paper>
            )
          })}
        </Stack>
        {error && (
          <Alert severity="error" variant="outlined" sx={{ mt: 1.25, fontSize: 11.5 }}>
            {error}
          </Alert>
        )}
    </>
  )

  const rotations = (
    <>
      <Typography color="text.secondary" sx={{ fontSize: 11.5, lineHeight: 1.55, mb: 1.5 }}>
        Rotation de l’autorité CA-TLS cliente.
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
            detail="Lecture de la campagne en cours."
            state={stateOf(0, phase)}
          />
          <CeremonyStep
            number={2}
            title="Première clé autorisée"
            detail={
              status?.first_key_label
                ? `Clé reconnue : ${status.first_key_label}`
                : 'Branchez la clé principale, puis continuez.'
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
              {status.message}
            </Alert>
          </>
        )}
        {status?.phase === 'awaiting_second_key' && (
          <Alert severity="info" variant="outlined" icon={<KeyRound size={17} />} sx={{ mt: 1.5, fontSize: 11.5 }}>
            {status.message}
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
            {status.message} Le dépôt n’est pas confirmé.
          </Alert>
        )}
        {status?.phase === 'deposited' && (
          <Alert severity="success" variant="outlined" sx={{ mt: 1.5, fontSize: 11.5 }}>
            Transition CA-TLS déposée{status.output_path ? ` dans ${status.output_path}` : ''}.
            La promotion reste à faire.
          </Alert>
        )}
        {status?.phase === 'awaiting_promotion_key' && (
          <Alert severity="info" variant="outlined" icon={<KeyRound size={17} />} sx={{ mt: 1.5, fontSize: 11.5 }}>
            {status.message}
          </Alert>
        )}
        {status?.phase === 'promoted' && (
          <Alert severity="success" variant="outlined" sx={{ mt: 1.5, fontSize: 11.5 }}>
            {status.message}
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
    </>
  )

  const panels: Record<AstraTab, ReactNode> = {
    'Enrôlement': <EnrollmentOperatorPanel onCeremony={setCeremony} />,
    'Coffre et clés': <VaultPanel onCeremony={setCeremony} />,
    'Domaine': <DomainPanel onCeremony={setCeremony} />,
    'Approbations': approvals,
    'Rotations': rotations,
    'Gateways': (
      <WaitingNote>La gestion des gateways arrivera dans une prochaine version d’Orion.</WaitingNote>
    ),
  }

  return (
    <Box sx={{ height: '100%', overflowY: 'auto', px: GUTTER, py: 1.5 }}>
      <Typography component="h2" sx={{ fontSize: 13, fontWeight: 700, mb: 0.5 }}>
        Astra
      </Typography>
      {/* A fixed grid rather than a tab strip: six labels in one row overflow
          the window Orion is drawn for, and a scrolling strip hides sections
          the operator must see. Three columns keep every section in view, in
          two rows, at the base size. */}
      <Box
        role="tablist"
        aria-label="Sections Astra"
        style={{ gridTemplateColumns: 'repeat(3, minmax(0, 1fr))' }}
        sx={{ display: 'grid', gap: 0.75, mb: 1.5 }}
      >
        {TABS.map((name) => {
          const selected = name === tab
          const count = name === 'Approbations' ? pending.length : 0
          return (
            <ButtonBase
              key={name}
              role="tab"
              aria-selected={selected}
              onClick={() => setTab(name)}
              sx={{
                minWidth: 0,
                minHeight: 32,
                px: 0.75,
                gap: 0.5,
                borderRadius: 1.5,
                border: `1px solid ${selected ? PINE : RULE}`,
                bgcolor: selected ? MINT : 'background.paper',
                color: selected ? PINE : 'text.secondary',
                fontSize: 12,
                fontWeight: selected ? 700 : 600,
                transition: 'background-color 150ms ease, border-color 150ms ease',
                '&:hover': { borderColor: PINE },
                '&.Mui-focusVisible': { outline: `2px solid ${PINE}`, outlineOffset: 1 },
              }}
            >
              <Box component="span" sx={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {name}
              </Box>
              {count > 0 && (
                <Box
                  component="span"
                  sx={{
                    flexShrink: 0,
                    minWidth: 16,
                    height: 16,
                    px: 0.5,
                    borderRadius: 8,
                    bgcolor: PINE,
                    color: '#fff',
                    fontSize: 10,
                    fontWeight: 700,
                    lineHeight: '16px',
                  }}
                >
                  {count}
                </Box>
              )}
            </ButtonBase>
          )
        })}
      </Box>
      {panels[tab]}
    </Box>
  )
}

function unixDate(seconds: number): string {
  return new Intl.DateTimeFormat('fr-FR', {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZone: 'Europe/Paris',
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
