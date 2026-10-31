import { useCallback, useEffect, useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Checkbox from '@mui/material/Checkbox'
import CircularProgress from '@mui/material/CircularProgress'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogContentText from '@mui/material/DialogContentText'
import DialogTitle from '@mui/material/DialogTitle'
import FormControlLabel from '@mui/material/FormControlLabel'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'

import * as api from '../../api'
import type { EnrollmentGesture, InvitationView, OperatorStatus } from '../../types'
import { readFileText } from './readFileText'
import { useOverview } from './useOverview'

/** An invitation is a short window, not a standing right (Rust enforces the same bound). */
const MAX_INVITE_HOURS = 24
/** The leaves last a year unless the operator says otherwise; Rust bounds it to 1825 days. */
const DEFAULT_VALIDITY_DAYS = 365
const MAX_VALIDITY_DAYS = 1825

const date = (unix: number) =>
  new Date(unix * 1000).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' })

const integerIn = (text: string, min: number, max: number): number | null => {
  if (!/^\d+$/.test(text.trim())) return null
  const value = Number(text)
  return value >= min && value <= max ? value : null
}

const optional = (text: string): string | undefined => (text.trim() === '' ? undefined : text.trim())

/** The connected profile's public endpoint, or `null` when no tunnel is up. */
function useConnectedEndpoint(): { connected: boolean; endpoint: string } {
  const [found, setFound] = useState({ connected: false, endpoint: '' })
  useEffect(() => {
    let cancelled = false
    void Promise.all([api.getState(), api.getConfig()])
      .then(([state, config]) => {
        if (cancelled || state !== 'up') return
        const profile = config.profiles.find((candidate) => candidate.name === config.selected)
        if (profile) setFound({ connected: true, endpoint: profile.endpoint })
      })
      .catch(() => {
        // Without a readable profile the screen simply offers the unconnected form.
      })
    return () => {
      cancelled = true
    }
  }, [])
  return found
}

type Form = 'invite' | 'accept' | null

/**
 * Astra › Enrôlement: invite a device, accept its request, resume an
 * acceptance, and manage the invitations of this machine.
 *
 * The page names a gesture and fills its typed parameters; Rust validates them
 * again, shows what will be signed and asks for the key. Files travel by their
 * content, read here, so no path is ever sent.
 */
export function EnrollmentOperatorPanel({
  onCeremony,
}: {
  onCeremony: (status: OperatorStatus) => void
}) {
  const { overview, error: overviewError } = useOverview()
  const gateway = useConnectedEndpoint()
  const [form, setForm] = useState<Form>(null)
  const [invitations, setInvitations] = useState<InvitationView[] | null>(null)
  const [resuming, setResuming] = useState<InvitationView | null>(null)
  const [revoking, setRevoking] = useState<InvitationView | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const refresh = useCallback(async () => {
    try {
      setInvitations(await api.operatorInvitations())
    } catch (cause) {
      setInvitations([])
      setError(`Invitations illisibles : ${String(cause)}`)
    }
  }, [])
  useEffect(() => {
    void refresh()
  }, [refresh])

  const begin = async (gesture: EnrollmentGesture) => {
    setBusy(true)
    setError(null)
    try {
      onCeremony(await api.beginEnrollmentCeremony(gesture))
    } catch (cause) {
      setError(String(cause))
    } finally {
      setBusy(false)
    }
  }

  const revoke = async () => {
    if (!revoking) return
    const target = revoking
    setRevoking(null)
    setError(null)
    try {
      await api.revokeInvitation(target.invitation_id)
      await refresh()
    } catch (cause) {
      setError(String(cause))
    }
  }

  const vaultReady = overview?.exists === true

  return (
    <Stack spacing={1.25}>
      {overviewError ? (
        <Alert severity="error" variant="outlined" sx={{ fontSize: 11.5 }}>
          Lecture du coffre impossible : {overviewError}
        </Alert>
      ) : !overview ? (
        <CircularProgress size={16} aria-label="Lecture du coffre" />
      ) : !overview.exists ? (
        <Alert severity="info" variant="outlined" sx={{ fontSize: 11.5 }}>
          Aucun coffre opérateur à cet emplacement : l’enrôlement en demande un.
        </Alert>
      ) : (
        <Paper variant="outlined" sx={{ p: 1.75 }}>
          <Typography component="h3" sx={{ fontSize: 12.5, fontWeight: 700, mb: 0.5 }}>
            Coffre opérateur
          </Typography>
          <Typography color="text.secondary" sx={{ fontSize: 11, overflowWrap: 'anywhere' }}>
            {overview.slots.length} clé(s) enrôlée(s)
            {overview.domain?.server_name ? ` · gateway ${overview.domain.server_name}` : ''}
            {gateway.connected ? ' · tunnel actif' : ' · aucune gateway connectée'}
          </Typography>
        </Paper>
      )}

      <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
        <Button
          size="small"
          variant="contained"
          disabled={busy || !vaultReady}
          onClick={() => setForm(form === 'invite' ? null : 'invite')}
          sx={{ minHeight: 30, fontSize: 11.5 }}
        >
          Inviter un poste…
        </Button>
        <Button
          size="small"
          variant="outlined"
          disabled={busy || !vaultReady}
          onClick={() => setForm(form === 'accept' ? null : 'accept')}
          sx={{ minHeight: 30, fontSize: 11.5 }}
        >
          Accepter une demande…
        </Button>
      </Box>

      {form === 'invite' && (
        <InviteForm connected={gateway.connected} busy={busy} onSubmit={begin} />
      )}
      {form === 'accept' && (
        <AcceptForm endpoint={gateway.endpoint} busy={busy} onSubmit={begin} />
      )}

      {error && (
        <Alert severity="error" variant="outlined" onClose={() => setError(null)} sx={{ fontSize: 11.5 }}>
          {error}
        </Alert>
      )}

      <Paper variant="outlined" sx={{ p: 1.75 }}>
        <Typography component="h3" sx={{ fontSize: 12.5, fontWeight: 700, mb: 1 }}>
          Invitations
        </Typography>
        {invitations === null ? (
          <CircularProgress size={16} aria-label="Lecture des invitations" />
        ) : invitations.length === 0 ? (
          <Typography color="text.secondary" sx={{ fontSize: 11.5 }}>
            Aucune invitation sur ce poste.
          </Typography>
        ) : (
          <Stack spacing={0.75}>
            {invitations.map((entry) => (
              <InvitationRow
                key={entry.invitation_id}
                entry={entry}
                onRevoke={() => setRevoking(entry)}
                onResume={() => setResuming(entry)}
              />
            ))}
          </Stack>
        )}
      </Paper>

      <ResumeDialog
        entry={resuming}
        endpoint={gateway.endpoint}
        busy={busy}
        onClose={() => setResuming(null)}
        onSubmit={async (gesture) => {
          setResuming(null)
          await begin(gesture)
        }}
      />

      <Dialog open={revoking !== null} onClose={() => setRevoking(null)}>
        <DialogTitle sx={{ fontSize: 14 }}>Révoquer cette invitation ?</DialogTitle>
        <DialogContent>
          <DialogContentText sx={{ fontSize: 12 }}>
            L’invitation n’admettra plus aucune demande. Aucune clé n’est nécessaire, mais
            l’opération est définitive.
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button color="inherit" onClick={() => setRevoking(null)}>
            Annuler
          </Button>
          <Button color="error" onClick={() => void revoke()}>
            Révoquer l’invitation
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  )
}

function InvitationRow({
  entry,
  onRevoke,
  onResume,
}: {
  entry: InvitationView
  onRevoke: () => void
  onResume: () => void
}) {
  const peer =
    entry.peer_admitted === null ? 'pair : inconnu' : entry.peer_admitted ? 'pair admis' : 'pair non admis'
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
      <Box sx={{ minWidth: 0, flex: 1 }}>
        <Typography sx={{ fontSize: 12, fontWeight: 600 }} noWrap>
          {entry.requested_name ?? `${entry.invitation_id.slice(0, 8)}…`}
        </Typography>
        <Typography color="text.secondary" sx={{ fontSize: 10.5 }}>
          {entry.state} · échéance {date(entry.not_after_unix)}
          {entry.state === 'consommée' ? ` · ${peer}` : ''}
        </Typography>
      </Box>
      {entry.state === 'émise' && (
        <Button size="small" color="inherit" onClick={onRevoke} sx={{ fontSize: 11 }}>
          Révoquer
        </Button>
      )}
      {entry.resumable && (
        <Button size="small" variant="outlined" onClick={onResume} sx={{ fontSize: 11 }}>
          Reprendre
        </Button>
      )}
    </Box>
  )
}

function InviteForm({
  connected,
  busy,
  onSubmit,
}: {
  connected: boolean
  busy: boolean
  onSubmit: (gesture: EnrollmentGesture) => Promise<void>
}) {
  const [name, setName] = useState('')
  const [hours, setHours] = useState('24')
  const [readmission, setReadmission] = useState(false)
  const [leaf, setLeaf] = useState<string | null>(null)
  const [fileError, setFileError] = useState<string | null>(null)

  const duration = integerIn(hours, 1, MAX_INVITE_HOURS)
  const ready = name.trim() !== '' && duration !== null && (connected || leaf !== null)

  const pick = async (file: File | undefined) => {
    setFileError(null)
    if (!file) return
    try {
      setLeaf(await readFileText(file))
    } catch (cause) {
      setLeaf(null)
      setFileError(String(cause instanceof Error ? cause.message : cause))
    }
  }

  return (
    <Paper variant="outlined" sx={{ p: 1.75 }}>
      <Stack spacing={1.25}>
        <TextField
          size="small"
          label="Nom du poste"
          value={name}
          onChange={(event) => setName(event.target.value)}
          helperText="Lettres, chiffres, « . », « _ » et « - » ; devient le nom du fichier."
        />
        <TextField
          size="small"
          label="Durée (heures)"
          value={hours}
          onChange={(event) => setHours(event.target.value)}
          error={duration === null}
          helperText={duration === null ? 'De 1 à 24 heures.' : ' '}
          slotProps={{ htmlInput: { inputMode: 'numeric' } }}
        />
        <FormControlLabel
          control={
            <Checkbox
              size="small"
              checked={readmission}
              onChange={(event) => setReadmission(event.target.checked)}
            />
          }
          label={<Typography sx={{ fontSize: 12 }}>Autoriser la réadmission d’une clé déjà enrôlée</Typography>}
        />
        {(
          <Box>
            <TextField
              size="small"
              type="file"
              label="Feuille PQ de la gateway"
              slotProps={{ inputLabel: { shrink: true } }}
              onChange={(event) =>
                void pick((event.target as HTMLInputElement).files?.[0])
              }
              fullWidth
            />
            <Typography color="text.secondary" sx={{ fontSize: 10.5, mt: 0.5 }}>
              {connected
                ? 'Facultatif : la gateway connectée est lue ; ce fichier sert si elle ne répond pas.'
                : 'Aucune gateway n’est connectée : la feuille de la gateway épingle l’invitation.'}
            </Typography>
            {fileError && (
              <Alert severity="error" variant="outlined" sx={{ mt: 0.75, fontSize: 11.5 }}>
                {fileError}
              </Alert>
            )}
          </Box>
        )}
        {readmission && (
          <Alert severity="warning" variant="outlined" sx={{ fontSize: 11.5 }}>
            La réadmission demande deux clés distinctes.
          </Alert>
        )}
        <Box>
          <Button
            size="small"
            variant="contained"
            disabled={busy || !ready}
            onClick={() =>
              duration !== null &&
              void onSubmit({
                gesture: 'invite',
                valid_for_hours: duration,
                allow_readmission: readmission,
                name: name.trim(),
                ...(leaf !== null ? { gateway_pq_certificate: leaf } : {}),
              })
            }
            sx={{ minHeight: 30, fontSize: 11.5 }}
          >
            Signer l’invitation
          </Button>
        </Box>
      </Stack>
    </Paper>
  )
}

/** The fields the document of a device is built from, shared by accept and resume. */
function DeliveryFields({
  endpoint,
  setEndpoint,
  allowedIps,
  setAllowedIps,
  sshTarget,
  setSshTarget,
}: {
  endpoint: string
  setEndpoint: (value: string) => void
  allowedIps: string
  setAllowedIps: (value: string) => void
  sshTarget: string
  setSshTarget: (value: string) => void
}) {
  return (
    <>
      <TextField
        size="small"
        label="Adresse publique de la gateway"
        value={endpoint}
        onChange={(event) => setEndpoint(event.target.value)}
        helperText="Point d’accès WireGuard tel que le document le portera."
      />
      <TextField
        size="small"
        label="Routes autorisées (facultatif)"
        value={allowedIps}
        onChange={(event) => setAllowedIps(event.target.value)}
      />
      <TextField
        size="small"
        label="Cible SSH (facultatif)"
        value={sshTarget}
        onChange={(event) => setSshTarget(event.target.value)}
      />
    </>
  )
}

/** The endpoint field starts from the connected profile's, until the operator edits it. */
function useEndpoint(prefill: string): [string, (value: string) => void] {
  const [typed, setTyped] = useState<string | null>(null)
  return [typed ?? prefill, setTyped]
}

function AcceptForm({
  endpoint: prefill,
  busy,
  onSubmit,
}: {
  endpoint: string
  busy: boolean
  onSubmit: (gesture: EnrollmentGesture) => Promise<void>
}) {
  const [request, setRequest] = useState<string | null>(null)
  const [fileError, setFileError] = useState<string | null>(null)
  const [days, setDays] = useState(String(DEFAULT_VALIDITY_DAYS))
  const [endpoint, setEndpoint] = useEndpoint(prefill)
  const [allowedIps, setAllowedIps] = useState('')
  const [sshTarget, setSshTarget] = useState('')

  const validity = integerIn(days, 1, MAX_VALIDITY_DAYS)
  const ready = request !== null && validity !== null && endpoint.trim() !== ''

  const pick = async (file: File | undefined) => {
    setFileError(null)
    if (!file) return
    try {
      setRequest(await readFileText(file))
    } catch (cause) {
      setRequest(null)
      setFileError(String(cause instanceof Error ? cause.message : cause))
    }
  }

  return (
    <Paper variant="outlined" sx={{ p: 1.75 }}>
      <Stack spacing={1.25}>
        <Box>
          <TextField
            size="small"
            type="file"
            label="Fichier de demande"
            slotProps={{
              inputLabel: { shrink: true },
              htmlInput: { accept: '.helios-request,text/plain' },
            }}
            onChange={(event) => void pick((event.target as HTMLInputElement).files?.[0])}
            fullWidth
          />
          {fileError && (
            <Alert severity="error" variant="outlined" sx={{ mt: 0.75, fontSize: 11.5 }}>
              {fileError}
            </Alert>
          )}
        </Box>
        <TextField
          size="small"
          label="Validité des feuilles (jours)"
          value={days}
          onChange={(event) => setDays(event.target.value)}
          error={validity === null}
          helperText={validity === null ? `De 1 à ${MAX_VALIDITY_DAYS} jours.` : ' '}
        />
        <DeliveryFields
          endpoint={endpoint}
          setEndpoint={setEndpoint}
          allowedIps={allowedIps}
          setAllowedIps={setAllowedIps}
          sshTarget={sshTarget}
          setSshTarget={setSshTarget}
        />
        <Box>
          <Button
            size="small"
            variant="contained"
            disabled={busy || !ready}
            onClick={() =>
              request !== null &&
              validity !== null &&
              void onSubmit({
                gesture: 'accept',
                request,
                validity_days: validity,
                endpoint: endpoint.trim(),
                ...(optional(allowedIps) ? { allowed_ips: optional(allowedIps) } : {}),
                ...(optional(sshTarget) ? { ssh_target: optional(sshTarget) } : {}),
              })
            }
            sx={{ minHeight: 30, fontSize: 11.5 }}
          >
            Vérifier et accepter
          </Button>
        </Box>
      </Stack>
    </Paper>
  )
}

function ResumeDialog({
  entry,
  endpoint: prefill,
  busy,
  onClose,
  onSubmit,
}: {
  entry: InvitationView | null
  endpoint: string
  busy: boolean
  onClose: () => void
  onSubmit: (gesture: EnrollmentGesture) => Promise<void>
}) {
  const [endpoint, setEndpoint] = useEndpoint(prefill)
  const [allowedIps, setAllowedIps] = useState('')
  const [sshTarget, setSshTarget] = useState('')
  return (
    <Dialog open={entry !== null} onClose={onClose} fullWidth maxWidth="xs">
      <DialogTitle sx={{ fontSize: 14 }}>Reprendre l’enrôlement</DialogTitle>
      <DialogContent>
        <DialogContentText sx={{ fontSize: 12, mb: 1.25 }}>
          Les feuilles déjà émises sont reprises, sans en émettre d’autres. Une clé signe le
          document.
        </DialogContentText>
        <Stack spacing={1.25} sx={{ pt: 0.5 }}>
          <DeliveryFields
            endpoint={endpoint}
            setEndpoint={setEndpoint}
            allowedIps={allowedIps}
            setAllowedIps={setAllowedIps}
            sshTarget={sshTarget}
            setSshTarget={setSshTarget}
          />
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button color="inherit" onClick={onClose}>
          Annuler
        </Button>
        <Button
          disabled={busy || entry === null || endpoint.trim() === ''}
          onClick={() =>
            entry &&
            void onSubmit({
              gesture: 'resume',
              invitation_id: entry.invitation_id,
              endpoint: endpoint.trim(),
              ...(optional(allowedIps) ? { allowed_ips: optional(allowedIps) } : {}),
              ...(optional(sshTarget) ? { ssh_target: optional(sshTarget) } : {}),
            })
          }
        >
          Reprendre l’enrôlement
        </Button>
      </DialogActions>
    </Dialog>
  )
}
