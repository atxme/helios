import { useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import CircularProgress from '@mui/material/CircularProgress'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogContentText from '@mui/material/DialogContentText'
import DialogTitle from '@mui/material/DialogTitle'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'

import * as api from '../../api'
import type { DomainView, OperatorStatus, RelayUpdate } from '../../types'
import { useOverview } from './useOverview'

const WAIT_GATEWAY = 'La gateway n’est pas encore dans le relais.'
const fieldSx = { '& input': { fontSize: 11.5 }, '& label': { fontSize: 11.5 } }

interface FormValues {
  gatewayKey: string
  serverName: string
  serviceKey: string
  epoch: string
  origin: string
}
const EMPTY_FORM: FormValues = { gatewayKey: '', serverName: '', serviceKey: '', epoch: '', origin: '' }

/** « Libellé : avant → après » over a recorded value, « Libellé : après » for a first fill. */
const line = (label: string, before: string | number | null, after: string) =>
  before === null ? `${label} : ${after}` : `${label} : ${before} → ${after}`

/**
 * The values the operator changed. The gateway key and the server name only
 * fill an empty relay (changing them is a gateway transition), so the form
 * never offers them once recorded.
 */
function changes(form: FormValues, domain: DomainView): { update: RelayUpdate; lines: string[] } {
  const update: RelayUpdate = {}
  const lines: string[] = []
  const gatewayKey = form.gatewayKey.trim()
  if (!domain.gateway_wg_public_key && gatewayKey) {
    update.gateway_wg_public_key = gatewayKey
    lines.push(line('Clé WireGuard de la gateway', null, gatewayKey))
  }
  const serverName = form.serverName.trim()
  if (!domain.server_name && serverName) {
    update.server_name = serverName
    lines.push(line('Nom de service', null, serverName))
  }
  const serviceKey = form.serviceKey.trim()
  if (serviceKey && serviceKey !== domain.astra_service_public_key) {
    update.astra_service_public_key = serviceKey
    lines.push(line('Clé de service Astra', domain.astra_service_public_key, serviceKey))
  }
  const epoch = form.epoch.trim()
  if (epoch && Number(epoch) !== domain.astra_service_key_epoch) {
    update.astra_service_key_epoch = Number(epoch)
    lines.push(line('Époque de la clé de service', domain.astra_service_key_epoch, epoch))
  }
  const origin = form.origin.trim()
  if (origin && origin !== domain.astra_authority_url) {
    update.astra_authority_url = origin
    lines.push(line('Origine d’Astra', domain.astra_authority_url, origin))
  }
  return { update, lines }
}

/** The trust domain recorded in the operator vault, completed and finalized from here. */
export function DomainPanel({ onCeremony }: { onCeremony: (status: OperatorStatus) => void }) {
  const { overview, error, refresh } = useOverview()
  const [editing, setEditing] = useState(false)
  const [form, setForm] = useState<FormValues>(EMPTY_FORM)
  const [pending, setPending] = useState<{ update: RelayUpdate; lines: string[] } | null>(null)
  const [busy, setBusy] = useState(false)
  const [formError, setFormError] = useState<string | null>(null)
  const [adoptError, setAdoptError] = useState<string | null>(null)
  const [finalizeError, setFinalizeError] = useState<string | null>(null)
  const setField = (key: keyof FormValues) => (value: string) =>
    setForm((current) => ({ ...current, [key]: value }))

  const save = async () => {
    if (!pending) return
    const { update } = pending
    setPending(null)
    setBusy(true)
    setFormError(null)
    try {
      await api.writeDomainRelay(update)
      setEditing(false)
      setForm(EMPTY_FORM)
      refresh()
    } catch (cause) {
      setFormError(String(cause))
    } finally {
      setBusy(false)
    }
  }

  const adopt = async () => {
    setBusy(true)
    setAdoptError(null)
    try {
      await api.adoptConnectedGateway()
      refresh()
    } catch (cause) {
      setAdoptError(String(cause))
    } finally {
      setBusy(false)
    }
  }

  const finalize = async () => {
    setBusy(true)
    setFinalizeError(null)
    try {
      onCeremony(await api.beginVaultCeremony({ gesture: 'finalize_domain' }))
    } catch (cause) {
      setFinalizeError(String(cause))
    } finally {
      setBusy(false)
    }
  }

  if (error) {
    return (
      <Alert severity="error" variant="outlined" sx={{ fontSize: 11.5 }}>
        Lecture du domaine impossible : {error}
      </Alert>
    )
  }
  if (!overview) return <CircularProgress size={16} aria-label="Lecture du domaine" />
  const domain = overview.domain
  if (!domain) {
    return (
      <Alert severity="info" variant="outlined" sx={{ fontSize: 11.5 }}>
        Aucun relais n’est enregistré dans le coffre : le domaine n’a pas encore été relayé.
      </Alert>
    )
  }
  const rows: [string, string, boolean][] = [
    ['Domaine de confiance', domain.trust_domain_id, false],
    ['Identifiant RP', domain.rp_id, false],
    ['Empreinte CA-PQ', domain.ca_pq_fingerprint, true],
    ['Époque CA', domain.ca_epoch === null ? '—' : String(domain.ca_epoch), false],
    [
      'Époque CA-TLS',
      domain.ca_tls_present && domain.ca_tls_epoch !== null ? String(domain.ca_tls_epoch) : 'absente',
      false,
    ],
    ['Nom du serveur', domain.server_name ?? '—', false],
    ['Clé WireGuard de la gateway', domain.gateway_wg_public_key ?? '—', true],
  ]
  const gatewayKnown = Boolean(domain.server_name && domain.gateway_wg_public_key)
  const needsFinalizing = !domain.ca_tls_present || !overview.credentials_complete
  const pendingChange = changes(form, domain)
  const epochInvalid =
    form.epoch.trim() !== '' &&
    (!/^\d+$/.test(form.epoch.trim()) ||
    !Number.isSafeInteger(Number(form.epoch.trim())))
  return (
    <Paper variant="outlined" sx={{ p: 1.75 }}>
      <Typography component="h3" sx={{ fontSize: 12.5, fontWeight: 700, mb: 1.25 }}>
        Domaine
      </Typography>
      <Box component="dl" sx={{ display: 'grid', gridTemplateColumns: '150px minmax(0, 1fr)', gap: '5px 12px', m: 0 }}>
        {rows.map(([label, value, mono]) => (
          <Box key={label} sx={{ display: 'contents' }}>
            <Typography component="dt" color="text.secondary" sx={{ fontSize: 10.5 }}>
              {label}
            </Typography>
            <Typography
              component="dd"
              sx={{ m: 0, minWidth: 0, overflowWrap: 'anywhere', fontSize: 10.5, fontFamily: mono ? 'monospace' : 'inherit' }}
            >
              {value}
            </Typography>
          </Box>
        ))}
      </Box>
      {!editing && (
        <Stack direction="row" spacing={1} sx={{ mt: 1.5, flexWrap: 'wrap', rowGap: 1 }}>
          <Button
            size="small"
            variant="outlined"
            disabled={busy}
            onClick={() => setEditing(true)}
            sx={{ minHeight: 30, fontSize: 11.5 }}
          >
            Modifier
          </Button>
          {!gatewayKnown && (
            <Button
              size="small"
              variant="outlined"
              disabled={busy}
              onClick={() => void adopt()}
              sx={{ minHeight: 30, fontSize: 11.5 }}
            >
              Reprendre la gateway connectée
            </Button>
          )}
        </Stack>
      )}
      {adoptError && (
        <Alert severity="error" variant="outlined" sx={{ mt: 1, fontSize: 11.5 }}>
          {adoptError}
        </Alert>
      )}
      {editing && (
        <Stack spacing={1.25} sx={{ mt: 1.5 }}>
          {!domain.gateway_wg_public_key && (
            <TextField
              size="small"
              label="Clé WireGuard de la gateway"
              value={form.gatewayKey}
              onChange={(event) => setField('gatewayKey')(event.target.value)}
              sx={fieldSx}
            />
          )}
          {!domain.server_name && (
            <TextField
              size="small"
              label="Nom de service"
              value={form.serverName}
              onChange={(event) => setField('serverName')(event.target.value)}
              sx={fieldSx}
            />
          )}
          <TextField
            size="small"
            label="Clé de service Astra"
            value={form.serviceKey}
            onChange={(event) => setField('serviceKey')(event.target.value)}
            sx={fieldSx}
          />
          <TextField
            size="small"
            label="Époque de la clé de service"
            value={form.epoch}
            error={epochInvalid}
            helperText={epochInvalid ? 'Un entier positif.' : undefined}
            onChange={(event) => setField('epoch')(event.target.value)}
            sx={fieldSx}
          />
          <TextField
            size="small"
            label="Origine d’Astra"
            value={form.origin}
            onChange={(event) => setField('origin')(event.target.value)}
            sx={fieldSx}
          />
          <Typography color="text.secondary" sx={{ fontSize: 10.5 }}>
            Seuls les champs remplis sont enregistrés.
            {gatewayKnown && ' La gateway déjà nommée ne se change pas ici.'}
          </Typography>
          <Stack direction="row" spacing={1}>
            <Button
              size="small"
              variant="contained"
              disabled={busy || epochInvalid || pendingChange.lines.length === 0}
              onClick={() => setPending(pendingChange)}
              sx={{ minHeight: 30, fontSize: 11.5 }}
            >
              Enregistrer
            </Button>
            <Button
              size="small"
              disabled={busy}
              onClick={() => {
                setEditing(false)
                setForm(EMPTY_FORM)
                setFormError(null)
              }}
              sx={{ minHeight: 30, fontSize: 11.5 }}
            >
              Annuler
            </Button>
          </Stack>
          {formError && (
            <Alert severity="error" variant="outlined" sx={{ fontSize: 11.5 }}>
              {formError}
            </Alert>
          )}
        </Stack>
      )}
      {needsFinalizing && (
        <Box sx={{ mt: 1.5 }}>
          <Button
            size="small"
            variant="contained"
            disabled={busy || !gatewayKnown}
            onClick={() => void finalize()}
            sx={{ minHeight: 30, fontSize: 11.5 }}
          >
            Finaliser le domaine
          </Button>
          {!gatewayKnown && (
            <Typography color="text.secondary" sx={{ mt: 0.75, fontSize: 10.5 }}>
              {WAIT_GATEWAY}
            </Typography>
          )}
          {finalizeError && (
            <Alert severity="error" variant="outlined" sx={{ mt: 1, fontSize: 11.5 }}>
              {finalizeError}
            </Alert>
          )}
        </Box>
      )}
      <Dialog open={pending !== null} onClose={() => setPending(null)} fullWidth maxWidth="xs">
        <DialogTitle sx={{ fontSize: 13 }}>Enregistrer dans le relais</DialogTitle>
        <DialogContent>
          <DialogContentText component="div" sx={{ fontSize: 12 }}>
            Ces valeurs seront écrites dans le relais.
            <Box component="ul" sx={{ m: 0, mt: 0.5, pl: 2.5, overflowWrap: 'anywhere' }}>
              {pending?.lines.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </Box>
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button size="small" onClick={() => setPending(null)}>
            Annuler
          </Button>
          <Button size="small" variant="contained" onClick={() => void save()}>
            Confirmer
          </Button>
        </DialogActions>
      </Dialog>
    </Paper>
  )
}
