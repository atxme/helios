import { useEffect, useState } from 'react'
import Alert from '@mui/material/Alert'
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
import { KeyRound } from 'lucide-react'

import * as api from '../../api'
import type { KeyRole, OperatorStatus, SlotView, VaultGesture, VaultLocationView } from '../../types'
import { CreateDomainForm } from './CreateDomainForm'
import { KeyRow } from './KeyRow'
import { useOverview } from './useOverview'

const MIN_KEYS = 2
const WAIT_GATEWAY = 'La gateway n’est pas encore dans le relais.'

/** The operator vault and its key slots, read without any key or PIN. */
export function VaultPanel({ onCeremony }: { onCeremony: (status: OperatorStatus) => void }) {
  const { overview, error, refresh } = useOverview()
  const [location, setLocation] = useState<VaultLocationView | null>(null)
  const [locationError, setLocationError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)
  const [removing, setRemoving] = useState<SlotView | null>(null)
  const [newLabel, setNewLabel] = useState('')
  const [newRole, setNewRole] = useState<KeyRole>('recuperation')

  useEffect(() => {
    let cancelled = false
    void api
      .operatorVaultLocation()
      .then((found) => {
        if (!cancelled) setLocation(found)
      })
      .catch((cause) => {
        if (!cancelled) setLocationError(String(cause))
      })
    return () => {
      cancelled = true
    }
  }, [])

  const begin = async (gesture: VaultGesture | { kind: 'verify_key' }) => {
    setBusy(true)
    setActionError(null)
    try {
      onCeremony(
        'kind' in gesture
          ? await api.beginOperatorCeremony(gesture)
          : await api.beginVaultCeremony(gesture),
      )
    } catch (cause) {
      setActionError(String(cause))
    } finally {
      setBusy(false)
    }
  }

  const moveLocation = async (change: () => Promise<VaultLocationView | null>) => {
    setLocationError(null)
    try {
      const moved = await change()
      // A cancelled picker answers nothing: the location stays as it was.
      if (!moved) return
      setLocation(moved)
      refresh()
    } catch (cause) {
      setLocationError(String(cause))
    }
  }

  // The location block comes first and always renders: an unreadable setting
  // or a failed read must still leave « Changer… » and « Emplacement par
  // défaut » within reach, or the operator has no way out of it.
  const shownPath = location ? location.path : (overview?.vault_path ?? null)
  const locationPanel = (
    <Paper variant="outlined" sx={{ p: 1.75 }}>
      <Typography component="h3" sx={{ fontSize: 12.5, fontWeight: 700, mb: 1 }}>
        Coffre opérateur
      </Typography>
      {shownPath && (
        <Typography color="text.secondary" sx={{ fontSize: 10.5, overflowWrap: 'anywhere' }}>
          {shownPath}
        </Typography>
      )}
      {overview?.vault_fingerprint && (
        <Typography sx={{ mt: 0.5, fontSize: 10.5, fontFamily: 'monospace', overflowWrap: 'anywhere' }}>
          {overview.vault_fingerprint}
        </Typography>
      )}
      {location?.error && (
        <Alert severity="error" variant="outlined" sx={{ mt: 1, fontSize: 11.5 }}>
          {location.error}
        </Alert>
      )}
      {location && (location.picker_available || !location.is_default) && (
        <Stack direction="row" spacing={1} sx={{ mt: 1 }}>
          {location.picker_available && (
            <Button
              size="small"
              sx={{ minHeight: 26, fontSize: 11 }}
              onClick={() => void moveLocation(api.chooseVaultLocation)}
            >
              Changer…
            </Button>
          )}
          {!location.is_default && (
            <Button
              size="small"
              sx={{ minHeight: 26, fontSize: 11 }}
              onClick={() => void moveLocation(api.resetVaultLocation)}
            >
              Emplacement par défaut
            </Button>
          )}
        </Stack>
      )}
      {locationError && (
        <Alert severity="error" variant="outlined" sx={{ mt: 1, fontSize: 11.5 }}>
          {locationError}
        </Alert>
      )}
    </Paper>
  )

  if (error) {
    return (
      <Stack spacing={1.25}>
        {locationPanel}
        {/* An unresolved location already says why, in its own block. */}
        {!location?.error && (
          <Alert severity="error" variant="outlined" sx={{ fontSize: 11.5 }}>
            Lecture du coffre impossible : {error}
          </Alert>
        )}
      </Stack>
    )
  }
  if (!overview) return <CircularProgress size={16} aria-label="Lecture du coffre" />

  if (!overview.location_available) {
    return (
      <Stack spacing={1.25}>
        {locationPanel}
        <Alert severity="warning" variant="outlined" sx={{ fontSize: 11.5 }}>
          Emplacement introuvable
        </Alert>
      </Stack>
    )
  }
  if (!overview.exists) {
    return (
      <Stack spacing={1.25}>
        {locationPanel}
        <CreateDomainForm onCeremony={onCeremony} />
      </Stack>
    )
  }

  const slots = overview.slots
  const full = slots.length >= overview.max_slots
  const atMinimum = slots.length <= MIN_KEYS
  const relayReady = Boolean(overview.domain?.server_name && overview.domain?.gateway_wg_public_key)
  const label = newLabel.trim()

  return (
    <Stack spacing={1.25}>
      {locationPanel}
      {!overview.bootstrapped && (
        <Alert
          severity="warning"
          variant="outlined"
          sx={{ fontSize: 11.5, alignItems: 'center' }}
          action={
            <Button
              size="small"
              color="inherit"
              disabled={busy}
              onClick={() =>
                void begin({
                  gesture: 'add_key',
                  label: 'Clé de récupération',
                  role: 'recuperation',
                })
              }
              sx={{ fontSize: 11, whiteSpace: 'nowrap' }}
            >
              Ajouter la clé de récupération
            </Button>
          }
        >
          Une seule clé : la perdre, c’est perdre le domaine.
        </Alert>
      )}
      <Paper variant="outlined" sx={{ p: 1.75 }}>
        <Typography component="h3" sx={{ fontSize: 12.5, fontWeight: 700, mb: 1 }}>
          Clés enrôlées
        </Typography>
        <Typography color="text.secondary" sx={{ fontSize: 11, mb: 1 }}>
          {slots.length} sur {overview.max_slots} emplacements utilisés
        </Typography>
        <Stack spacing={0.5}>
          {slots.map((slot) => (
            <KeyRow
              key={slot.slot_id}
              slot={slot}
              busy={busy}
              canMark={relayReady}
              canRemove={!atMinimum}
              onRenamed={refresh}
              onError={setActionError}
              onMark={(lost) => void begin({ gesture: 'mark_key', slot_id: slot.slot_id, lost })}
              onRemove={() => setRemoving(slot)}
            />
          ))}
        </Stack>
        {!relayReady && (
          <Typography color="text.secondary" sx={{ mt: 0.75, fontSize: 10.5 }}>
            {WAIT_GATEWAY}
          </Typography>
        )}
        {atMinimum && (
          <Typography color="text.secondary" sx={{ mt: 0.75, fontSize: 10.5 }}>
            Le coffre doit garder au moins deux clés.
          </Typography>
        )}
        <Stack direction="row" spacing={1} sx={{ mt: 1.5, alignItems: 'center' }}>
          <TextField
            size="small"
            label="Libellé de la nouvelle clé"
            value={newLabel}
            disabled={full}
            onChange={(event) => setNewLabel(event.target.value)}
            slotProps={{ htmlInput: { maxLength: 64 } }}
            sx={{ flex: 1, minWidth: 0, '& input': { fontSize: 11.5 }, '& label': { fontSize: 11.5 } }}
          />
          <TextField
            select
            size="small"
            label="Rôle"
            value={newRole}
            disabled={full}
            onChange={(event) => setNewRole(event.target.value as KeyRole)}
            slotProps={{ select: { native: true } }}
            sx={{ width: 150, '& select': { fontSize: 11.5 }, '& label': { fontSize: 11.5 } }}
          >
            <option value="recuperation">Clé de récupération</option>
            <option value="principale">Clé principale</option>
          </TextField>
          <Button
            size="small"
            variant="outlined"
            disabled={busy || full || !label}
            onClick={() => void begin({ gesture: 'add_key', label, role: newRole })}
            sx={{ minHeight: 30, fontSize: 11.5, whiteSpace: 'nowrap' }}
          >
            Ajouter une clé
          </Button>
        </Stack>
        {full && (
          <Typography color="text.secondary" sx={{ mt: 0.75, fontSize: 10.5 }}>
            Le coffre porte déjà huit clés.
          </Typography>
        )}
        <Button
          size="small"
          variant="contained"
          disabled={busy}
          startIcon={<KeyRound size={14} aria-hidden />}
          onClick={() => void begin({ kind: 'verify_key' })}
          sx={{ mt: 1.5, minHeight: 30, fontSize: 11.5 }}
        >
          Vérifier une clé
        </Button>
        {actionError && (
          <Alert severity="error" variant="outlined" sx={{ mt: 1, fontSize: 11.5 }}>
            {actionError}
          </Alert>
        )}
      </Paper>
      <Dialog open={removing !== null} onClose={() => setRemoving(null)} fullWidth maxWidth="xs">
        <DialogTitle sx={{ fontSize: 13 }}>Retirer une clé</DialogTitle>
        <DialogContent>
          <DialogContentText sx={{ fontSize: 12 }}>
            {`Retirer « ${removing?.label ?? ''} » ? Le retrait est définitif. Une sauvegarde antérieure du coffre reste ouvrable par cette clé.`}
          </DialogContentText>
          <DialogContentText sx={{ mt: 1, fontSize: 12 }}>
            {`Pour ouvrir le coffre, présentez une autre clé que « ${removing?.label ?? ''} ».`}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button size="small" onClick={() => setRemoving(null)}>
            Annuler
          </Button>
          <Button
            size="small"
            color="error"
            variant="contained"
            onClick={() => {
              const target = removing
              setRemoving(null)
              if (target) void begin({ gesture: 'remove_key', slot_id: target.slot_id })
            }}
          >
            Retirer
          </Button>
        </DialogActions>
      </Dialog>
    </Stack>
  )
}
