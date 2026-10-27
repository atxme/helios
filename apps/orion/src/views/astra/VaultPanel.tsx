import { useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import CircularProgress from '@mui/material/CircularProgress'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { KeyRound } from 'lucide-react'

import * as api from '../../api'
import type { OperatorStatus } from '../../types'
import { useOverview } from './useOverview'

const ROLE_LABEL = { principale: 'Principale', recuperation: 'Récupération' } as const

/** The operator vault and its key slots, read without any key or PIN. */
export function VaultPanel({ onCeremony }: { onCeremony: (status: OperatorStatus) => void }) {
  const { overview, error } = useOverview()
  const [busy, setBusy] = useState(false)
  const [startError, setStartError] = useState<string | null>(null)

  const verify = async () => {
    setBusy(true)
    setStartError(null)
    try {
      onCeremony(await api.beginOperatorCeremony({ kind: 'verify_key' }))
    } catch (cause) {
      setStartError(String(cause))
    } finally {
      setBusy(false)
    }
  }

  if (error) {
    return (
      <Alert severity="error" variant="outlined" sx={{ fontSize: 11.5 }}>
        Lecture du coffre impossible : {error}
      </Alert>
    )
  }
  if (!overview) return <CircularProgress size={16} aria-label="Lecture du coffre" />
  if (!overview.exists) {
    return (
      <Alert severity="info" variant="outlined" sx={{ fontSize: 11.5 }}>
        Aucun coffre opérateur à cet emplacement. La création d'un domaine arrivera dans Orion ;
        d'ici là, `astra-signer init`.
      </Alert>
    )
  }
  return (
    <Stack spacing={1.25}>
      <Paper variant="outlined" sx={{ p: 1.75 }}>
        <Typography component="h3" sx={{ fontSize: 12.5, fontWeight: 700, mb: 1 }}>
          Coffre opérateur
        </Typography>
        <Typography color="text.secondary" sx={{ fontSize: 10.5, overflowWrap: 'anywhere' }}>
          {overview.vault_path}
        </Typography>
        {overview.vault_fingerprint && (
          <Typography sx={{ mt: 0.5, fontSize: 10.5, fontFamily: 'monospace', overflowWrap: 'anywhere' }}>
            {overview.vault_fingerprint}
          </Typography>
        )}
      </Paper>
      <Paper variant="outlined" sx={{ p: 1.75 }}>
        <Typography component="h3" sx={{ fontSize: 12.5, fontWeight: 700, mb: 1 }}>
          Clés enrôlées
        </Typography>
        <Typography color="text.secondary" sx={{ fontSize: 11, mb: 1 }}>
          {overview.slots.length} sur {overview.max_slots} emplacements utilisés
        </Typography>
        <Stack spacing={0.75}>
          {overview.slots.map((slot) => (
            <Box key={slot.slot_id} sx={{ display: 'flex', justifyContent: 'space-between', gap: 1 }}>
              <Typography sx={{ fontSize: 11.5 }}>{slot.label}</Typography>
              <Typography color="text.secondary" sx={{ fontSize: 11 }}>
                {ROLE_LABEL[slot.role]}
              </Typography>
            </Box>
          ))}
        </Stack>
        <Button
          size="small"
          variant="contained"
          disabled={busy}
          startIcon={<KeyRound size={14} aria-hidden />}
          onClick={() => void verify()}
          sx={{ mt: 1.5, minHeight: 30, fontSize: 11.5 }}
        >
          Vérifier une clé
        </Button>
        {startError && (
          <Alert severity="error" variant="outlined" sx={{ mt: 1, fontSize: 11.5 }}>
            {startError}
          </Alert>
        )}
      </Paper>
    </Stack>
  )
}
