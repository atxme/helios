import { useState } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'

import * as api from '../../api'
import type { SlotView } from '../../types'

const ROLE_LABEL = { principale: 'Principale', recuperation: 'Récupération' } as const
const STATE_LABEL = { lost: 'perdue', revoked: 'révoquée' } as const

const action = { minWidth: 0, px: 0.75, py: 0, minHeight: 24, fontSize: 11 } as const

/** One enrolled key: its label, role, state and the gestures it accepts. */
export function KeyRow({
  slot,
  canMark,
  canRemove,
  busy,
  onRenamed,
  onMark,
  onRemove,
  onError,
}: {
  slot: SlotView
  canMark: boolean
  canRemove: boolean
  busy: boolean
  onRenamed: () => void
  onMark: (lost: boolean) => void
  onRemove: () => void
  onError: (message: string | null) => void
}) {
  const [draft, setDraft] = useState<string | null>(null)

  const save = async () => {
    const label = (draft ?? '').trim()
    if (!label || label === slot.label) {
      setDraft(null)
      return
    }
    onError(null)
    try {
      await api.renameOperatorKey(slot.slot_id, label)
      setDraft(null)
      onRenamed()
    } catch (cause) {
      onError(String(cause))
    }
  }

  const lost = slot.state === 'lost'
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', columnGap: 1, rowGap: 0.25 }}>
      <Box sx={{ flex: '1 1 160px', minWidth: 0 }}>
        {draft === null ? (
          <Typography sx={{ fontSize: 11.5, overflowWrap: 'anywhere' }}>{slot.label}</Typography>
        ) : (
          <TextField
            autoFocus
            fullWidth
            size="small"
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === 'Enter') void save()
              if (event.key === 'Escape') setDraft(null)
            }}
            slotProps={{
              htmlInput: { 'aria-label': 'Nouveau libellé', maxLength: 64 },
            }}
            sx={{ '& input': { fontSize: 11.5, py: 0.5 } }}
          />
        )}
      </Box>
      <Typography color="text.secondary" sx={{ fontSize: 11 }}>
        {ROLE_LABEL[slot.role]}
      </Typography>
      {(slot.state === 'lost' || slot.state === 'revoked') && (
        <Typography color="error" sx={{ fontSize: 11, fontWeight: 600 }}>
          {STATE_LABEL[slot.state]}
        </Typography>
      )}
      <Box sx={{ display: 'flex', ml: 'auto' }}>
        <Button
          size="small"
          sx={action}
          disabled={busy}
          aria-label={`Renommer ${slot.label}`}
          onClick={() => setDraft(slot.label)}
        >
          Renommer
        </Button>
        {slot.state !== 'revoked' && (
          <Button
            size="small"
            sx={action}
            disabled={busy || !canMark}
            aria-label={`${lost ? 'Réactiver' : 'Marquer perdue'} ${slot.label}`}
            onClick={() => onMark(!lost)}
          >
            {lost ? 'Réactiver' : 'Marquer perdue'}
          </Button>
        )}
        <Button
          size="small"
          color="error"
          sx={action}
          disabled={busy || !canRemove}
          aria-label={`Retirer ${slot.label}`}
          onClick={onRemove}
        >
          Retirer
        </Button>
      </Box>
    </Box>
  )
}
