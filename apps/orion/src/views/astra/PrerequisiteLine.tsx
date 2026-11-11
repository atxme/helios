import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Typography from '@mui/material/Typography'
import { Check, X } from 'lucide-react'

import { PINE } from '../../theme'
import type { Prerequisite } from './rotationRows'

/** One line of the prerequisites: the check, its label, and what fixes it when it is red. */
export function PrerequisiteLine({
  line,
  busy,
  onFix,
}: {
  line: Prerequisite
  busy: boolean
  onFix?: (line: Prerequisite) => void
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
            onClick={() => onFix?.(line)}
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
