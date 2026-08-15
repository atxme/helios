import Box from '@mui/material/Box'
import Stack from '@mui/material/Stack'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import type { LucideIcon } from 'lucide-react'
import type { ReactNode } from 'react'

/**
 * One labelled fact: a name on the left, a value on the right.
 *
 * The value is monospaced because nearly all of them are machine-readable —
 * interfaces, ports, CIDRs, key fingerprints — and an operator compares them
 * character by character against a config file or another screen. Proportional
 * digits break that comparison.
 */

interface Props {
  label: ReactNode
  value: ReactNode
  icon?: LucideIcon
  /** Shown on hover: what this value means, or what it implies. */
  hint?: string
  /** Long values (fingerprints, hashes) wrap instead of being truncated. */
  wrap?: boolean
}

export function DataRow({ label, value, icon: Icon, hint, wrap = false }: Props) {
  const empty = value === null || value === undefined || value === ''

  const row = (
    <Stack
      direction="row"
      spacing={2}
      sx={{
        alignItems: 'baseline',
        py: 1.25,
        borderBottom: '1px solid',
        borderColor: 'divider',
        '&:last-of-type': { borderBottom: 0 },
      }}
    >
      {Icon && (
        <Box sx={{ color: 'text.disabled', alignSelf: 'center', display: 'flex' }}>
          <Icon size={15} strokeWidth={1.6} />
        </Box>
      )}
      <Typography
        variant="overline"
        sx={{ color: 'text.secondary', width: 132, flexShrink: 0 }}
      >
        {label}
      </Typography>
      <Typography
        sx={{
          fontFamily: 'monospace',
          fontSize: '0.8125rem',
          color: empty ? 'text.disabled' : 'text.primary',
          minWidth: 0,
          ...(wrap
            ? { wordBreak: 'break-all' }
            : { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }),
        }}
      >
        {empty ? '—' : value}
      </Typography>
    </Stack>
  )

  return hint ? <Tooltip title={hint}>{row}</Tooltip> : row
}
