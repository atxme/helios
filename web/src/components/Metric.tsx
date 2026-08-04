import Box from '@mui/material/Box'
import Paper from '@mui/material/Paper'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import type { LucideIcon } from 'lucide-react'

/**
 * A single reading, sized to be caught at a glance.
 *
 * Metrics are the top of every view: the four numbers that answer "what is
 * this gateway doing right now" without scrolling. Each is a bordered panel
 * with its own icon in brand gold — the readings are the instrument's dial
 * faces, and a row of them should read as a console, not as a row of empty
 * pills.
 *
 * `accent` tints the figure only when the value carries a live security
 * meaning. A reading that is merely informative stays in ink: an accent spent
 * on everything says nothing.
 */

interface Props {
  label: string
  value: string
  icon?: LucideIcon
  /** An `sx` color path — usually a `state.*` tone from `state.ts`. */
  accent?: string
  hint?: string
}

export function Metric({ label, value, icon: Icon, accent, hint }: Props) {
  const tile = (
    <Paper
      sx={{
        px: 2.25,
        py: 1.75,
        borderRadius: '14px',
        bgcolor: 'surfaceContainer.low',
        border: '1px solid',
        borderColor: 'divider',
        display: 'flex',
        alignItems: 'center',
        gap: 1.75,
        minWidth: 0,
        height: '100%',
      }}
    >
      {Icon && (
        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: 34,
            height: 34,
            borderRadius: '10px',
            flexShrink: 0,
            bgcolor: 'primary.container',
            color: 'primary.onContainer',
          }}
        >
          <Icon size={17} strokeWidth={1.8} />
        </Box>
      )}
      <Box sx={{ minWidth: 0 }}>
        <Typography variant="overline" sx={{ color: 'text.secondary', display: 'block' }}>
          {label}
        </Typography>
        <Typography
          sx={{
            fontFamily: 'monospace',
            fontSize: '1.0625rem',
            fontWeight: 500,
            lineHeight: 1.25,
            letterSpacing: '-0.01em',
            color: accent ?? 'text.primary',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
        >
          {value}
        </Typography>
      </Box>
    </Paper>
  )

  return hint ? <Tooltip title={hint}>{tile}</Tooltip> : tile
}
