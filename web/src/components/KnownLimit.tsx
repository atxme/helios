import Box from '@mui/material/Box'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { AlertTriangle, Info, Wrench } from 'lucide-react'
import type { ReactNode } from 'react'

/**
 * States a limitation the operator would otherwise discover in production.
 *
 * The repository forbids `TODO` markers: an incomplete capability is either
 * built, refused in the type system, or **documented as a known limit** — and
 * when that limit is visible to a user, the interface has to say so
 * (AGENTS.md, "Interdiction des TODO"). This component is where that
 * obligation is discharged, which is why it is a named surface rather than an
 * italic gray sentence: a limit is content, not an apology.
 *
 * Three registers, and they are not interchangeable:
 *
 * - `scope` — works as designed, but not here. Kernel counters that need the
 *   real target, a feature out of the current lot. Dashed, uncolored: nothing
 *   is wrong.
 * - `caution` — the gateway is running in a reduced posture and the operator
 *   must know now. Dry-run, development keyring.
 * - `danger` — a security property is not being enforced.
 */

type Register = 'scope' | 'caution' | 'danger'

const REGISTER: Record<Register, {
  Icon: typeof Info
  border: string
  bg: string
  fg: string
  dashed: boolean
}> = {
  scope: {
    Icon: Wrench,
    border: 'divider',
    bg: 'transparent',
    fg: 'text.secondary',
    dashed: true,
  },
  caution: {
    Icon: AlertTriangle,
    border: 'warning.main',
    bg: 'warning.container',
    fg: 'warning.onContainer',
    dashed: false,
  },
  danger: {
    Icon: AlertTriangle,
    border: 'error.main',
    bg: 'error.container',
    fg: 'error.onContainer',
    dashed: false,
  },
}

interface Props {
  register?: Register
  title: ReactNode
  children?: ReactNode
}

export function KnownLimit({ register = 'scope', title, children }: Props) {
  const style = REGISTER[register]
  const { Icon } = style

  return (
    <Stack
      direction="row"
      spacing={1.75}
      sx={{
        alignItems: 'flex-start',
        px: 2.5,
        py: 2,
        borderRadius: '14px',
        border: '1px solid',
        borderStyle: style.dashed ? 'dashed' : 'solid',
        borderColor: style.border,
        bgcolor: style.bg,
        color: style.fg,
      }}
    >
      <Box sx={{ display: 'flex', mt: 0.25, flexShrink: 0 }}>
        <Icon size={17} strokeWidth={1.8} />
      </Box>
      <Box sx={{ minWidth: 0 }}>
        <Typography variant="body2" sx={{ fontWeight: 600, color: 'inherit' }}>
          {title}
        </Typography>
        {children && (
          <Typography variant="body2" sx={{ color: 'inherit', opacity: 0.85, mt: 0.5 }}>
            {children}
          </Typography>
        )}
      </Box>
    </Stack>
  )
}
