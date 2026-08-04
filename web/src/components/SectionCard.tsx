import Box from '@mui/material/Box'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import type { SxProps, Theme } from '@mui/material/styles'
import type { LucideIcon } from 'lucide-react'
import type { ReactNode } from 'react'
import { CARD_RADIUS } from '../theme'

/**
 * The console's single content surface.
 *
 * Every card in Helios has the same radius, the same padding and the same
 * header rhythm, which is what keeps four very different views reading as one
 * product. Views never build their own panel.
 *
 * `accent` colors the header icon only. It marks what a card is *about* —
 * a client, a key, a firewall rule — and it is the one place the interface
 * spends color on categories rather than on state.
 */

interface Props {
  title?: ReactNode
  /** One short line. If it needs a paragraph, it belongs in a tooltip. */
  subtitle?: ReactNode
  icon?: LucideIcon
  /** An `sx` color path for the header icon. */
  accent?: string
  /** Controls pinned to the right of the header. */
  action?: ReactNode
  children?: ReactNode
  /** For content managing its own padding — lists, tables, editors. */
  disableContentPadding?: boolean
  sx?: SxProps<Theme>
}

export function SectionCard({
  title,
  subtitle,
  icon: Icon,
  accent = 'primary.main',
  action,
  children,
  disableContentPadding = false,
  sx,
}: Props) {
  const hasHeader = Boolean(title || subtitle || action)

  return (
    <Paper
      sx={{
        borderRadius: `${CARD_RADIUS}px`,
        bgcolor: 'surfaceContainer.low',
        border: '1px solid',
        borderColor: 'divider',
        boxShadow: 'var(--mui-palette-cardShadow)',
        overflow: 'hidden',
        ...sx,
      }}
    >
      {hasHeader && (
        <Stack
          direction="row"
          spacing={1.5}
          sx={{ alignItems: 'center', px: 2.5, pt: 2.25, pb: children ? 1.75 : 2.25 }}
        >
          {Icon && (
            <Box sx={{ color: accent, display: 'flex', flexShrink: 0 }}>
              <Icon size={18} strokeWidth={2} />
            </Box>
          )}
          <Box sx={{ minWidth: 0, flex: 1 }}>
            {title && <Typography variant="h6">{title}</Typography>}
            {subtitle && (
              <Typography variant="body2" sx={{ color: 'text.secondary', mt: 0.25 }}>
                {subtitle}
              </Typography>
            )}
          </Box>
          {action && <Box sx={{ flexShrink: 0 }}>{action}</Box>}
        </Stack>
      )}

      {children && (
        <Box sx={disableContentPadding ? undefined : { px: 2.5, pb: 2.25, pt: hasHeader ? 0 : 2.25 }}>
          {children}
        </Box>
      )}
    </Paper>
  )
}
