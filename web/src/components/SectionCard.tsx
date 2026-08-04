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
 * MD3 expresses elevation with tone rather than shadow, so a card is simply
 * one rung up the `surfaceContainer` ladder from the page behind it, plus a
 * hairline. Views never build their own panel: every card in Helios has the
 * same radius, the same padding and the same header rhythm, which is what
 * keeps seven very different views reading as one instrument.
 *
 * Typographic contract, applied here and relied on everywhere else:
 * the card title is `h6` — plain, readable prose — while the mono capitals of
 * `overline` are reserved for **labelling data** (`DataRow`, `Metric`). The
 * previous interface used those capitals for both, which left no way to tell a
 * section from a field at a glance.
 */

interface Props {
  title?: ReactNode
  /** One sentence under the title: what this card is for, or what it implies. */
  subtitle?: ReactNode
  icon?: LucideIcon
  /** Controls pinned to the right of the header. */
  action?: ReactNode
  children?: ReactNode
  /** For content that manages its own padding — lists, editors, tables. */
  disableContentPadding?: boolean
  sx?: SxProps<Theme>
}

export function SectionCard({
  title,
  subtitle,
  icon: Icon,
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
        overflow: 'hidden',
        ...sx,
      }}
    >
      {hasHeader && (
        <Stack
          direction="row"
          spacing={2}
          sx={{
            alignItems: 'flex-start',
            px: 3,
            pt: 2.5,
            pb: children ? 2 : 2.5,
          }}
        >
          {Icon && (
            <Box sx={{ color: 'primary.main', mt: 0.25, display: 'flex' }}>
              <Icon size={20} strokeWidth={1.6} />
            </Box>
          )}
          <Box sx={{ minWidth: 0, flex: 1 }}>
            {title && <Typography variant="h6">{title}</Typography>}
            {subtitle && (
              <Typography variant="body2" sx={{ color: 'text.secondary', mt: 0.5 }}>
                {subtitle}
              </Typography>
            )}
          </Box>
          {action && <Box sx={{ flexShrink: 0 }}>{action}</Box>}
        </Stack>
      )}

      {children && (
        <Box sx={disableContentPadding ? undefined : { px: 3, pb: 2.5, pt: hasHeader ? 0 : 2.5 }}>
          {children}
        </Box>
      )}
    </Paper>
  )
}
