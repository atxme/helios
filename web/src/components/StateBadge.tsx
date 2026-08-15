import Box from '@mui/material/Box'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { keyframes } from '@mui/material/styles'
import type { ReactNode } from 'react'
import { TUNNEL_STATE, toneColors } from '../state'
import { CARD_RADIUS, EMPHASIZED } from '../theme'
import type { TunnelState } from '../types'

/**
 * The one thing this console exists to answer, rendered twice.
 *
 * `StateBanner` is the first thing on the overview: a white card whose left
 * edge and icon carry the state's color, the state named in words, and the
 * elapsed time as a large tabular figure. No glow and no tinted field — an
 * earlier version washed the whole surface in the state color, which made the
 * card shout the same volume whether the tunnel was fine or on fire.
 *
 * `StateChip` is the same fact compressed, for the header, where it must
 * coexist with navigation without competing with it.
 *
 * Both take their meaning from `state.ts` and their pigment from
 * `palette.state`; neither knows what "up" implies.
 */

const pulse = keyframes`
  0%, 100% { opacity: 1; transform: scale(1); }
  50%      { opacity: 0.35; transform: scale(0.8); }
`

/** States where the gateway is waiting on something outside itself. */
function isPending(state: TunnelState): boolean {
  return state === 'connecting' || state === 'captive_portal'
}

function Dot({ state, size = 8 }: { state: TunnelState; size?: number }) {
  const tone = toneColors(TUNNEL_STATE[state].tone)
  return (
    <Box
      sx={{
        width: size,
        height: size,
        borderRadius: '50%',
        flexShrink: 0,
        bgcolor: tone.main,
        animation: isPending(state) ? `${pulse} 1.8s ease-in-out infinite` : 'none',
      }}
    />
  )
}

export function StateBanner({
  state,
  uptime,
  trailing,
}: {
  state: TunnelState
  /** Elapsed time since the tunnel came up, already formatted. */
  uptime?: string
  trailing?: ReactNode
}) {
  const semantics = TUNNEL_STATE[state]
  const tone = toneColors(semantics.tone)
  const { Icon } = semantics

  return (
    <Paper
      sx={{
        position: 'relative',
        overflow: 'hidden',
        borderRadius: `${CARD_RADIUS}px`,
        bgcolor: 'surfaceContainer.low',
        border: '1px solid',
        borderColor: 'divider',
        boxShadow: 'var(--mui-palette-cardShadow)',
        px: 3,
        py: 2.5,
        // The state, readable from the far side of a room.
        '&::before': {
          content: '""',
          position: 'absolute',
          insetBlock: 0,
          left: 0,
          width: '4px',
          bgcolor: tone.main,
          transition: `background-color 320ms ${EMPHASIZED}`,
        },
      }}
    >
      <Stack
        direction="row"
        spacing={2.5}
        sx={{ alignItems: 'center', flexWrap: 'wrap', rowGap: 2, pl: 1 }}
      >
        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: 46,
            height: 46,
            borderRadius: '12px',
            flexShrink: 0,
            bgcolor: tone.container,
            color: tone.main,
          }}
        >
          <Icon size={24} strokeWidth={2} />
        </Box>

        <Box sx={{ minWidth: 0, flex: 1 }}>
          <Stack direction="row" spacing={1.25} sx={{ alignItems: 'center' }}>
            <Dot state={state} />
            <Typography variant="h4">{semantics.label}</Typography>
          </Stack>
          <Typography variant="body2" sx={{ color: 'text.secondary', mt: 0.5 }}>
            {semantics.detail}
          </Typography>
        </Box>

        {uptime && (
          <Box sx={{ flexShrink: 0, textAlign: 'right' }}>
            <Typography variant="overline" sx={{ color: 'text.secondary' }}>
              Depuis
            </Typography>
            <Typography
              sx={{
                fontFamily: 'monospace',
                fontSize: '1.875rem',
                fontWeight: 500,
                lineHeight: 1.1,
                letterSpacing: '-0.02em',
                fontVariantNumeric: 'tabular-nums',
                mt: 0.25,
              }}
            >
              {uptime}
            </Typography>
          </Box>
        )}

        {trailing}
      </Stack>
    </Paper>
  )
}

export function StateChip({ state }: { state: TunnelState }) {
  const semantics = TUNNEL_STATE[state]
  const tone = toneColors(semantics.tone)

  return (
    <Stack
      direction="row"
      spacing={0.875}
      sx={{
        alignItems: 'center',
        px: 1.25,
        py: 0.625,
        borderRadius: '8px',
        bgcolor: tone.container,
        color: tone.onContainer,
        transition: `background-color 320ms ${EMPHASIZED}`,
      }}
    >
      <Dot state={state} size={7} />
      <Typography variant="overline" sx={{ color: 'inherit' }}>
        {semantics.label}
      </Typography>
    </Stack>
  )
}
