import Box from '@mui/material/Box'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { keyframes } from '@mui/material/styles'
import type { Theme } from '@mui/material/styles'
import type { ReactNode } from 'react'
import { TUNNEL_STATE, toneColors } from '../state'
import { CARD_RADIUS, EMPHASIZED } from '../theme'
import type { TunnelState } from '../types'
import { HeliosMark } from './HeliosMark'

/**
 * The one thing this console exists to answer, rendered twice.
 *
 * `StateBanner` is the signature of the interface: the Helios mark, lit from
 * behind by the state's own color. The mark is a solar disk and a corona, so
 * the gateway's health is expressed the way the product's own emblem already
 * expresses it — the sun is either shining or it is not. That is the whole
 * reason the hero is a mark and not the usual big-number-with-a-label: the
 * number that matters (uptime) is meaningless when the answer is "down", and a
 * hero that goes blank in the state you most need to read is a bad hero.
 *
 * `StateChip` is the same fact compressed, for the app bar, where it must
 * coexist with navigation without competing with it.
 *
 * Both take their meaning from `state.ts` and their pigment from
 * `palette.state`; neither knows what "up" implies.
 */

const pulse = keyframes`
  0%, 100% { opacity: 1; transform: scale(1); }
  50%      { opacity: 0.4; transform: scale(0.82); }
`

const breathe = keyframes`
  0%, 100% { opacity: 0.55; }
  50%      { opacity: 0.95; }
`

/** States where the gateway is waiting on something outside itself. */
function isPending(state: TunnelState): boolean {
  return state === 'connecting' || state === 'captive_portal'
}

/**
 * The CSS variable behind a tone, read from the theme rather than spelled out.
 *
 * Gradients and `color-mix()` need a real color string, which `sx` colour
 * paths cannot provide. Going through `theme.vars` keeps MUI as the single
 * author of the variable's name.
 */
function toneVar(theme: Theme, state: TunnelState): string {
  return theme.vars.palette.state[TUNNEL_STATE[state].tone].main
}

/**
 * The tone's container, used for the hero's wash.
 *
 * The wash cannot be built from `main`: a dark green at low opacity over white
 * turns muddy, and a light green over the night scheme disappears. The
 * container tone is already the scheme's answer to "this surface, tinted by
 * this state", so mixing it holds up in both.
 */
function containerVar(theme: Theme, state: TunnelState): string {
  return theme.vars.palette.state[TUNNEL_STATE[state].tone].container
}

function Dot({ state }: { state: TunnelState }) {
  const tone = toneColors(TUNNEL_STATE[state].tone)
  return (
    <Box
      sx={{
        width: 8,
        height: 8,
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
  const lit = state === 'up'

  return (
    <Paper
      sx={theme => ({
        position: 'relative',
        overflow: 'hidden',
        borderRadius: `${CARD_RADIUS}px`,
        bgcolor: 'surfaceContainer.low',
        border: '1px solid',
        borderColor: 'divider',
        px: { xs: 2.5, sm: 3.5 },
        py: 3,
        transition: `border-color 420ms ${EMPHASIZED}`,
        // The corona's light: a broad wash from the mark's side of the panel,
        // plus a tighter halo right behind the disk.
        '&::before': {
          content: '""',
          position: 'absolute',
          inset: 0,
          pointerEvents: 'none',
          background: [
            `radial-gradient(300px 190px at 96px 50%, color-mix(in srgb, ${toneVar(
              theme,
              state,
            )} 22%, transparent) 0%, transparent 70%)`,
            `linear-gradient(102deg, ${containerVar(theme, state)} 0%, color-mix(in srgb, ${containerVar(
              theme,
              state,
            )} 45%, transparent) 34%, transparent 68%)`,
          ].join(', '),
        },
        // A carrier line across the top: the state, read at a glance from the
        // far side of a room.
        '&::after': {
          content: '""',
          position: 'absolute',
          insetInline: 0,
          top: 0,
          height: 2,
          pointerEvents: 'none',
          background: `linear-gradient(90deg, ${toneVar(theme, state)} 0%, color-mix(in srgb, ${toneVar(
            theme,
            state,
          )} 30%, transparent) 45%, transparent 85%)`,
        },
      })}
    >
      <Stack
        direction="row"
        spacing={{ xs: 2.5, sm: 4 }}
        sx={{ position: 'relative', alignItems: 'center', flexWrap: 'wrap', rowGap: 3 }}
      >
        <Box
          sx={theme => ({
            position: 'relative',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
            color: tone.main,
            // Only a live tunnel glows; the rest of the time the mark is
            // simply drawn in the state's color.
            filter: lit
              ? `drop-shadow(0 0 18px color-mix(in srgb, ${toneVar(theme, state)} 55%, transparent))`
              : 'none',
            animation: lit ? `${breathe} 4.5s ease-in-out infinite` : 'none',
          })}
        >
          <HeliosMark size={84} title={`Passerelle : ${semantics.label.toLowerCase()}`} />
        </Box>

        <Box sx={{ minWidth: 0, flex: 1 }}>
          <Typography variant="overline" sx={{ color: 'text.secondary' }}>
            État du tunnel
          </Typography>
          <Stack direction="row" spacing={1.5} sx={{ alignItems: 'center', mt: 0.75 }}>
            <Dot state={state} />
            <Typography variant="h4" sx={{ color: tone.main }}>
              {semantics.label}
            </Typography>
          </Stack>
          <Typography variant="body2" sx={{ color: 'text.secondary', mt: 1, maxWidth: '52ch' }}>
            {semantics.detail}
          </Typography>
        </Box>

        {uptime && (
          <Box sx={{ flexShrink: 0 }}>
            <Typography variant="overline" sx={{ color: 'text.secondary' }}>
              Depuis
            </Typography>
            <Typography
              sx={{
                fontFamily: 'monospace',
                fontSize: '2.25rem',
                fontWeight: 500,
                lineHeight: 1.05,
                letterSpacing: '-0.02em',
                fontVariantNumeric: 'tabular-nums',
                color: 'text.primary',
                mt: 0.5,
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
      spacing={1}
      sx={{
        alignItems: 'center',
        px: 1.5,
        py: 0.75,
        borderRadius: '9px',
        bgcolor: tone.container,
        color: tone.onContainer,
        border: '1px solid',
        borderColor: tone.main,
        transition: `background-color 420ms ${EMPHASIZED}`,
      }}
    >
      <Dot state={state} />
      <Typography variant="overline" sx={{ color: 'inherit' }}>
        {semantics.label}
      </Typography>
    </Stack>
  )
}
