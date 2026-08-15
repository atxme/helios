import Box from '@mui/material/Box'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import type { DisplayEvent } from '../types'
import { TUNNEL_STATE } from '../state'

/**
 * The daemon's event stream, newest first.
 *
 * This is the only place in the console showing raw daemon output, and it
 * stays deliberately close to a log: fixed columns, monospace, no wrapping of
 * the timestamp. An operator reads it to correlate with `journalctl`, and a
 * prettified rendering that reorders or reflows the lines defeats that.
 *
 * The colored `kind` column is the one concession: it lets a state transition
 * be spotted in a wall of info lines without reading a single word.
 */

export type TimestampedEvent = DisplayEvent & { ts: string }

/** Kind, text and `sx` color path of one line. Pure, so it can be tested. */
export function describeEvent(event: TimestampedEvent): {
  kind: string
  text: string
  color: string
} {
  switch (event.type) {
    case 'state_changed':
      return {
        kind: 'état',
        text: TUNNEL_STATE[event.state].label,
        color: `state.${TUNNEL_STATE[event.state].tone}.main`,
      }
    case 'log':
      return {
        kind: event.level.slice(0, 5),
        text: event.message,
        color:
          event.level === 'error'
            ? 'error.main'
            : event.level === 'warn'
              ? 'warning.main'
              : 'text.secondary',
      }
    case 'captive_portal_detected':
      return {
        kind: 'portail',
        text: `Passerelle détectée : ${event.gateway}`,
        color: 'state.captivePortal.main',
      }
    case 'mtu_discovered':
      return { kind: 'pmtud', text: `MTU ${event.mtu}, MSS ${event.mss}`, color: 'tertiary.main' }
    case 'split_tunnel_changed':
      return {
        kind: 'routes',
        text: event.cidrs.join(', ') || 'split-tunnel désactivé',
        color: 'tertiary.main',
      }
  }
}

export function EventLog({ events, maxHeight = 280 }: { events: TimestampedEvent[]; maxHeight?: number }) {
  if (events.length === 0) {
    return (
      <Box sx={{ px: 3, py: 4, textAlign: 'center' }}>
        <Typography variant="body2" sx={{ color: 'text.disabled', fontFamily: 'monospace' }}>
          En attente d’événements…
        </Typography>
      </Box>
    )
  }

  return (
    <Box
      component="ul"
      sx={{
        listStyle: 'none',
        m: 0,
        px: 1.5,
        py: 1,
        maxHeight,
        overflowY: 'auto',
        bgcolor: 'surfaceContainer.high',
      }}
    >
      {events.map((event, index) => {
        const line = describeEvent(event)
        return (
          <Stack
            component="li"
            direction="row"
            spacing={1.5}
            // The daemon sends no identifier; position in a newest-first,
            // append-only list is the only stable handle available.
            key={`${event.ts}-${index}`}
            sx={{
              alignItems: 'baseline',
              px: 1.5,
              py: 0.5,
              borderRadius: '7px',
              '&:hover': { bgcolor: 'action.hover' },
            }}
          >
            <Typography
              sx={{
                fontFamily: 'monospace',
                fontSize: '0.75rem',
                color: 'text.disabled',
                flexShrink: 0,
                fontVariantNumeric: 'tabular-nums',
              }}
            >
              {event.ts}
            </Typography>
            <Typography
              variant="overline"
              sx={{ color: line.color, width: 62, flexShrink: 0, lineHeight: 1.6 }}
            >
              {line.kind}
            </Typography>
            <Typography
              sx={{
                fontFamily: 'monospace',
                fontSize: '0.75rem',
                color: 'text.primary',
                minWidth: 0,
                wordBreak: 'break-word',
              }}
            >
              {line.text}
            </Typography>
          </Stack>
        )
      })}
    </Box>
  )
}
