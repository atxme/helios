import Box from '@mui/material/Box'
import Divider from '@mui/material/Divider'
import Typography from '@mui/material/Typography'
import type { LogLine } from '../types'

/** Le niveau est porté par un liseré autant que par la couleur du texte. */
const LEVEL: Record<string, { text: string; rail: string }> = {
  error: { text: '#fca5a5', rail: '#ef4444' },
  warn: { text: '#fcd34d', rail: '#f59e0b' },
  info: { text: '#cbd5e1', rail: 'transparent' },
}

export function EventLog({ logs }: { logs: LogLine[] }) {
  return (
    <Box sx={{ display: 'flex', maxHeight: 192, flexDirection: 'column' }}>
      <Box sx={{ display: 'flex', flexShrink: 0, alignItems: 'center', px: 2, py: 0.75 }}>
        <Typography variant="overline" color="text.disabled">
          Journal
        </Typography>
        <Typography
          color="text.disabled"
          sx={{ ml: 'auto', fontFamily: 'monospace', fontSize: 10, fontVariantNumeric: 'tabular-nums' }}
        >
          {logs.length} {logs.length > 1 ? 'entrées' : 'entrée'}
        </Typography>
      </Box>
      <Divider />

      {logs.length === 0 ? (
        <Typography color="text.disabled" sx={{ px: 2, py: 1.5, fontSize: 12 }}>
          Aucun événement pour l’instant.
        </Typography>
      ) : (
        <Box
          component="ol"
          role="log"
          aria-live="polite"
          aria-relevant="additions"
          sx={{ m: 0, overflowY: 'auto', py: 0.5, pl: 0, fontFamily: 'monospace', listStyle: 'none' }}
        >
          {logs.map((line, index) => {
            const level = LEVEL[line.level] ?? LEVEL.info
            return (
              <Box
                component="li"
                key={`${line.ts}-${index}`}
                sx={{ display: 'flex', alignItems: 'flex-start', gap: 1, px: 2, py: 0.2 }}
              >
                <Box
                  aria-hidden
                  sx={{ mt: 0.35, width: 2, height: 12, flexShrink: 0, borderRadius: 1, bgcolor: level.rail }}
                />
                <Typography
                  component="time"
                  color="text.disabled"
                  sx={{ flexShrink: 0, fontFamily: 'inherit', fontSize: 11, fontVariantNumeric: 'tabular-nums' }}
                >
                  {line.ts}
                </Typography>
                <Typography
                  sx={{ minWidth: 0, color: level.text, fontFamily: 'inherit', fontSize: 11, overflowWrap: 'anywhere' }}
                >
                  {line.message}
                </Typography>
              </Box>
            )
          })}
        </Box>
      )}
    </Box>
  )
}
