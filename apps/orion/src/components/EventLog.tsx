import { useCallback, useEffect, useState } from 'react'
import Box from '@mui/material/Box'
import Divider from '@mui/material/Divider'
import IconButton from '@mui/material/IconButton'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { Check, ClipboardCopy, Download } from 'lucide-react'
import { exportLogs } from '../api'
import { copyText } from '../clipboard'
import { EMERALD, GUTTER, PINE } from '../theme'
import type { LogLine } from '../types'

/**
 * Event log — a full-fledged view.
 *
 * Three ways to get text out of it, because they don't serve the same
 * purpose: **selection** to lift a line, **copy** to paste the whole thing
 * into a report, **export** to attach a file. None replaces the other two.
 *
 * Accepted limitation: the view doesn't scroll and therefore only shows the
 * most recent entries that fit. This is the one place where "show
 * everything" runs into reality — a log has no end. The counter says how
 * many exist, copy and export take all of them.
 */

/** The level is carried by a rail as much as by the text color. */
const LEVEL: Record<string, { text: string; rail: string }> = {
  error: { text: '#9B2C2C', rail: '#EF4444' },
  warn: { text: '#A16207', rail: '#F5B301' },
  info: { text: '#5A6B65', rail: 'transparent' },
}

/** Renders the log as plain text, one line per entry, oldest to most recent. */
function toPlainText(logs: LogLine[]): string {
  return [...logs]
    .reverse()
    .map((line) => `${line.ts}  ${line.level.toUpperCase().padEnd(5)}  ${line.message}`)
    .join('\n')
}

/** Readable file label, in local time. Rust sanitizes it before use. */
function exportStem(): string {
  const d = new Date()
  const pad = (n: number) => String(n).padStart(2, '0')
  return `orion-journal-${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(
    d.getHours(),
  )}${pad(d.getMinutes())}${pad(d.getSeconds())}`
}

export function EventLog({ logs }: { logs: LogLine[] }) {
  const [notice, setNotice] = useState<string | null>(null)

  useEffect(() => {
    if (notice === null) return
    const id = setTimeout(() => setNotice(null), 3000)
    return () => clearTimeout(id)
  }, [notice])

  const onCopy = useCallback(async () => {
    await copyText(toPlainText(logs))
    setNotice('Journal copié')
  }, [logs])

  const onExport = useCallback(async () => {
    try {
      const path = await exportLogs(exportStem(), toPlainText(logs))
      setNotice(`Écrit dans ${path}`)
    } catch (cause) {
      setNotice(`Export impossible : ${String(cause)}`)
    }
  }, [logs])

  const empty = logs.length === 0

  return (
    <Box sx={{ display: 'flex', minHeight: 0, height: '100%', flexDirection: 'column' }}>
      <Box sx={{ display: 'flex', flexShrink: 0, alignItems: 'center', gap: 0.5, pl: GUTTER, pr: 0.75, py: 1 }}>
        <Typography variant="overline" color="text.disabled">
          Journal
        </Typography>
        <Typography
          color="text.disabled"
          sx={{ ml: 1, fontFamily: 'monospace', fontSize: 10, fontVariantNumeric: 'tabular-nums' }}
        >
          {logs.length}
        </Typography>

        <Tooltip title="Copier tout le journal">
          <span style={{ marginLeft: 'auto' }}>
            <IconButton size="small" onClick={onCopy} disabled={empty} aria-label="Copier tout le journal">
              <ClipboardCopy size={15} aria-hidden />
            </IconButton>
          </span>
        </Tooltip>
        <Tooltip title="Exporter dans un fichier">
          <span>
            <IconButton size="small" onClick={onExport} disabled={empty} aria-label="Exporter le journal dans un fichier">
              <Download size={15} aria-hidden />
            </IconButton>
          </span>
        </Tooltip>
      </Box>

      {notice && (
        <Box
          role="status"
          sx={{
            display: 'flex',
            flexShrink: 0,
            alignItems: 'flex-start',
            gap: 0.75,
            mx: GUTTER,
            mb: 0.5,
            px: 1,
            py: 0.6,
            borderRadius: 1,
            bgcolor: `${EMERALD}14`,
          }}
        >
          <Check size={13} aria-hidden style={{ color: PINE, flexShrink: 0, marginTop: 2 }} />
          <Typography sx={{ minWidth: 0, fontSize: 10.5, lineHeight: 1.45, overflowWrap: 'anywhere' }}>
            {notice}
          </Typography>
        </Box>
      )}

      <Divider />

      {empty ? (
        <Typography color="text.disabled" sx={{ px: GUTTER, py: 1.5, fontSize: 11.5 }}>
          Aucun événement pour l’instant.
        </Typography>
      ) : (
        <Box
          component="ol"
          role="log"
          aria-live="polite"
          aria-relevant="additions"
          sx={{
            m: 0,
            minHeight: 0,
            flex: 1,
            // No scrollbar or wheel: shows the most recent entries that fit.
            overflow: 'hidden',
            py: 0.5,
            pl: 0,
            fontFamily: 'monospace',
            listStyle: 'none',
            // Text must remain selectable with the mouse.
            userSelect: 'text',
            cursor: 'text',
          }}
        >
          {logs.map((line, index) => {
            const level = LEVEL[line.level] ?? LEVEL.info
            return (
              <Box
                component="li"
                key={`${line.ts}-${index}`}
                sx={{ display: 'flex', alignItems: 'flex-start', gap: 0.9, px: GUTTER, py: 0.22 }}
              >
                <Box
                  aria-hidden
                  sx={{ mt: 0.4, width: 2, height: 11, flexShrink: 0, borderRadius: 1, bgcolor: level.rail }}
                />
                <Typography
                  component="time"
                  color="text.disabled"
                  sx={{ flexShrink: 0, fontFamily: 'inherit', fontSize: 10.5, fontVariantNumeric: 'tabular-nums' }}
                >
                  {line.ts}
                </Typography>
                <Typography
                  sx={{ minWidth: 0, color: level.text, fontFamily: 'inherit', fontSize: 10.5, overflowWrap: 'anywhere' }}
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
