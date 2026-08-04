import Box from '@mui/material/Box'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { ArrowDownRight, ArrowUpRight } from 'lucide-react'
import type { TelemetrySample } from '../types'
import { Sparkline } from './Sparkline'

/**
 * Live throughput, in and out.
 *
 * Blue in, violet out. The two hues are deliberately far apart on the wheel:
 * the curves are stacked, read at a glance, and an earlier pairing put indigo
 * next to violet — close enough that at sparkline width you had to read the
 * label to know which direction you were looking at.
 *
 * Neither is a state tone. A green upload curve would read as "protected",
 * which is the one confusion this interface cannot afford.
 */

export function formatBps(bps: number): string {
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} Mbps`
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(0)} Kbps`
  return `${bps} bps`
}

export function formatPps(pps: number): string {
  if (pps >= 1_000) return `${(pps / 1_000).toFixed(1)}k pps`
  return `${pps} pps`
}

function Channel({
  label,
  icon: Icon,
  color,
  bps,
  pps,
  values,
  height,
}: {
  label: string
  icon: typeof ArrowDownRight
  color: string
  bps: number | null
  pps: number | null
  values: number[]
  height: number
}) {
  return (
    <Box sx={{ minWidth: 0 }}>
      <Stack direction="row" spacing={1} sx={{ alignItems: 'baseline', mb: 0.5 }}>
        <Box sx={{ color, display: 'flex', alignSelf: 'center' }}>
          <Icon size={15} strokeWidth={2} />
        </Box>
        <Typography variant="overline" sx={{ color: 'text.secondary' }}>
          {label}
        </Typography>
        <Typography
          sx={{
            ml: 'auto',
            fontFamily: 'monospace',
            fontSize: '0.8125rem',
            fontWeight: 600,
            fontVariantNumeric: 'tabular-nums',
            color: bps === null ? 'text.disabled' : color,
          }}
        >
          {bps === null || pps === null ? '—' : `${formatBps(bps)} · ${formatPps(pps)}`}
        </Typography>
      </Stack>
      <Box sx={{ color }}>
        <Sparkline values={values} height={height} label={`${label} sur la dernière minute`} />
      </Box>
    </Box>
  )
}

export function NetworkStats({
  samples,
  sparklineHeight = 44,
}: {
  samples: TelemetrySample[]
  sparklineHeight?: number
}) {
  const latest = samples[samples.length - 1] ?? null

  return (
    <Stack spacing={2.5}>
      <Channel
        label="Rx entrant"
        icon={ArrowDownRight}
        color="state.connecting.main"
        bps={latest?.rx_bps ?? null}
        pps={latest?.rx_pps ?? null}
        values={samples.map(sample => sample.rx_bps)}
        height={sparklineHeight}
      />
      <Channel
        label="Tx sortant"
        icon={ArrowUpRight}
        color="tertiary.main"
        bps={latest?.tx_bps ?? null}
        pps={latest?.tx_pps ?? null}
        values={samples.map(sample => sample.tx_bps)}
        height={sparklineHeight}
      />
    </Stack>
  )
}
