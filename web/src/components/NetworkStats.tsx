import { Activity } from 'lucide-react'
import type { TelemetrySample } from '../types'

interface Props {
  samples: TelemetrySample[]
  sparklineHeight?: number
}

function formatBps(bps: number): string {
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} Mbps`
  if (bps >= 1_000)     return `${(bps / 1_000).toFixed(0)} Kbps`
  return `${bps} bps`
}

function formatPps(pps: number): string {
  if (pps >= 1_000) return `${(pps / 1_000).toFixed(1)}k pps`
  return `${pps} pps`
}

interface SparklineProps {
  values: number[]
  color: string
  height?: number
}

function Sparkline({ values, color, height = 40 }: SparklineProps) {
  const W = 240
  const H = height
  const PAD = 2

  if (values.length < 2) {
    return <svg width={W} height={H} className="w-full" />
  }

  const max = Math.max(...values, 1)
  const step = (W - PAD * 2) / (values.length - 1)

  const points = values
    .map((v, i) => `${PAD + i * step},${H - PAD - ((v / max) * (H - PAD * 2))}`)
    .join(' ')

  const areaPoints = [
    `${PAD},${H - PAD}`,
    ...values.map((v, i) => `${PAD + i * step},${H - PAD - ((v / max) * (H - PAD * 2))}`),
    `${PAD + (values.length - 1) * step},${H - PAD}`,
  ].join(' ')

  return (
    <svg width={W} height={H} className="w-full" preserveAspectRatio="none">
      <polygon points={areaPoints} fill={color} fillOpacity="0.08" />
      <polyline
        points={points}
        fill="none"
        stroke={color}
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {values.length > 0 && (
        <circle
          cx={PAD + (values.length - 1) * step}
          cy={H - PAD - ((values[values.length - 1] / max) * (H - PAD * 2))}
          r="2.5"
          fill={color}
        />
      )}
    </svg>
  )
}

export function NetworkStats({ samples, sparklineHeight = 40 }: Props) {
  const latest = samples[samples.length - 1]
  const rxValues = samples.map(s => s.rx_bps)
  const txValues = samples.map(s => s.tx_bps)

  return (
    <div className="panel hud p-5 flex flex-col gap-4">
      <div className="flex items-center gap-2">
        <Activity className="h-3.5 w-3.5 text-cyan-500/70" strokeWidth={1.5} />
        <h2 className="hud-title">Télémétrie réseau</h2>
        {!latest && (
          <span className="ml-auto text-[10px] text-slate-300 dark:text-slate-700 font-mono">en attente…</span>
        )}
      </div>

      {/* Rx */}
      <div className="space-y-1">
        <div className="flex items-baseline justify-between">
          <span className="text-[10px] uppercase tracking-wider text-slate-400 dark:text-slate-600">Rx entrant</span>
          <span className="font-mono text-xs text-cyan-600 dark:text-cyan-400">
            {latest ? `${formatBps(latest.rx_bps)} · ${formatPps(latest.rx_pps)}` : '—'}
          </span>
        </div>
        <Sparkline values={rxValues} color="#22d3ee" height={sparklineHeight} />
      </div>

      {/* Tx */}
      <div className="space-y-1">
        <div className="flex items-baseline justify-between">
          <span className="text-[10px] uppercase tracking-wider text-slate-400 dark:text-slate-600">Tx sortant</span>
          <span className="font-mono text-xs text-fuchsia-600 dark:text-fuchsia-400">
            {latest ? `${formatBps(latest.tx_bps)} · ${formatPps(latest.tx_pps)}` : '—'}
          </span>
        </div>
        <Sparkline values={txValues} color="#e879f9" height={sparklineHeight} />
      </div>
    </div>
  )
}
