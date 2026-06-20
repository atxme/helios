import { Clock, Wifi } from 'lucide-react'
import { NetworkStats } from '../components/NetworkStats'
import type { Status, TelemetrySample } from '../types'

interface Props {
  samples: TelemetrySample[]
  status: Status | null
}

export function TelemetryView({ samples, status }: Props) {
  return (
    <div className="space-y-4 max-w-4xl">

      <div>
        <h1 className="text-sm font-semibold text-slate-900 dark:text-slate-200 tracking-wide">Télémétrie réseau</h1>
        <p className="text-xs text-slate-500 mt-0.5">Compteurs en temps réel depuis <span className="font-mono">/proc/net/dev</span></p>
      </div>

      <NetworkStats samples={samples} sparklineHeight={64} />

      {/* Interface surveillée */}
      <div className="panel hud p-5 space-y-3">
        <h2 className="hud-title">Interface surveillée</h2>
        <div className="flex items-center gap-3">
          <Wifi className="h-4 w-4 text-slate-400 dark:text-slate-600 shrink-0" strokeWidth={1.5} />
          <span className="font-mono text-sm text-slate-700 dark:text-slate-300">{status?.wan_iface ?? '—'}</span>
          <div className="flex items-center gap-1.5 ml-auto">
            <Clock className="h-3 w-3 text-slate-300 dark:text-slate-700" strokeWidth={1.5} />
            <span className="text-[10px] text-slate-400 dark:text-slate-600 font-mono">Δ 1 s</span>
          </div>
        </div>
      </div>

      {/* Placeholder CPU / Mémoire */}
      <div className="rounded-xl border border-slate-200/50 dark:border-slate-800/50 border-dashed p-5">
        <h2 className="text-[10px] font-medium uppercase tracking-[0.15em] text-slate-300 dark:text-slate-700 mb-3">
          CPU · Mémoire · Température
        </h2>
        <p className="text-xs text-slate-400 dark:text-slate-700 italic">
          Disponible sur cible — nécessite la lecture de <span className="font-mono not-italic">/proc/stat</span> et <span className="font-mono not-italic">/sys/class/thermal</span>
        </p>
      </div>
    </div>
  )
}
