import { Terminal } from 'lucide-react'
import type { DisplayEvent } from '../types'
import type { WsStatus } from '../hooks/useHelios'

type TimestampedEvent = DisplayEvent & { ts: string }

interface Props {
  events: TimestampedEvent[]
  wsStatus: WsStatus
}

const WS_INDICATOR: Record<WsStatus, { dot: string; label: string }> = {
  connected:    { dot: 'bg-emerald-400',              label: 'TEMPS RÉEL' },
  connecting:   { dot: 'bg-amber-400 animate-pulse',  label: 'CONNEXION…' },
  disconnected: { dot: 'bg-red-500',                  label: 'DÉCONNECTÉ' },
}

function EventLine({ ev }: { ev: TimestampedEvent }) {
  if (ev.type === 'state_changed') {
    const stateColor: Record<string, string> = {
      up:         'text-emerald-400',
      rekeying:   'text-amber-400',
      connecting: 'text-sky-400',
      down:       'text-slate-500',
      failed:     'text-red-400',
    }
    return (
      <li className="flex gap-3 items-baseline py-0.5 hover:bg-slate-800/30 px-2 -mx-2 rounded transition-colors">
        <span className="text-slate-600 shrink-0 w-[4.5rem] font-mono text-[11px]">{ev.ts}</span>
        <span className="text-slate-600 shrink-0 w-14 font-mono text-[11px] uppercase">STATE</span>
        <span className={`font-mono text-[11px] font-medium ${stateColor[ev.state] ?? 'text-slate-400'}`}>
          {ev.state.toUpperCase()}
        </span>
      </li>
    )
  }

  const levelStyle: Record<string, string> = {
    error: 'text-red-400',
    warn:  'text-amber-400',
    info:  'text-slate-500',
    debug: 'text-slate-700',
  }

  return (
    <li className="flex gap-3 items-baseline py-0.5 hover:bg-slate-800/30 px-2 -mx-2 rounded transition-colors">
      <span className="text-slate-600 shrink-0 w-[4.5rem] font-mono text-[11px]">{ev.ts}</span>
      <span className={`shrink-0 w-14 font-mono text-[11px] uppercase ${levelStyle[ev.level] ?? 'text-slate-500'}`}>
        {ev.level.slice(0, 5)}
      </span>
      <span className="text-slate-400 font-mono text-[11px] break-all">{ev.message}</span>
    </li>
  )
}

export function EventTerminal({ events, wsStatus }: Props) {
  const { dot, label } = WS_INDICATOR[wsStatus]

  return (
    <div className="rounded-xl bg-slate-900/60 border border-slate-800 overflow-hidden">
      {/* Barre titre style terminal */}
      <div className="flex items-center justify-between px-5 py-3 border-b border-slate-800 bg-slate-900/80">
        <div className="flex items-center gap-2">
          <Terminal className="h-3.5 w-3.5 text-slate-600" strokeWidth={1.5} />
          <span className="text-[10px] font-medium uppercase tracking-[0.15em] text-slate-500">
            Journal d'événements
          </span>
          {events.length > 0 && (
            <span className="text-[10px] text-slate-700 font-mono">({events.length})</span>
          )}
        </div>
        <div className="flex items-center gap-1.5">
          <span className={`h-1.5 w-1.5 rounded-full ${dot}`} />
          <span className="text-[10px] font-mono text-slate-600">{label}</span>
        </div>
      </div>

      {/* Corps terminal */}
      <div className="p-4">
        {events.length === 0 ? (
          <p className="text-slate-700 text-[11px] font-mono px-2">
            <span className="text-slate-600">{'>'}</span> En attente d'événements…
          </p>
        ) : (
          <ul className="space-y-0 max-h-56 overflow-y-auto">
            {events.map((ev, i) => (
              <EventLine key={i} ev={ev} />
            ))}
          </ul>
        )}
      </div>
    </div>
  )
}
