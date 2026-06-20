import type { HeliosEvent } from '../types'
import type { WsStatus } from '../hooks/useHelios'

type TimestampedEvent = HeliosEvent & { ts: string }

interface Props {
  events: TimestampedEvent[]
  wsStatus: WsStatus
}

const WS_DOT: Record<WsStatus, string> = {
  connected:    'bg-emerald-400',
  connecting:   'bg-amber-400 animate-pulse',
  disconnected: 'bg-red-500',
}

const WS_LABEL: Record<WsStatus, string> = {
  connected:    'Temps réel',
  connecting:   'Connexion…',
  disconnected: 'Déconnecté',
}

export function EventFeed({ events, wsStatus }: Props) {
  return (
    <div className="rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-slate-300 text-sm font-medium uppercase tracking-wider">Événements</h2>
        <span className="flex items-center gap-1.5 text-xs text-slate-500">
          <span className={`h-2 w-2 rounded-full ${WS_DOT[wsStatus]}`} />
          {WS_LABEL[wsStatus]}
        </span>
      </div>

      {events.length === 0 ? (
        <p className="text-slate-600 text-sm">En attente d'événements…</p>
      ) : (
        <ul className="space-y-1.5 max-h-64 overflow-y-auto pr-1">
          {events.map((ev, i) => (
            <li key={i} className="flex gap-3 text-xs font-mono">
              <span className="text-slate-600 shrink-0 w-20">{ev.ts}</span>
              {ev.type === 'state_changed' ? (
                <span>
                  <span className="text-slate-500">état →</span>{' '}
                  <span className="text-slate-200">{ev.state}</span>
                </span>
              ) : (
                <span>
                  <span className={`${ev.level === 'error' ? 'text-red-400' : 'text-slate-500'}`}>
                    [{ev.level}]
                  </span>{' '}
                  <span className="text-slate-300">{ev.message}</span>
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
