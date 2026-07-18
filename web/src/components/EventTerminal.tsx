import { Terminal } from 'lucide-react'
import type { WsStatus } from '../hooks/useHelios'
import type { DisplayEvent } from '../types'

type TimestampedEvent = DisplayEvent & { ts: string }

const WS_INDICATOR: Record<WsStatus, { dot: string; label: string }> = {
  connected: { dot: 'bg-emerald-400', label: 'TEMPS RÉEL' },
  connecting: { dot: 'bg-amber-400 animate-pulse', label: 'CONNEXION…' },
  disconnected: { dot: 'bg-red-500', label: 'DÉCONNECTÉ' },
}

function eventText(event: TimestampedEvent): { kind: string; text: string; style: string } {
  switch (event.type) {
    case 'state_changed':
      return {
        kind: 'ÉTAT',
        text: event.state.toUpperCase(),
        style: event.state === 'up' ? 'text-emerald-600 dark:text-emerald-400'
          : event.state === 'failed' ? 'text-red-500 dark:text-red-400'
          : event.state === 'captive_portal' ? 'text-amber-600 dark:text-amber-400'
          : 'text-sky-600 dark:text-sky-400',
      }
    case 'log':
      return {
        kind: event.level.slice(0, 5).toUpperCase(),
        text: event.message,
        style: event.level === 'error' ? 'text-red-500 dark:text-red-400'
          : event.level === 'warn' ? 'text-amber-600 dark:text-amber-400'
          : 'text-slate-600 dark:text-slate-400',
      }
    case 'captive_portal_detected':
      return { kind: 'PORTAIL', text: `Passerelle détectée : ${event.gateway}`, style: 'text-amber-600 dark:text-amber-400' }
    case 'mtu_discovered':
      return { kind: 'PMTUD', text: `MTU ${event.mtu}, MSS ${event.mss}`, style: 'text-cyan-600 dark:text-cyan-400' }
    case 'split_tunnel_changed':
      return { kind: 'ROUTES', text: event.cidrs.join(', ') || 'split-tunnel désactivé', style: 'text-cyan-600 dark:text-cyan-400' }
  }
}

function EventLine({ event }: { event: TimestampedEvent }) {
  const display = eventText(event)
  return (
    <li className="flex gap-3 items-baseline py-0.5 hover:bg-slate-100 dark:hover:bg-slate-800/30 px-2 -mx-2 rounded">
      <span className="text-slate-500 shrink-0 w-[4.5rem] font-mono text-[11px]">{event.ts}</span>
      <span className="text-slate-500 shrink-0 w-14 font-mono text-[11px] uppercase">{display.kind}</span>
      <span className={`font-mono text-[11px] break-all ${display.style}`}>{display.text}</span>
    </li>
  )
}

export function EventTerminal({ events, wsStatus }: { events: TimestampedEvent[]; wsStatus: WsStatus }) {
  const indicator = WS_INDICATOR[wsStatus]
  return (
    <div className="panel hud overflow-hidden">
      <div className="flex items-center justify-between px-5 py-3 border-b border-[var(--panel-border)] bg-black/10 dark:bg-black/20">
        <div className="flex items-center gap-2">
          <Terminal className="h-3.5 w-3.5 text-cyan-500/70" strokeWidth={1.5} />
          <span className="hud-title">Journal d’événements</span>
          {events.length > 0 && <span className="text-[10px] text-slate-500 font-mono">({events.length})</span>}
        </div>
        <div className="flex items-center gap-1.5">
          <span className={`h-1.5 w-1.5 rounded-full ${indicator.dot}`} />
          <span className="text-[10px] font-mono text-slate-500">{indicator.label}</span>
        </div>
      </div>
      <div className="p-4">
        {events.length === 0 ? (
          <p className="text-slate-500 text-[11px] font-mono px-2">&gt; En attente d’événements…</p>
        ) : (
          <ul className="space-y-0 max-h-56 overflow-y-auto">
            {events.map((event, index) => <EventLine key={index} event={event} />)}
          </ul>
        )}
      </div>
    </div>
  )
}
