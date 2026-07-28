import { Clock, Network, RadioTower, Shield, ShieldAlert, ShieldOff, Wifi } from 'lucide-react'
import { useEffect, useState } from 'react'
import { ConnectionDetails } from '../components/ConnectionDetails'
import { EventTerminal } from '../components/EventTerminal'
import { TunnelControls } from '../components/TunnelControls'
import type { WsStatus } from '../hooks/useHelios'
import type { DisplayEvent, Status, TunnelState } from '../types'

interface Props {
  status: Status | null
  currentState: TunnelState
  error: string | null
  events: (DisplayEvent & { ts: string })[]
  wsStatus: WsStatus
  tunnelUpSince: Date | null
  connect: () => Promise<void>
  disconnect: () => Promise<void>
  releaseCaptivePortal: () => Promise<void>
}

function useUptime(since: Date | null): string {
  const [, tick] = useState(0)
  useEffect(() => {
    if (!since) return
    const id = setInterval(() => tick(value => value + 1), 1000)
    return () => clearInterval(id)
  }, [since])
  if (!since) return '—'
  const seconds = Math.max(0, Math.floor((Date.now() - since.getTime()) / 1000))
  const pad = (value: number) => String(value).padStart(2, '0')
  return `${pad(Math.floor(seconds / 3600))}:${pad(Math.floor((seconds / 60) % 60))}:${pad(seconds % 60)}`
}

const STATE_UI: Record<TunnelState, {
  Icon: React.ElementType
  color: string
  bg: string
  border: string
  dot: string
  label: string
  detail: string
}> = {
  up: {
    Icon: Shield,
    color: 'text-emerald-600 dark:text-emerald-400',
    bg: 'bg-emerald-500/8',
    border: 'border-emerald-500/25',
    dot: 'bg-emerald-500 animate-pulse',
    label: 'HANDSHAKE ACTIF',
    detail: 'Au moins un pair WireGuard a handshaké il y a moins de 150 s',
  },
  connecting: {
    Icon: Shield,
    color: 'text-sky-600 dark:text-sky-400',
    bg: 'bg-sky-500/8',
    border: 'border-sky-500/25',
    dot: 'bg-sky-500 animate-pulse',
    label: 'EN ATTENTE DE PAIR',
    detail: 'Interface montée, kill-switch engagé jusqu’au prochain handshake',
  },
  down: {
    Icon: ShieldOff,
    color: 'text-slate-500',
    bg: 'bg-slate-100/60 dark:bg-slate-900/30',
    border: 'border-slate-300 dark:border-slate-800',
    dot: 'bg-slate-400 dark:bg-slate-600',
    label: 'HORS LIGNE',
    detail: 'Interface arrêtée, kill-switch engagé',
  },
  failed: {
    Icon: ShieldAlert,
    color: 'text-red-500 dark:text-red-400',
    bg: 'bg-red-500/8',
    border: 'border-red-500/25',
    dot: 'bg-red-500',
    label: 'ÉCHEC',
    detail: 'Le trafic reste bloqué en mode fail-closed',
  },
  captive_portal: {
    Icon: Wifi,
    color: 'text-amber-600 dark:text-amber-400',
    bg: 'bg-amber-500/8',
    border: 'border-amber-500/25',
    dot: 'bg-amber-500 animate-pulse',
    label: 'PORTAIL CAPTIF',
    detail: 'Accès limité à la passerelle du portail',
  },
}

function StatusStrip({ state, status }: { state: TunnelState; status: Status | null }) {
  const meta = STATE_UI[state]
  const { Icon } = meta
  return (
    <div className={`card flex items-center gap-3 px-4 py-3 ${meta.bg} border ${meta.border}`}>
      <Icon className={`h-4 w-4 shrink-0 ${meta.color} ${state === 'connecting' ? 'animate-pulse' : ''}`} strokeWidth={1.5} />
      <span className={`h-2 w-2 rounded-full shrink-0 ${meta.dot}`} />
      <div>
        <div className={`font-bold tracking-[0.12em] text-xs ${meta.color}`}>{meta.label}</div>
        <div className="text-[10px] text-slate-500 mt-0.5">{meta.detail}</div>
      </div>
      {status?.dry_run && <span className="ml-auto text-[10px] font-mono text-amber-500">SIMULATION</span>}
    </div>
  )
}

function StatPill({ icon: Icon, label, value, highlight = false }: {
  icon: React.ElementType
  label: string
  value: string
  highlight?: boolean
}) {
  return (
    <div className="card flex items-center gap-2.5 px-3 py-2 min-w-0">
      <Icon className="h-3 w-3 text-slate-500 dark:text-slate-400 shrink-0" strokeWidth={1.5} />
      <div className="min-w-0">
        <div className="text-[9px] uppercase tracking-widest text-slate-500 leading-none mb-0.5">{label}</div>
        <div className={`text-[11px] font-mono truncate ${highlight ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-700 dark:text-slate-300'}`}>{value}</div>
      </div>
    </div>
  )
}

export function DashboardView({
  status,
  currentState,
  error,
  events,
  wsStatus,
  tunnelUpSince,
  connect,
  disconnect,
  releaseCaptivePortal,
}: Props) {
  const isUp = currentState === 'up'
  const uptime = useUptime(tunnelUpSince)
  return (
    <div className="space-y-3 max-w-4xl">
      <StatusStrip state={currentState} status={status} />

      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
        <StatPill icon={RadioTower} label="Interface" value={status?.wg_iface || '—'} highlight={isUp} />
        <StatPill icon={Clock} label="Handshake actif" value={uptime} highlight={isUp} />
        <StatPill icon={Wifi} label="Écoute" value={status?.wg_listen_port ? `UDP ${status.wg_listen_port}` : 'fermée'} />
        <StatPill icon={Network} label="Pairs admis" value={String(status?.peers.length ?? 0)} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        <TunnelControls
          state={currentState}
          daemonError={Boolean(error)}
          captiveGateway={status?.captive_portal_gateway ?? null}
          onConnect={connect}
          onDisconnect={disconnect}
          onReleaseCaptivePortal={releaseCaptivePortal}
        />
        <ConnectionDetails status={status} />
      </div>

      <EventTerminal events={events} wsStatus={wsStatus} />
    </div>
  )
}
