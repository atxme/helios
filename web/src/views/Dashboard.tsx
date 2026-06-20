import { Clock, Network, RefreshCw, Shield, ShieldAlert, ShieldOff, Wifi } from 'lucide-react'
import { useEffect, useState } from 'react'
import { ConnectionDetails } from '../components/ConnectionDetails'
import { EventTerminal } from '../components/EventTerminal'
import { TunnelControls } from '../components/TunnelControls'
import type { WsStatus } from '../hooks/useHelios'
import type { DisplayEvent, ProfileSummary, Status, TunnelState } from '../types'

interface Props {
  status: Status | null
  currentState: TunnelState
  error: string | null
  events: (DisplayEvent & { ts: string })[]
  wsStatus: WsStatus
  tunnelUpSince: Date | null
  selectedProfile: string | null
  onProfileChange: (id: string) => void
  connect: () => Promise<void>
  disconnect: () => Promise<void>
}

function useUptime(since: Date | null): string {
  const [, setTick] = useState(0)
  useEffect(() => {
    if (!since) return
    const id = setInterval(() => setTick(t => t + 1), 1000)
    return () => clearInterval(id)
  }, [since])
  if (!since) return '—'
  const s = Math.floor((Date.now() - since.getTime()) / 1000)
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  const sec = s % 60
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(sec).padStart(2, '0')}`
}

const STATE_UI: Record<TunnelState, {
  Icon: React.ElementType; color: string; bg: string; border: string; dot: string; label: string
}> = {
  up:         { Icon: Shield,      color: 'text-emerald-600 dark:text-emerald-400', bg: 'bg-emerald-500/8',  border: 'border-emerald-500/25', dot: 'bg-emerald-500 animate-pulse', label: 'TUNNEL SÉCURISÉ'      },
  rekeying:   { Icon: RefreshCw,   color: 'text-amber-600 dark:text-amber-400',    bg: 'bg-amber-500/8',    border: 'border-amber-500/25',   dot: 'bg-amber-500 animate-pulse',   label: 'RENOUVELLEMENT IKE'   },
  connecting: { Icon: Shield,      color: 'text-sky-600 dark:text-sky-400',        bg: 'bg-sky-500/8',      border: 'border-sky-500/25',     dot: 'bg-sky-500 animate-pulse',     label: 'ÉTABLISSEMENT'        },
  down:       { Icon: ShieldOff,   color: 'text-slate-500',                        bg: 'bg-slate-100/60 dark:bg-slate-900/30',  border: 'border-slate-300 dark:border-slate-800', dot: 'bg-slate-400 dark:bg-slate-600', label: 'HORS LIGNE' },
  failed:     { Icon: ShieldAlert, color: 'text-red-500 dark:text-red-400',        bg: 'bg-red-500/8',      border: 'border-red-500/25',     dot: 'bg-red-500',                   label: 'ÉCHEC DE CONNEXION'   },
}

function StatusStrip({ state, status }: { state: TunnelState; status: Status | null }) {
  const s   = STATE_UI[state]
  const { Icon } = s
  const conn = status?.connections[0]

  return (
    <div className={`card flex items-center gap-3 px-4 py-3 ${s.bg} border ${s.border}`}>
      <Icon className={`h-4 w-4 shrink-0 ${s.color} ${state === 'rekeying' ? 'animate-spin' : state === 'connecting' ? 'animate-pulse' : ''}`} strokeWidth={1.5} />
      <span className={`h-2 w-2 rounded-full shrink-0 ${s.dot}`} />
      <span className={`font-bold tracking-[0.12em] text-xs ${s.color}`}>{s.label}</span>
      {conn && (
        <div className="ml-auto hidden md:flex items-center gap-2">
          <span className="text-slate-400 dark:text-slate-600 text-[10px] uppercase tracking-widest">IKE</span>
          <div className="flex gap-1">
            {conn.ike_proposal.split('-').map((part, i) => (
              <span key={i} className={`text-[10px] font-mono px-1 py-0.5 rounded border ${
                part.includes('mlkem') ? 'border-violet-500/40 text-violet-600 dark:text-violet-400 bg-violet-500/5'
                : 'border-slate-200 dark:border-slate-700 text-slate-500 dark:text-slate-500'
              }`}>{part}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function StatPill({ icon: Icon, label, value, highlight = false }: {
  icon: React.ElementType; label: string; value: string; highlight?: boolean
}) {
  return (
    <div className="card flex items-center gap-2.5 px-3 py-2 min-w-0">
      <Icon className="h-3 w-3 text-slate-400 dark:text-slate-600 shrink-0" strokeWidth={1.5} />
      <div className="min-w-0">
        <div className="text-[9px] uppercase tracking-widest text-slate-400 dark:text-slate-600 leading-none mb-0.5">{label}</div>
        <div className={`text-[11px] font-mono truncate ${highlight ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-700 dark:text-slate-300'}`}>
          {value}
        </div>
      </div>
    </div>
  )
}

export function DashboardView({
  status, currentState, error, events, wsStatus,
  tunnelUpSince, selectedProfile, onProfileChange, connect, disconnect,
}: Props) {
  const uptime   = useUptime(tunnelUpSince)
  const profiles: ProfileSummary[] = status?.profiles ?? []
  const isUp     = currentState === 'up'

  const activeProfileName = profiles.find(p => p.id === (selectedProfile ?? status?.active_profile ?? ''))?.name ?? '—'

  return (
    <div className="space-y-3 max-w-4xl">
      {/* Bandeau d'état compact */}
      <StatusStrip state={currentState} status={status} />

      {/* Stats bar */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
        <StatPill icon={Shield}  label="Profil"      value={activeProfileName}                          highlight={isUp} />
        <StatPill icon={Clock}   label="Uptime"      value={uptime}                                     highlight={isUp} />
        <StatPill icon={Wifi}    label="WAN"         value={status?.wan_iface ?? '—'} />
        <StatPill icon={Network} label="Connexions"  value={`${status?.connections.length ?? 0} IKEv2`} />
      </div>

      {/* Grille contrôles + réseau */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        <TunnelControls
          state={currentState}
          daemonError={!!error}
          status_profiles={profiles}
          selectedProfile={selectedProfile}
          onProfileChange={onProfileChange}
          onConnect={connect}
          onDisconnect={disconnect}
        />
        <ConnectionDetails status={status} />
      </div>

      <EventTerminal events={events} wsStatus={wsStatus} />
    </div>
  )
}
