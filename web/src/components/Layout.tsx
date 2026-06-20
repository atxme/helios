import { Activity, LayoutDashboard, Settings2, Shield, ShieldHalf } from 'lucide-react'
import type { ReactNode } from 'react'
import type { Status } from '../types'
import type { WsStatus } from '../hooks/useHelios'
import { AlertCircle } from 'lucide-react'

export type NavId = 'dashboard' | 'telemetry' | 'firewall' | 'settings'

const NAV_ITEMS: { id: NavId; icon: React.ElementType; label: string }[] = [
  { id: 'dashboard', icon: LayoutDashboard, label: 'Dashboard'   },
  { id: 'telemetry', icon: Activity,        label: 'Télémétrie'  },
  { id: 'firewall',  icon: Shield,          label: 'Pare-feu'    },
  { id: 'settings',  icon: Settings2,       label: 'Paramètres'  },
]

const WS_LABEL: Record<WsStatus, { dot: string; label: string }> = {
  connected:    { dot: 'bg-emerald-400',             label: 'Temps réel' },
  connecting:   { dot: 'bg-amber-400 animate-pulse', label: 'Connexion…' },
  disconnected: { dot: 'bg-red-500',                 label: 'Déconnecté' },
}

interface Props {
  children: ReactNode
  nav: NavId
  onNav: (id: NavId) => void
  status: Status | null
  error: string | null
  wsStatus: WsStatus
}

export function Layout({ children, nav, onNav, status, error, wsStatus }: Props) {
  const ws = WS_LABEL[wsStatus]

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 overflow-hidden">

      {/* ── Sidebar ── */}
      <aside className="w-14 lg:w-56 shrink-0 flex flex-col border-r border-slate-800 bg-slate-950">

        {/* Logo */}
        <div className="h-14 flex items-center gap-3 px-3 lg:px-4 border-b border-slate-800 shrink-0">
          <div className="h-7 w-7 shrink-0 rounded border border-emerald-500/30 bg-emerald-500/8 flex items-center justify-center">
            <ShieldHalf className="h-4 w-4 text-emerald-400" strokeWidth={1.5} />
          </div>
          <div className="hidden lg:block min-w-0">
            <div className="font-bold tracking-[0.18em] text-xs text-slate-100">HELIOS</div>
            <div className="text-[10px] text-slate-600 tracking-wide">IPsec Gateway</div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 py-3 flex flex-col gap-0.5 px-1.5 lg:px-2">
          {NAV_ITEMS.map(({ id, icon: Icon, label }) => {
            const active = nav === id
            return (
              <button
                key={id}
                onClick={() => onNav(id)}
                className={`
                  group flex items-center gap-3 w-full px-2 py-2.5 rounded-lg text-left
                  transition-all duration-150 relative
                  ${active
                    ? 'bg-slate-800 text-slate-100'
                    : 'text-slate-500 hover:bg-slate-800/50 hover:text-slate-300'
                  }
                `}
              >
                {active && (
                  <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 bg-emerald-500 rounded-r" />
                )}
                <Icon className={`h-4 w-4 shrink-0 ${active ? 'text-emerald-400' : 'text-slate-600 group-hover:text-slate-400'}`} strokeWidth={1.5} />
                <span className="hidden lg:block text-xs font-medium tracking-wide">{label}</span>
              </button>
            )
          })}
        </nav>

        {/* Pied de sidebar */}
        <div className="border-t border-slate-800 px-3 lg:px-4 py-3 space-y-2 shrink-0">
          {/* WS status */}
          <div className="flex items-center gap-2 justify-center lg:justify-start">
            <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${ws.dot}`} />
            <span className="hidden lg:block text-[10px] text-slate-600 font-mono">{ws.label}</span>
          </div>
          {/* Badges */}
          {status?.dry_run && (
            <div className="hidden lg:flex">
              <span className="text-[10px] px-2 py-0.5 rounded border border-violet-500/30 bg-violet-500/8 text-violet-400 font-mono tracking-wider uppercase">
                Simulation
              </span>
            </div>
          )}
          {status && (
            <div className="hidden lg:block text-[10px] text-slate-700 font-mono">v{status.version}</div>
          )}
        </div>
      </aside>

      {/* ── Zone principale ── */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">

        {/* Bannière erreur daemon */}
        {error && (
          <div className="shrink-0 border-b border-red-500/20 bg-red-500/5">
            <div className="px-6 py-2.5 flex items-center gap-2.5">
              <AlertCircle className="h-3.5 w-3.5 text-red-400 shrink-0" strokeWidth={1.5} />
              <span className="text-xs text-red-400">{error}</span>
            </div>
          </div>
        )}

        {/* Contenu vue active */}
        <main className="flex-1 overflow-y-auto px-6 py-5">
          {children}
        </main>
      </div>
    </div>
  )
}
