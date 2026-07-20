import { Activity, AlertCircle, LayoutDashboard, RadioTower, RefreshCw, Settings2, Shield, ShieldCheck } from 'lucide-react'
import type { ReactNode } from 'react'
import type { Status } from '../types'
import type { WsStatus } from '../hooks/useHelios'
import { useTheme } from '../hooks/useTheme'
import { Background } from './Background'
import { HeliosMark } from './HeliosMark'

export type NavId = 'dashboard' | 'telemetry' | 'wireguard' | 'firewall' | 'trust' | 'update' | 'settings'

const NAV_ITEMS: { id: NavId; icon: React.ElementType; label: string }[] = [
  { id: 'dashboard', icon: LayoutDashboard, label: 'Dashboard'   },
  { id: 'telemetry', icon: Activity,        label: 'Télémétrie'  },
  { id: 'wireguard', icon: RadioTower,      label: 'WireGuard'   },
  { id: 'firewall',  icon: Shield,          label: 'Pare-feu'    },
  { id: 'trust',     icon: ShieldCheck,     label: 'Confiance'   },
  { id: 'update',    icon: RefreshCw,       label: 'Mise à jour' },
  { id: 'settings',  icon: Settings2,       label: 'Paramètres'  },
]

const WS_LABEL: Record<WsStatus, { dot: string; label: string }> = {
  connected:    { dot: 'bg-cyan-400 shadow-neon-cyan',        label: 'WebSocket actif' },
  connecting:   { dot: 'bg-amber-300 animate-pulse',          label: 'Connexion WS…'   },
  disconnected: { dot: 'bg-red-500',                          label: 'WS déconnecté'   },
}

interface Props {
  children: ReactNode
  nav: NavId
  onNav: (id: NavId) => void
  status: Status | null
  error: string | null
  wsStatus: WsStatus
}

// Sélecteur de thème flottant — segment LIGHT / DARK à la maquette.
function ThemeSwitch({ dark, toggle }: { dark: boolean; toggle: () => void }) {
  return (
    <div className="fixed bottom-4 left-1/2 -translate-x-1/2 z-30">
      <div className="card hud flex items-center p-1 text-[10px] font-mono uppercase tracking-[0.18em]">
        <button
          onClick={() => { if (dark) toggle() }}
          className={`px-4 py-1.5 rounded-md transition-all ${
            !dark ? 'bg-amber-400/90 text-amber-950 shadow-neon-amber' : 'text-slate-400 hover:text-amber-300'
          }`}
        >
          Light
        </button>
        <button
          onClick={() => { if (!dark) toggle() }}
          className={`px-4 py-1.5 rounded-md transition-all ${
            dark ? 'bg-cyan-400/90 text-cyan-950 shadow-neon-cyan' : 'text-slate-500 hover:text-cyan-600'
          }`}
        >
          Dark
        </button>
      </div>
    </div>
  )
}

export function Layout({ children, nav, onNav, status, error, wsStatus }: Props) {
  const ws = WS_LABEL[wsStatus]
  const { dark, toggle } = useTheme()

  return (
    <div className="relative flex h-screen overflow-hidden">
      {/* Scène 3D — soleil ambre + réseau cyber (derrière tout) */}
      <Background dark={dark} />

      {/* ── Sidebar — verre cyber, identité soleil Helios ── */}
      <aside className="panel relative z-20 m-2 w-14 lg:w-56 shrink-0 flex flex-col rounded-xl">
        {/* Logo */}
        <div className="h-14 flex items-center gap-3 px-3 lg:px-4 border-b border-[var(--panel-border)] shrink-0">
          <HeliosMark
            className="h-7 w-7 shrink-0 text-amber-500 dark:text-amber-400 drop-shadow-[0_0_6px_rgba(251,191,36,0.35)]"
            title="Helios"
          />
          <div className="hidden lg:block min-w-0 leading-none">
            <div className="font-bold tracking-[0.26em] text-xs text-amber-600 dark:text-amber-300">HELIOS</div>
            <div className="mt-1 text-[9px] uppercase tracking-[0.14em] text-cyan-700/80 dark:text-cyan-500/70 font-mono">WireGuard · PQ Gateway</div>
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
                className={`group relative flex items-center gap-3 w-full px-2 py-2.5 rounded-lg text-left transition-all duration-150 ${
                  active
                    ? 'bg-cyan-400/10 text-cyan-700 dark:text-cyan-300'
                    : 'text-slate-600 dark:text-slate-400 hover:bg-cyan-400/5 hover:text-cyan-700 dark:hover:text-cyan-400'
                }`}
              >
                {active && (
                  <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 bg-cyan-400 rounded-r shadow-neon-cyan" />
                )}
                <Icon
                  className={`h-4 w-4 shrink-0 ${active ? 'text-cyan-500 dark:text-cyan-400' : 'text-slate-500 group-hover:text-cyan-500 dark:group-hover:text-cyan-400'}`}
                  strokeWidth={1.5}
                />
                <span className="hidden lg:block text-xs font-medium tracking-wide">{label}</span>
              </button>
            )
          })}
        </nav>

        {/* Pied de sidebar */}
        <div className="border-t border-[var(--panel-border)] px-3 lg:px-4 py-3 space-y-2 shrink-0">
          <div className="flex items-center gap-2 justify-center lg:justify-start">
            <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${ws.dot}`} />
            <span className="hidden lg:block text-[10px] text-slate-500 font-mono">{ws.label}</span>
          </div>
          {status?.dry_run && (
            <div className="hidden lg:flex">
              <span className="text-[10px] px-2 py-0.5 rounded border border-amber-500/40 bg-amber-500/10 text-amber-400 font-mono tracking-wider uppercase">
                Simulation
              </span>
            </div>
          )}
          {status && (
            <div className="hidden lg:block text-[10px] text-slate-500/70 font-mono">v{status.version}</div>
          )}
        </div>
      </aside>

      {/* ── Zone principale ── */}
      <div className="relative z-10 flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Bannière erreur daemon */}
        {error && (
          <div className="shrink-0 m-2 mb-0 rounded-lg border border-red-500/30 bg-red-500/10 backdrop-blur-sm">
            <div className="px-5 py-2.5 flex items-center gap-2.5">
              <AlertCircle className="h-3.5 w-3.5 text-red-400 shrink-0" strokeWidth={1.5} />
              <span className="text-xs text-red-400">{error}</span>
            </div>
          </div>
        )}

        {/* Contenu vue active */}
        <main className="flex-1 overflow-y-auto px-6 py-5 pb-16">
          {children}
        </main>
      </div>

      <ThemeSwitch dark={dark} toggle={toggle} />
    </div>
  )
}
