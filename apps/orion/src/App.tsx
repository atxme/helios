import { useState } from 'react'
import { Radio, Settings2, Terminal, X } from 'lucide-react'
import { useClient } from './hooks/useClient'
import { ConnectView } from './views/ConnectView'
import { ProfilesView } from './views/ProfilesView'
import { EventLog } from './components/EventLog'
import { OrionMark } from './components/OrionMark'
import { postureMeta } from './components/state'

type Tab = 'connect' | 'profiles'

export default function App() {
  const c = useClient()
  const [tab, setTab] = useState<Tab>('connect')
  const [logOpen, setLogOpen] = useState(false)
  const posture = postureMeta(c.state, c.adapterUp)

  return (
    <div className="flex h-screen flex-col gap-2 p-2">
      {/* ── En-tête : identité + pastille de posture ── */}
      <header className="flex shrink-0 items-center gap-3 px-2 py-1">
        <OrionMark className="h-7 w-7 shrink-0 text-node" title="Orion" />
        <div className="min-w-0 leading-none">
          <div className="text-[12px] font-bold tracking-[0.26em] text-slate-100">ORION</div>
          <div className="mt-1 font-mono text-[9px] uppercase tracking-[0.14em] text-node/70">
            WireGuard · PQ Client
          </div>
        </div>

        {/* Résumé permanent : la posture reste lisible depuis n'importe quel onglet. */}
        <div
          className="ml-auto flex items-center gap-2 rounded-full border px-2.5 py-1"
          style={{ borderColor: `${posture.color}40`, background: `${posture.color}12` }}
          title={posture.detail}
        >
          <span
            className={`h-1.5 w-1.5 rounded-full ${
              posture.posture === 'protected' ? 'motion-safe:animate-pulse' : ''
            }`}
            style={{ background: posture.color }}
          />
          <span className="text-[10px] font-medium" style={{ color: posture.color }}>
            {posture.label}
          </span>
        </div>
      </header>

      {/* ── Onglets ── */}
      <nav className="flex shrink-0 gap-1 px-2">
        <TabBtn active={tab === 'connect'} onClick={() => setTab('connect')} icon={Radio}>
          Connexion
        </TabBtn>
        <TabBtn active={tab === 'profiles'} onClick={() => setTab('profiles')} icon={Settings2}>
          Profils
        </TabBtn>

        <button
          onClick={() => setLogOpen((open) => !open)}
          className={`ml-auto flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs transition ${
            logOpen
              ? 'bg-white/10 text-slate-200'
              : 'text-slate-500 hover:bg-white/5 hover:text-slate-300'
          }`}
          aria-expanded={logOpen}
        >
          <Terminal size={13} />
          Journal
          {c.logs.length > 0 && (
            <span className="rounded-full bg-white/10 px-1.5 text-[10px] tabular-nums text-slate-400">
              {c.logs.length}
            </span>
          )}
        </button>
      </nav>

      {/* ── Bannière d'erreur ── */}
      {c.error && (
        <div className="mx-2 flex shrink-0 items-start justify-between gap-2 rounded-lg border border-red-500/30 bg-red-950/40 px-3 py-2 text-xs text-red-200">
          <span className="min-w-0 break-words">{c.error}</span>
          <button
            onClick={c.clearError}
            className="shrink-0 text-red-300/70 hover:text-red-200"
            aria-label="Masquer l’erreur"
          >
            <X size={14} />
          </button>
        </div>
      )}

      {/* ── Contenu ── */}
      <main className="panel min-h-0 flex-1 overflow-hidden">
        {tab === 'connect' ? (
          <ConnectView
            state={c.state}
            profile={c.selectedProfile}
            upSince={c.upSince}
            telemetry={c.telemetry}
            history={c.history}
            backend={c.backend}
            adapterUp={c.adapterUp}
            onConnect={() => c.connect(c.selectedProfile?.name)}
            onDisconnect={c.disconnect}
          />
        ) : (
          <ProfilesView
            config={c.config}
            onSave={c.saveProfile}
            onDelete={c.removeProfile}
            onSelect={c.select}
          />
        )}
      </main>

      {/* ── Journal, replié par défaut : il ne dispute plus la place à l'instrument ── */}
      {logOpen && (
        <footer className="panel shrink-0 overflow-hidden">
          <EventLog logs={c.logs} />
        </footer>
      )}
    </div>
  )
}

function TabBtn({
  active,
  onClick,
  icon: Icon,
  children,
}: {
  active: boolean
  onClick: () => void
  icon: React.ElementType
  children: React.ReactNode
}) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs transition ${
        active ? 'bg-node/15 text-node' : 'text-slate-400 hover:bg-white/5 hover:text-slate-200'
      }`}
      aria-current={active ? 'page' : undefined}
    >
      <Icon size={13} />
      {children}
    </button>
  )
}
