import { useState } from 'react'
import { Settings2, Activity, Sun, X } from 'lucide-react'
import { useClient } from './hooks/useClient'
import { ConnectView } from './views/ConnectView'
import { ProfilesView } from './views/ProfilesView'
import { EventLog } from './components/EventLog'

type Tab = 'connect' | 'profiles'

export default function App() {
  const c = useClient()
  const [tab, setTab] = useState<Tab>('connect')

  return (
    <div className="flex h-screen flex-col">
      {/* En-tête */}
      <header className="flex items-center justify-between px-4 py-3">
        <div className="flex items-center gap-2">
          <Sun size={18} className="text-sun" />
          <span className="text-sm font-semibold tracking-wide">Helios VPN</span>
        </div>
        <nav className="flex gap-1">
          <TabBtn active={tab === 'connect'} onClick={() => setTab('connect')}>
            <Activity size={14} /> Connexion
          </TabBtn>
          <TabBtn active={tab === 'profiles'} onClick={() => setTab('profiles')}>
            <Settings2 size={14} /> Profils
          </TabBtn>
        </nav>
      </header>

      {/* Bannière d'erreur */}
      {c.error && (
        <div className="mx-4 mb-2 flex items-start justify-between gap-2 rounded-lg border border-red-500/30 bg-red-950/40 px-3 py-2 text-xs text-red-200">
          <span>{c.error}</span>
          <button onClick={c.clearError} className="shrink-0 text-red-300/70 hover:text-red-200">
            <X size={14} />
          </button>
        </div>
      )}

      {/* Contenu */}
      <main className="mx-3 flex-1 overflow-hidden panel">
        {tab === 'connect' ? (
          <ConnectView
            state={c.state}
            profile={c.selectedProfile}
            upSince={c.upSince}
            telemetry={c.telemetry}
            backend={c.backend}
            onConnect={() => c.connect()}
            onDisconnect={c.disconnect}
          />
        ) : (
          <ProfilesView
            config={c.config}
            predefined={c.predefined}
            onSave={c.saveProfile}
            onDelete={c.removeProfile}
            onSelect={c.select}
          />
        )}
      </main>

      {/* Journal d'événements */}
      <footer className="mx-3 mb-3 mt-2 panel">
        <div className="border-b border-white/5 px-4 py-1.5 text-[11px] uppercase tracking-wide text-slate-500">
          Journal
        </div>
        <EventLog logs={c.logs} />
      </footer>
    </div>
  )
}

function TabBtn({
  active,
  onClick,
  children,
}: {
  active: boolean
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs transition ${
        active ? 'bg-node/15 text-node' : 'text-slate-400 hover:bg-white/5 hover:text-slate-200'
      }`}
    >
      {children}
    </button>
  )
}
