import { AlertCircle, ShieldHalf } from 'lucide-react'
import { ConnectionDetails } from './components/ConnectionDetails'
import { EventTerminal } from './components/EventTerminal'
import { StatusHero } from './components/StatusHero'
import { TunnelControls } from './components/TunnelControls'
import { useHelios } from './hooks/useHelios'

export default function App() {
  const { status, error, events, wsStatus, currentState, connect, disconnect } = useHelios()

  return (
    <div className="min-h-screen text-zinc-100">
      {/* En-tête */}
      <header className="sticky top-0 z-10 bg-zinc-950/90 backdrop-blur-sm border-b border-zinc-800/80">
        <div className="max-w-4xl mx-auto px-6 h-14 flex items-center justify-between">
          {/* Logo */}
          <div className="flex items-center gap-3">
            <div className="h-7 w-7 rounded border border-emerald-500/30 bg-emerald-500/8
                            flex items-center justify-center">
              <ShieldHalf className="h-4 w-4 text-emerald-400" strokeWidth={1.5} />
            </div>
            <span className="font-bold tracking-[0.2em] text-sm text-zinc-100">HELIOS</span>
            <span className="text-zinc-700 text-xs hidden sm:block">IPsec Gateway</span>
          </div>

          {/* Badges */}
          <div className="flex items-center gap-2">
            {status?.dry_run && (
              <span className="text-[10px] px-2 py-0.5 rounded border border-violet-500/30
                               bg-violet-500/8 text-violet-400 font-mono tracking-wider uppercase">
                Simulation
              </span>
            )}
            {status && (
              <span className="text-[10px] text-zinc-600 font-mono">v{status.version}</span>
            )}
          </div>
        </div>
      </header>

      {/* Bannière d'erreur daemon unreachable */}
      {error && (
        <div className="border-b border-red-500/20 bg-red-500/5">
          <div className="max-w-4xl mx-auto px-6 py-2.5 flex items-center gap-2.5">
            <AlertCircle className="h-3.5 w-3.5 text-red-400 shrink-0" strokeWidth={1.5} />
            <span className="text-xs text-red-400">{error}</span>
          </div>
        </div>
      )}

      {/* Contenu */}
      <main className="max-w-4xl mx-auto px-6 py-5 space-y-4">
        {/* Statut hero — pleine largeur */}
        <StatusHero state={currentState} status={status} />

        {/* Grille 2 colonnes */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <ConnectionDetails status={status} />
          <TunnelControls
            state={currentState}
            onConnect={connect}
            onDisconnect={disconnect}
          />
        </div>

        {/* Journal temps réel */}
        <EventTerminal events={events} wsStatus={wsStatus} />
      </main>
    </div>
  )
}
