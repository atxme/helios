import { EventFeed } from './components/EventFeed'
import { StatusCard } from './components/StatusCard'
import { TunnelControls } from './components/TunnelControls'
import { useHelios } from './hooks/useHelios'

export default function App() {
  const { status, events, wsStatus, currentState, connect, disconnect } = useHelios()

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="text-lg font-bold tracking-tight">HELIOS</span>
          <span className="text-xs text-slate-500">IPsec Gateway</span>
        </div>
        {status && (
          <span className="text-xs text-slate-600 font-mono">v{status.version}</span>
        )}
      </header>

      <main className="max-w-2xl mx-auto px-6 py-8 space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <StatusCard status={status} />
          <TunnelControls
            state={currentState}
            onConnect={connect}
            onDisconnect={disconnect}
          />
        </div>
        <EventFeed events={events} wsStatus={wsStatus} />
      </main>
    </div>
  )
}
