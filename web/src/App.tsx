import { useState } from 'react'
import { AppShell } from './components/AppShell'
import { useHelios } from './hooks/useHelios'
import type { NavId } from './navigation'
import { ClientsView } from './views/Clients'
import { OverviewView } from './views/Overview'
import { SecurityView } from './views/Security'
import { SystemView } from './views/System'

export default function App() {
  const [nav, setNav] = useState<NavId>('overview')
  // Owned here rather than by the Clients view: the button that opens it lives
  // in the shell's header, above the view.
  const [admitOpen, setAdmitOpen] = useState(false)
  const helios = useHelios()

  return (
    <AppShell
      nav={nav}
      onNav={setNav}
      status={helios.status}
      currentState={helios.currentState}
      error={helios.error}
      wsStatus={helios.wsStatus}
    >
      {nav === 'overview' && (
        <OverviewView
          status={helios.status}
          currentState={helios.currentState}
          error={helios.error}
          events={helios.events}
          telemetry={helios.telemetry}
          tunnelUpSince={helios.tunnelUpSince}
          connect={helios.connect}
          disconnect={helios.disconnect}
          releaseCaptivePortal={helios.releaseCaptivePortal}
        />
      )}
      {nav === 'clients' && (
        <ClientsView
          status={helios.status}
          refresh={helios.refresh}
          admitOpen={admitOpen}
          onAdmitOpenChange={setAdmitOpen}
        />
      )}
      {nav === 'security' && <SecurityView status={helios.status} state={helios.currentState} />}
      {nav === 'system' && (
        <SystemView
          status={helios.status}
          events={helios.events}
          onSplitTunnelChange={helios.updateSplitTunnel}
        />
      )}
    </AppShell>
  )
}
