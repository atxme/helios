import { useState } from 'react'
import { AppShell } from './components/AppShell'
import { useHelios } from './hooks/useHelios'
import type { NavId } from './navigation'
import { DashboardView } from './views/Dashboard'
import { FirewallView } from './views/Firewall'
import { SettingsView } from './views/Settings'
import { TelemetryView } from './views/Telemetry'
import { TrustView } from './views/Trust'
import { UpdateView } from './views/Update'
import { WireGuardView } from './views/WireGuard'

export default function App() {
  const [nav, setNav] = useState<NavId>('dashboard')
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
      {nav === 'dashboard' && (
        <DashboardView
          status={helios.status}
          currentState={helios.currentState}
          error={helios.error}
          events={helios.events}
          tunnelUpSince={helios.tunnelUpSince}
          connect={helios.connect}
          disconnect={helios.disconnect}
          releaseCaptivePortal={helios.releaseCaptivePortal}
        />
      )}
      {nav === 'telemetry' && <TelemetryView samples={helios.telemetry} status={helios.status} />}
      {nav === 'wireguard' && <WireGuardView status={helios.status} />}
      {nav === 'firewall' && <FirewallView status={helios.status} state={helios.currentState} />}
      {nav === 'trust' && <TrustView />}
      {nav === 'update' && <UpdateView />}
      {nav === 'settings' && (
        <SettingsView status={helios.status} onSplitTunnelChange={helios.updateSplitTunnel} />
      )}
    </AppShell>
  )
}
