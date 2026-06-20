import { useState } from 'react'
import { Layout } from './components/Layout'
import type { NavId } from './components/Layout'
import { useHelios } from './hooks/useHelios'
import { DashboardView } from './views/Dashboard'
import { FirewallView } from './views/Firewall'
import { SettingsView } from './views/Settings'
import { TelemetryView } from './views/Telemetry'

export default function App() {
  const [nav, setNav] = useState<NavId>('dashboard')
  const helios = useHelios()

  return (
    <Layout
      nav={nav}
      onNav={setNav}
      status={helios.status}
      error={helios.error}
      wsStatus={helios.wsStatus}
    >
      {nav === 'dashboard' && (
        <DashboardView
          status={helios.status}
          currentState={helios.currentState}
          error={helios.error}
          events={helios.events}
          wsStatus={helios.wsStatus}
          connect={helios.connect}
          disconnect={helios.disconnect}
        />
      )}
      {nav === 'telemetry' && (
        <TelemetryView samples={helios.telemetry} status={helios.status} />
      )}
      {nav === 'firewall' && (
        <FirewallView status={helios.status} state={helios.currentState} />
      )}
      {nav === 'settings' && (
        <SettingsView status={helios.status} />
      )}
    </Layout>
  )
}
