import { ConnectionDetails } from '../components/ConnectionDetails'
import { EventTerminal } from '../components/EventTerminal'
import { StatusHero } from '../components/StatusHero'
import { TunnelControls } from '../components/TunnelControls'
import type { WsStatus } from '../hooks/useHelios'
import type { DisplayEvent, Status, TunnelState } from '../types'

interface Props {
  status: Status | null
  currentState: TunnelState
  error: string | null
  events: (DisplayEvent & { ts: string })[]
  wsStatus: WsStatus
  connect: () => Promise<void>
  disconnect: () => Promise<void>
}

export function DashboardView({ status, currentState, error, events, wsStatus, connect, disconnect }: Props) {
  return (
    <div className="space-y-4 max-w-4xl">
      <StatusHero state={currentState} status={status} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <TunnelControls
          state={currentState}
          daemonError={!!error}
          onConnect={connect}
          onDisconnect={disconnect}
        />
        <ConnectionDetails status={status} />
      </div>

      <EventTerminal events={events} wsStatus={wsStatus} />
    </div>
  )
}
