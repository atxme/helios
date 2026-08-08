import Box from '@mui/material/Box'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { Activity, KeyRound, RadioTower, ScrollText, Users, Wifi } from 'lucide-react'
import { useEffect, useState } from 'react'
import { EventLog } from '../components/EventLog'
import type { TimestampedEvent } from '../components/EventLog'
import { Metric } from '../components/Metric'
import { NetworkStats } from '../components/NetworkStats'
import { SectionCard } from '../components/SectionCard'
import { StateBanner } from '../components/StateBadge'
import { TunnelControls } from '../components/TunnelControls'
import { formatDuration } from '../format'
import type { Status, TelemetrySample, TunnelState } from '../types'

interface Props {
  status: Status | null
  currentState: TunnelState
  error: string | null
  events: TimestampedEvent[]
  telemetry: TelemetrySample[]
  tunnelUpSince: Date | null
  connect: () => Promise<void>
  disconnect: () => Promise<void>
  releaseCaptivePortal: () => Promise<void>
}

/**
 * Counts up for as long as a handshake has been holding.
 *
 * Derived from `since` on every tick rather than accumulated, so a tab that was
 * backgrounded — where timers are throttled — shows the true elapsed time on
 * return instead of however many ticks the browser allowed.
 */
function useUptime(since: Date | null): string | undefined {
  const [, tick] = useState(0)

  useEffect(() => {
    if (!since) return
    const id = setInterval(() => tick(value => value + 1), 1000)
    return () => clearInterval(id)
  }, [since])

  if (!since) return undefined
  return formatDuration((Date.now() - since.getTime()) / 1000)
}

export function OverviewView({
  status,
  currentState,
  error,
  events,
  telemetry,
  tunnelUpSince,
  connect,
  disconnect,
  releaseCaptivePortal,
}: Props) {
  const uptime = useUptime(tunnelUpSince)
  const staleAfter = status?.handshake_stale_after_seconds ?? 150
  const peers = status?.peers ?? []
  const online = peers.filter(
    peer => peer.last_handshake_age_seconds !== null && peer.last_handshake_age_seconds < staleAfter,
  ).length

  return (
    <Stack spacing={2.5}>
      <StateBanner state={currentState} uptime={uptime} />

      <Box
        sx={{
          display: 'grid',
          gap: 2,
          gridTemplateColumns: { xs: 'repeat(2, 1fr)', md: 'repeat(4, 1fr)' },
        }}
      >
        <Metric
          label="Clients en ligne"
          value={`${online} / ${peers.length}`}
          icon={Users}
          accent={online > 0 ? 'state.up.main' : undefined}
        />
        <Metric label="Interface" value={status?.wg_iface || '—'} icon={RadioTower} />
        <Metric
          label="Écoute"
          value={status?.wg_listen_port ? `UDP ${status.wg_listen_port}` : 'fermée'}
          icon={Wifi}
        />
        <Metric
          label="Négociation"
          value={status?.key_negotiation_port ? `UDP ${status.key_negotiation_port}` : 'inactive'}
          icon={KeyRound}
          hint="Sans ce second port, aucun PSK post-quantique n’est négocié et un client qui épingle cette gateway échoue avant WireGuard."
        />
      </Box>

      <Box
        sx={{
          display: 'grid',
          gap: 2.5,
          gridTemplateColumns: { xs: '1fr', lg: '1fr 1fr' },
        }}
      >
        <SectionCard title="Trafic WAN" icon={Activity} accent="state.connecting.main">
          <NetworkStats samples={telemetry} sparklineHeight={56} />
        </SectionCard>

        <SectionCard title="Commandes" icon={RadioTower}>
          <TunnelControls
            state={currentState}
            daemonError={Boolean(error)}
            captiveGateway={status?.captive_portal_gateway ?? null}
            onConnect={connect}
            onDisconnect={disconnect}
            onReleaseCaptivePortal={releaseCaptivePortal}
          />
        </SectionCard>
      </Box>

      <SectionCard
        title="Événements"
        icon={ScrollText}
        action={
          events.length > 0 ? (
            <Typography variant="overline" sx={{ color: 'text.disabled' }}>
              {events.length}
            </Typography>
          ) : undefined
        }
        disableContentPadding
      >
        <EventLog events={events} maxHeight={260} />
      </SectionCard>
    </Stack>
  )
}
