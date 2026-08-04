import Box from '@mui/material/Box'
import Stack from '@mui/material/Stack'
import { Globe, KeyRound, Network, RadioTower, Server, Wifi } from 'lucide-react'
import { useEffect, useState } from 'react'
import { DataRow } from '../components/DataRow'
import { EventLog } from '../components/EventLog'
import type { TimestampedEvent } from '../components/EventLog'
import { Metric } from '../components/Metric'
import { SectionCard } from '../components/SectionCard'
import { StateBanner } from '../components/StateBadge'
import { TunnelControls } from '../components/TunnelControls'
import { TUNNEL_STATE, toneColors } from '../state'
import type { Status, TunnelState } from '../types'

interface Props {
  status: Status | null
  currentState: TunnelState
  error: string | null
  events: TimestampedEvent[]
  tunnelUpSince: Date | null
  connect: () => Promise<void>
  disconnect: () => Promise<void>
  releaseCaptivePortal: () => Promise<void>
}

/**
 * Counts up for as long as a handshake has been holding.
 *
 * The value is derived from `since` on every tick rather than accumulated, so
 * a tab that was backgrounded — where timers are throttled — shows the true
 * elapsed time on return instead of however many ticks the browser allowed.
 */
function useUptime(since: Date | null): string | undefined {
  const [, tick] = useState(0)

  useEffect(() => {
    if (!since) return
    const id = setInterval(() => tick(value => value + 1), 1000)
    return () => clearInterval(id)
  }, [since])

  if (!since) return undefined

  const seconds = Math.max(0, Math.floor((Date.now() - since.getTime()) / 1000))
  const pad = (value: number) => String(value).padStart(2, '0')
  return `${pad(Math.floor(seconds / 3600))}:${pad(Math.floor((seconds / 60) % 60))}:${pad(seconds % 60)}`
}

export function DashboardView({
  status,
  currentState,
  error,
  events,
  tunnelUpSince,
  connect,
  disconnect,
  releaseCaptivePortal,
}: Props) {
  const uptime = useUptime(tunnelUpSince)
  const isUp = currentState === 'up'
  const upTone = toneColors(TUNNEL_STATE.up.tone).main

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
          label="Interface"
          value={status?.wg_iface || '—'}
          icon={RadioTower}
          accent={isUp ? upTone : undefined}
        />
        <Metric
          label="Écoute"
          value={status?.wg_listen_port ? `UDP ${status.wg_listen_port}` : 'fermée'}
          icon={Wifi}
          hint="Port WireGuard à rediriger depuis l’extérieur."
        />
        <Metric
          label="Négociation"
          value={status?.key_negotiation_port ? `UDP ${status.key_negotiation_port}` : 'inactive'}
          icon={KeyRound}
          hint="Sans ce second port, les clients retombent sur l’ancien chemin et leur premier handshake n’est pas protégé."
        />
        <Metric label="Pairs admis" value={String(status?.peers.length ?? 0)} icon={Server} />
      </Box>

      <Box
        sx={{
          display: 'grid',
          gap: 2.5,
          gridTemplateColumns: { xs: '1fr', lg: '1fr 1fr' },
          alignItems: 'stretch',
        }}
      >
        <SectionCard title="Contrôle de la passerelle">
          <TunnelControls
            state={currentState}
            daemonError={Boolean(error)}
            captiveGateway={status?.captive_portal_gateway ?? null}
            onConnect={connect}
            onDisconnect={disconnect}
            onReleaseCaptivePortal={releaseCaptivePortal}
          />
        </SectionCard>

        {/*
          Deliberately does not repeat the metric strip above it: an interface
          name printed twice on one screen reads as two different interfaces
          for exactly as long as it takes to notice they match.
        */}
        <SectionCard title="Réseau">
          {status ? (
            <Box>
              <DataRow icon={Globe} label="WAN" value={status.wan_iface} />
              <DataRow icon={Network} label="LAN protégé" value={status.lan_ifaces.join(', ')} />
              <DataRow
                icon={Network}
                label="Site-à-site"
                value={status.wg_peers.join(', ')}
                hint="Pairs sortants statiques, distincts des clients admis."
              />
              <DataRow
                icon={Wifi}
                label="MSS clamp"
                value={status.mss_clamp === null ? '' : `${status.mss_clamp} octets`}
                hint="Découvert par PMTUD et appliqué au trafic sortant du tunnel."
              />
            </Box>
          ) : (
            <DataRow label="Réseau" value="" hint="Statut non encore reçu du démon." />
          )}
        </SectionCard>
      </Box>

      <SectionCard
        title="Journal d’événements"
        subtitle={
          events.length > 0
            ? `${events.length} dernier${events.length > 1 ? 's' : ''} événement${events.length > 1 ? 's' : ''} reçus du démon, le plus récent en tête.`
            : 'Diffusé par le démon sur la WebSocket d’administration.'
        }
        disableContentPadding
      >
        <EventLog events={events} />
      </SectionCard>
    </Stack>
  )
}
