import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Skeleton from '@mui/material/Skeleton'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { Globe, KeyRound, Network, Save, Server, Shield, Wifi } from 'lucide-react'
import { useEffect, useState } from 'react'
import { DataRow } from '../components/DataRow'
import { KnownLimit } from '../components/KnownLimit'
import { SectionCard } from '../components/SectionCard'
import type { Status } from '../types'

interface Props {
  status: Status | null
  onSplitTunnelChange: (cidrs: string[]) => Promise<void>
}

export function SettingsView({ status, onSplitTunnelChange }: Props) {
  const [routes, setRoutes] = useState('')
  const [saving, setSaving] = useState(false)
  const [feedback, setFeedback] = useState<{ ok: boolean; message: string } | null>(null)

  useEffect(() => {
    setRoutes(status?.split_tunnel_cidrs.join('\n') ?? '')
  }, [status?.split_tunnel_cidrs])

  if (!status) {
    return (
      <Stack spacing={2.5}>
        <Skeleton variant="rounded" height={200} />
        <Skeleton variant="rounded" height={160} />
      </Stack>
    )
  }

  const save = async () => {
    setSaving(true)
    setFeedback(null)
    const cidrs = routes
      .split(/[\n,]/)
      .map(value => value.trim())
      .filter(Boolean)
    try {
      await onSplitTunnelChange(cidrs)
      setFeedback({ ok: true, message: 'Routes de split-tunnel transmises à l’orchestrateur.' })
    } catch {
      setFeedback({ ok: false, message: 'Échec de la mise à jour des routes de split-tunnel.' })
    } finally {
      setSaving(false)
    }
  }

  return (
    <Stack spacing={2.5}>
      {status.dry_run && (
        <KnownLimit register="caution" title="Le démon tourne en simulation">
          Les backends noyau WireGuard et nftables ne sont pas utilisés : les commandes sont
          journalisées, aucune interface n’est montée et aucune règle n’atteint le noyau. Rien de ce
          qui s’affiche ici ne prouve un effet réel sur le plan de données.
        </KnownLimit>
      )}

      <Box
        sx={{
          display: 'grid',
          gap: 2.5,
          gridTemplateColumns: { xs: '1fr', lg: '1fr 1fr' },
        }}
      >
        <SectionCard title="Passerelle">
          <Box>
            <DataRow icon={Wifi} label="Interface" value={status.wg_iface} />
            <DataRow
              icon={Network}
              label="Port"
              value={status.wg_listen_port ? `UDP ${status.wg_listen_port}` : 'non ouvert'}
            />
            <DataRow
              icon={KeyRound}
              label="Négociation"
              value={status.key_negotiation_port ? `UDP ${status.key_negotiation_port}` : 'inactive'}
            />
            <DataRow icon={Server} label="Pairs admis" value={String(status.peers.length)} />
            <DataRow
              icon={Shield}
              label="MSS clamp"
              value={status.mss_clamp ? String(status.mss_clamp) : 'automatique / absent'}
            />
            <DataRow icon={Server} label="Version" value={status.version} />
          </Box>
        </SectionCard>

        <SectionCard title="Administration">
          <Box>
            <DataRow icon={Globe} label="WAN" value={status.wan_iface} />
            <DataRow icon={Network} label="LAN" value={status.lan_ifaces.join(', ')} />
            <DataRow
              icon={Shield}
              label="SSH autorisé"
              value={status.allow_ssh_from.join(', ') || 'aucun'}
              hint="Exception permanente au kill-switch."
            />
            <DataRow icon={Wifi} label="Portail" value={status.captive_portal_gateway ?? 'absent'} />
          </Box>
        </SectionCard>
      </Box>

      <SectionCard
        title="Split-tunneling dynamique"
        subtitle="Un CIDR par ligne. Une liste vide désactive les routes de contournement."
      >
        <Stack spacing={2}>
          <TextField
            value={routes}
            onChange={event => setRoutes(event.target.value)}
            multiline
            minRows={5}
            fullWidth
            placeholder={'10.0.0.0/8\n192.168.0.0/16'}
            spellCheck={false}
            slotProps={{ input: { sx: { fontFamily: 'monospace', fontSize: '0.8125rem' } } }}
          />
          <Stack direction="row" spacing={2} sx={{ alignItems: 'center' }}>
            <Button
              variant="contained"
              disabled={saving}
              onClick={() => void save()}
              startIcon={<Save size={17} />}
            >
              {saving ? 'Envoi…' : 'Appliquer'}
            </Button>
            {feedback && (
              <Typography
                variant="body2"
                role="status"
                sx={{ color: feedback.ok ? 'state.up.main' : 'error.main' }}
              >
                {feedback.message}
              </Typography>
            )}
          </Stack>
        </Stack>
      </SectionCard>

      <KnownLimit title="Ce qui ne se change pas depuis cette interface">
        Les secrets WireGuard et la liste d’admission vivent dans{' '}
        <code>/var/lib/helios/network.toml</code> et ne sont volontairement jamais sérialisés par
        l’API. Le fichier est relu à chaud, mais le nom de l’interface, le port d’écoute et l’adresse
        d’administration ne peuvent pas changer sous un plan de données en marche : ils exigent un{' '}
        <code>systemctl restart heliosd</code>.
      </KnownLimit>
    </Stack>
  )
}
