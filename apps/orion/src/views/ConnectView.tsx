import { useEffect, useState } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { ArrowDown, ArrowUp, Info, Power, ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'
import type { ClientProfile, TelemetrySample, TunnelState } from '../types'
import { elapsed, formatBps, postureMeta, stateMeta } from '../components/state'
import { Sparkline } from '../components/Sparkline'
import { StatusOrb } from '../components/StatusOrb'

interface Props {
  state: TunnelState
  profile: ClientProfile | null
  upSince: number | null
  telemetry: TelemetrySample | null
  history: TelemetrySample[]
  backend: string
  adapterUp: boolean
  onConnect: () => void
  onDisconnect: () => void
}

const POSTURE_ICON = {
  protected: ShieldCheck,
  held: ShieldQuestion,
  exposed: ShieldAlert,
} as const

export function ConnectView({
  state,
  profile,
  upSince,
  telemetry,
  history,
  backend,
  adapterUp,
  onConnect,
  onDisconnect,
}: Props) {
  const meta = stateMeta(state)
  const posture = postureMeta(state, adapterUp)
  const [now, setNow] = useState(Date.now())

  useEffect(() => {
    if (upSince === null) return
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [upSince])

  const duration = elapsed(upSince, now)
  const pq = Boolean(profile?.preshared_key?.trim())
  const ready = Boolean(profile?.endpoint && profile.private_key && profile.peer_public_key)
  const PostureIcon = POSTURE_ICON[posture.posture]

  return (
    <Stack
      spacing={2.25}
      sx={{ height: '100%', overflowY: 'auto', px: { xs: 2, sm: 3 }, py: 2.5 }}
    >
      <Stack spacing={1.5} sx={{ alignItems: 'center' }}>
        <StatusOrb state={state} adapterUp={adapterUp} />

        <Box sx={{ textAlign: 'center' }} aria-live="polite" aria-atomic="true">
          <Typography
            component="h2"
            sx={{ color: meta.color, fontSize: 21, fontWeight: 700, letterSpacing: '-0.02em' }}
          >
            {meta.label}
          </Typography>
          <Typography
            color="text.secondary"
            sx={{ mt: 0.5, fontFamily: 'monospace', fontSize: 12, overflowWrap: 'anywhere' }}
          >
            {profile?.endpoint || (profile ? 'endpoint non défini' : 'aucun profil sélectionné')}
          </Typography>
          {duration && (
            <Typography
              color="text.disabled"
              sx={{ mt: 0.4, fontFamily: 'monospace', fontSize: 11, fontVariantNumeric: 'tabular-nums' }}
            >
              {duration}
            </Typography>
          )}
        </Box>
      </Stack>

      {/* La couleur et l’icône portent toutes deux la posture de sécurité réelle. */}
      <Paper
        variant="outlined"
        sx={{
          display: 'flex',
          alignItems: 'flex-start',
          gap: 1.5,
          borderColor: `${posture.color}44`,
          bgcolor: `${posture.color}0e`,
          p: 1.5,
        }}
      >
        <PostureIcon size={19} aria-hidden style={{ color: posture.color, flexShrink: 0, marginTop: 2 }} />
        <Box sx={{ minWidth: 0 }}>
          <Typography sx={{ color: posture.color, fontSize: 13, fontWeight: 700 }}>
            {posture.label}
          </Typography>
          <Typography color="text.secondary" sx={{ mt: 0.25, fontSize: 11, lineHeight: 1.55 }}>
            {posture.detail}
          </Typography>
        </Box>
      </Paper>

      {meta.active && <Throughput telemetry={telemetry} history={history} />}

      <Box
        aria-label="Caractéristiques du profil"
        sx={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 1 }}
      >
        <Tile
          label="Protection"
          value={pq ? 'PSK post-quantique' : 'WireGuard classique'}
          accent={pq}
          hint={
            pq
              ? 'Le secret ML-KEM-768 alimente le slot PresharedKey : un enregistrement du trafic reste illisible pour un adversaire quantique.'
              : 'Sans PSK, la confidentialité repose sur Curve25519 seul et reste exposée au scénario « récolter maintenant, déchiffrer plus tard ».'
          }
        />
        <Tile label="Adresse virtuelle" value={profile?.address ?? 'assignée à l’enrôlement'} mono />
        <Tile label="Trafic capté" value={profile?.allowed_ips ?? '—'} mono />
        <Tile label="Backend" value={backend || '—'} mono />
      </Box>

      <Stack spacing={1} sx={{ mt: 'auto', pt: 0.5 }}>
        {meta.active || meta.transitioning ? (
          <Button
            fullWidth
            variant="outlined"
            color="error"
            startIcon={<Power size={17} aria-hidden />}
            onClick={onDisconnect}
            sx={{ bgcolor: 'rgba(127, 29, 29, 0.18)' }}
          >
            {state === 'connecting' ? 'Annuler et démonter' : 'Déconnecter'}
          </Button>
        ) : (
          <Button
            fullWidth
            variant="contained"
            startIcon={<Power size={17} aria-hidden />}
            onClick={onConnect}
            disabled={!ready}
          >
            Connecter
          </Button>
        )}

        {!ready && profile && (
          <Typography
            role="status"
            color="warning.main"
            sx={{ textAlign: 'center', fontSize: 11, opacity: 0.9 }}
          >
            Profil incomplet : endpoint, clé privée et clé publique de la gateway sont requis.
          </Typography>
        )}

        {posture.posture === 'held' && (
          <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 0.75, color: 'text.disabled' }}>
            <Info size={14} aria-hidden style={{ flexShrink: 0, marginTop: 2 }} />
            <Typography sx={{ fontSize: 11, lineHeight: 1.5 }}>
              Déconnecter démonte l’adaptateur et rend la route par défaut au trafic en clair. Pour
              relancer une négociation, laissez Orion réessayer.
            </Typography>
          </Box>
        )}
      </Stack>
    </Stack>
  )
}

function Throughput({
  telemetry,
  history,
}: {
  telemetry: TelemetrySample | null
  history: TelemetrySample[]
}) {
  // Échelle commune aux deux séries — voir le doc-comment de Sparkline.
  const ceiling = Math.max(1, ...history.map((sample) => Math.max(sample.rx_bps, sample.tx_bps)))

  return (
    <Box
      aria-label="Débit du tunnel"
      sx={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 1 }}
    >
      <Series
        icon={ArrowDown}
        label="Réception"
        value={telemetry ? formatBps(telemetry.rx_bps) : '—'}
        points={history.map((sample) => sample.rx_bps)}
        ceiling={ceiling}
        color="#28e4a0"
      />
      <Series
        icon={ArrowUp}
        label="Émission"
        value={telemetry ? formatBps(telemetry.tx_bps) : '—'}
        points={history.map((sample) => sample.tx_bps)}
        ceiling={ceiling}
        color="#22d3ee"
      />
    </Box>
  )
}

function Series({
  icon: Icon,
  label,
  value,
  points,
  ceiling,
  color,
}: {
  icon: React.ElementType
  label: string
  value: string
  points: number[]
  ceiling: number
  color: string
}) {
  return (
    <Paper variant="outlined" sx={{ minWidth: 0, bgcolor: 'rgba(0, 0, 0, 0.18)', px: 1.25, pt: 1.1 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.6 }}>
        <Icon size={13} aria-hidden style={{ color }} />
        <Typography variant="overline" color="text.disabled" sx={{ fontSize: 9 }}>
          {label}
        </Typography>
        <Typography
          sx={{
            ml: 'auto',
            color,
            fontFamily: 'monospace',
            fontSize: 11,
            fontVariantNumeric: 'tabular-nums',
          }}
        >
          {value}
        </Typography>
      </Box>
      <Sparkline points={points} ceiling={ceiling} color={color} label={label} />
    </Paper>
  )
}

function Tile({
  label,
  value,
  mono = false,
  accent = false,
  hint,
}: {
  label: string
  value: string
  mono?: boolean
  accent?: boolean
  hint?: string
}) {
  const tile = (
    <Paper
      variant="outlined"
      sx={{ minWidth: 0, bgcolor: 'rgba(0, 0, 0, 0.18)', px: 1.25, py: 1.1 }}
    >
      <Typography variant="overline" color="text.disabled" sx={{ display: 'block', fontSize: 9 }}>
        {label}
      </Typography>
      <Typography
        noWrap
        sx={{
          mt: 0.35,
          color: accent ? 'primary.main' : 'text.secondary',
          fontFamily: mono ? 'monospace' : undefined,
          fontSize: 11,
        }}
      >
        {value}
      </Typography>
    </Paper>
  )

  return hint ? <Tooltip title={hint}>{tile}</Tooltip> : tile
}
