import { useEffect, useState } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Stack from '@mui/material/Stack'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { ArrowDown, ArrowUp, Power, ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'
import type { ClientProfile, TelemetrySample, TunnelState } from '../types'
import { elapsed, formatBps, postureMeta, stateMeta } from '../components/state'
import { Sparkline } from '../components/Sparkline'
import { StatusOrb } from '../components/StatusOrb'
import { EMERALD, GUTTER } from '../theme'

/**
 * Vue Connexion — l’écran qui répond à la seule question qui compte :
 * « mon trafic est-il protégé ? »
 *
 * Hiérarchie assumée : l’orbe et l’état occupent le centre optique, les
 * caractéristiques techniques restent en bas et en petit. Rien ne défile ; ce
 * qui ne mérite pas sa place à l’écran n’y est pas — et ce que l’en-tête dit
 * déjà n’est pas répété ici.
 */

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
  // Seul « retenu » mérite une phrase : c'est le seul cas contre-intuitif, où
  // l'utilisateur croit fuir alors que WireGuard jette ses paquets. « Protégé »
  // et « en clair » sont déjà dits par la pastille de l'en-tête, mot pour mot —
  // les répéter ici ne fait que remplir.
  const explain = posture.posture === 'held'
  // Le débit ne s'affiche que s'il existe vraiment. Tant que la télémétrie
  // n'émet rien, une carte vide serait une promesse non tenue.
  const hasThroughput = meta.active && history.length >= 2

  return (
    <Stack sx={{ height: '100%', px: GUTTER, py: GUTTER }}>
      <Stack
        spacing={1.25}
        sx={{ alignItems: 'center', justifyContent: 'center', flex: 1, minHeight: 0 }}
      >
        <StatusOrb state={state} adapterUp={adapterUp} size={150} />

        <Box sx={{ textAlign: 'center' }} aria-live="polite" aria-atomic="true">
          <Typography
            component="h2"
            sx={{ color: meta.color, fontSize: 24, fontWeight: 700, letterSpacing: '-0.02em', lineHeight: 1.1 }}
          >
            {meta.label}
          </Typography>
          <Typography
            color="text.secondary"
            sx={{ mt: 0.6, fontFamily: 'monospace', fontSize: 12, overflowWrap: 'anywhere' }}
          >
            {profile?.endpoint || (profile ? 'endpoint non défini' : 'aucun profil sélectionné')}
          </Typography>
          {duration && (
            <Typography
              color="text.disabled"
              sx={{ mt: 0.3, fontFamily: 'monospace', fontSize: 11, fontVariantNumeric: 'tabular-nums' }}
            >
              {duration}
            </Typography>
          )}
        </Box>
      </Stack>

      {/* Posture : uniquement « retenu ». Les deux autres états sont déjà
          énoncés à l'identique par la pastille de l'en-tête ; seul celui-ci dit
          quelque chose que la pastille ne dit pas — que WireGuard jette les
          paquets et qu'il ne faut surtout pas démonter l'adaptateur. */}
      {explain && (
        <Box
          sx={{
            display: 'flex',
            flexWrap: 'wrap',
            justifyContent: 'center',
            alignItems: 'center',
            gap: 0.75,
            mt: 1.5,
          }}
        >
          <PostureIcon size={15} aria-hidden style={{ color: posture.color, flexShrink: 0 }} />
          <Typography sx={{ color: posture.color, fontSize: 12, fontWeight: 650 }}>
            {posture.label}
          </Typography>
          <Typography color="text.secondary" sx={{ fontSize: 12, lineHeight: 1.5 }}>
            {posture.detail}
          </Typography>
        </Box>
      )}

      {hasThroughput && (
        <Box
          aria-label="Débit du tunnel"
          sx={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 1, mt: 1.25 }}
        >
          <Series
            icon={ArrowDown}
            label="Réception"
            value={telemetry ? formatBps(telemetry.rx_bps) : '—'}
            points={history.map((sample) => sample.rx_bps)}
            ceiling={ceilingOf(history)}
          />
          <Series
            icon={ArrowUp}
            label="Émission"
            value={telemetry ? formatBps(telemetry.tx_bps) : '—'}
            points={history.map((sample) => sample.tx_bps)}
            ceiling={ceilingOf(history)}
          />
        </Box>
      )}

      {/* Caractéristiques : de la référence, pas un titre. Discrètes par choix. */}
      <Box sx={{ pt: 1.5 }}>
        <Tooltip
          title={
            pq
              ? 'Le secret ML-KEM-768 occupe le slot PresharedKey : un trafic enregistré aujourd’hui reste illisible pour un adversaire quantique.'
              : 'Sans PSK, la confidentialité repose sur Curve25519 seul.'
          }
        >
          <Box
            sx={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 0.75,
              px: 1,
              py: 0.4,
              borderRadius: 1,
              border: '1px solid',
              borderColor: pq ? `${EMERALD}66` : 'divider',
              bgcolor: pq ? `${EMERALD}14` : 'transparent',
            }}
          >
            <Typography
              sx={{
                color: pq ? 'primary.main' : 'text.secondary',
                fontFamily: 'monospace',
                fontSize: 10.5,
                fontWeight: 600,
              }}
            >
              {pq ? 'PSK POST-QUANTIQUE' : 'WIREGUARD CLASSIQUE'}
            </Typography>
          </Box>
        </Tooltip>

        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.4, mt: 1 }}>
          <Fact label="adresse" value={profile?.address ?? '—'} />
          <Fact label="capté" value={profile?.allowed_ips ?? '—'} />
          <Fact label="backend" value={backend || '—'} />
        </Box>
      </Box>

      <Stack spacing={0.75} sx={{ pt: 1.75 }}>
        {meta.active || meta.transitioning ? (
          <Button
            fullWidth
            variant="outlined"
            color="error"
            startIcon={<Power size={17} aria-hidden />}
            onClick={onDisconnect}
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
            sx={{ textAlign: 'center', fontSize: 11 }}
          >
            Profil incomplet : endpoint, clé privée et clé publique de la gateway sont requis.
          </Typography>
        )}
      </Stack>
    </Stack>
  )
}

/** Échelle commune aux deux séries — voir le doc-comment de `Sparkline`. */
function ceilingOf(history: TelemetrySample[]): number {
  return Math.max(1, ...history.map((sample) => Math.max(sample.rx_bps, sample.tx_bps)))
}

function Fact({ label, value }: { label: string; value: string }) {
  return (
    <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 0.5, minWidth: 0 }}>
      <Typography
        color="text.disabled"
        sx={{ fontFamily: 'monospace', fontSize: 9.5, letterSpacing: '0.1em', textTransform: 'uppercase' }}
      >
        {label}
      </Typography>
      <Typography
        noWrap
        color="text.secondary"
        sx={{ fontFamily: 'monospace', fontSize: 10.5, mr: 1 }}
      >
        {value}
      </Typography>
    </Box>
  )
}

function Series({
  icon: Icon,
  label,
  value,
  points,
  ceiling,
}: {
  icon: React.ElementType
  label: string
  value: string
  points: number[]
  ceiling: number
}) {
  return (
    <Box
      sx={{
        minWidth: 0,
        px: 1.25,
        pt: 0.9,
        pb: 0.4,
        borderRadius: 2,
        border: '1px solid',
        borderColor: 'divider',
      }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.6 }}>
        <Icon size={12} aria-hidden style={{ color: EMERALD }} />
        <Typography variant="overline" color="text.disabled" sx={{ fontSize: 9 }}>
          {label}
        </Typography>
        <Typography
          sx={{
            ml: 'auto',
            color: 'primary.main',
            fontFamily: 'monospace',
            fontSize: 11,
            fontVariantNumeric: 'tabular-nums',
          }}
        >
          {value}
        </Typography>
      </Box>
      <Sparkline points={points} ceiling={ceiling} color={EMERALD} label={label} />
    </Box>
  )
}
