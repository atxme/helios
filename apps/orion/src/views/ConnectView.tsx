import { useEffect, useState } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Stack from '@mui/material/Stack'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import {
  ArrowDown,
  ArrowUp,
  KeyRound,
  Power,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  TerminalSquare,
} from 'lucide-react'
import type { ClientProfile, PskKind, TelemetrySample, TunnelState } from '../types'
import {
  elapsed,
  formatBps,
  postureMeta,
  protectionMeta,
  stateMeta,
  type ProtectionTone,
} from '../components/state'
import { Sparkline } from '../components/Sparkline'
import { StatusOrb } from '../components/StatusOrb'
import { EMERALD, GUTTER, PINE } from '../theme'

/** Transition amber — same tint as the "Connecting…" state, readable on paper. */
const AMBER = '#A16207'

/**
 * Connect view — the screen that answers the only question that matters:
 * "is my traffic protected?"
 *
 * Deliberate hierarchy: the orb and the state occupy the optical center,
 * technical characteristics stay at the bottom and small. Nothing scrolls;
 * what doesn't deserve its place on screen isn't there — and what the
 * header already says isn't repeated here.
 */

interface Props {
  state: TunnelState
  profile: ClientProfile | null
  upSince: number | null
  telemetry: TelemetrySample | null
  history: TelemetrySample[]
  adapterUp: boolean
  /** Kind of PSK set for the current session. `null` = not yet decided. */
  psk: PskKind | null
  onConnect: () => void
  onDisconnect: () => void
  /** Opens a terminal on the gateway, de-elevated. */
  onOpenSsh: () => void
  /** A renewal is in flight, from its start to its outcome. */
  renewing: boolean
  /** Renews the ML-KEM PSK through the tunnel. */
  onRenewKey: () => void
}

const POSTURE_ICON = {
  protected: ShieldCheck,
  blocked: ShieldQuestion,
  exposed: ShieldAlert,
} as const

/**
 * Styling of the protection chip.
 *
 * Three visual levels for three distinct facts, and the gap between `pqc`
 * and `static` is intentional: the static PSK protects, but it doesn't
 * rotate. Giving it the same solid green as the PQC PSK would erase the
 * only difference that matters.
 */
const PROTECTION_SKIN: Record<ProtectionTone, { border: string; fill: string; text: string }> = {
  pqc: { border: `${EMERALD}66`, fill: `${EMERALD}14`, text: 'primary.main' },
  static: { border: `${PINE}44`, fill: 'transparent', text: 'primary.main' },
  pending: { border: `${AMBER}55`, fill: `${AMBER}12`, text: AMBER },
  classic: { border: 'divider', fill: 'transparent', text: 'text.secondary' },
}

export function ConnectView({
  state,
  profile,
  upSince,
  telemetry,
  history,
  adapterUp,
  psk,
  renewing,
  onConnect,
  onDisconnect,
  onOpenSsh,
  onRenewKey,
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
  const protection = protectionMeta(profile, psk, state)
  // `has_private_key` rather than the key itself: the screen needs to know a
  // key exists, and never needed to hold one (ADR-006 §5).
  const ready = Boolean(profile?.endpoint && profile.has_private_key && profile.peer_public_key)
  const PostureIcon = POSTURE_ICON[posture.posture]
  // Only "blocked" deserves a sentence: it's the one counter-intuitive case,
  // where the machine reaches nothing at all and the reason is an adapter the
  // screen would otherwise never mention. "Protected" and "in clear" are
  // already said by the header chip, word for word — repeating them here would
  // just be filler.
  const explain = posture.posture === 'blocked'
  // Throughput is only shown if it truly exists. As long as telemetry
  // emits nothing, an empty card would be an unfulfilled promise.
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
          {/* The virtual address earns its place next to the endpoint only
              while the tunnel carries it: announcing an address the machine
              does not hold yet would read as a promise. */}
          {meta.active && profile?.address && (
            <Typography
              color="text.disabled"
              sx={{ mt: 0.3, fontFamily: 'monospace', fontSize: 11, overflowWrap: 'anywhere' }}
            >
              {profile.address}
            </Typography>
          )}
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

      {/* Posture: only "blocked". The other two states are already stated
          identically by the header chip; only this one says something the
          chip doesn't — that an adapter is still mounted, that it is what
          blocks the packets, and how to get out of it. */}
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

      {/* The one characteristic that belongs on this screen: what protects
          the traffic. Address, captured range, backend and negotiation
          endpoint are reference material — they live in the posture panel,
          one click away on the header chip, and are not repeated here. */}
      <Box sx={{ pt: 1.5 }}>
        <Tooltip title={protection.detail}>
          <Box
            aria-label={`${protection.label}. ${protection.detail}`}
            sx={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 0.75,
              px: 1,
              py: 0.4,
              borderRadius: 1,
              border: '1px solid',
              borderColor: PROTECTION_SKIN[protection.tone].border,
              bgcolor: PROTECTION_SKIN[protection.tone].fill,
            }}
          >
            <Typography
              sx={{
                color: PROTECTION_SKIN[protection.tone].text,
                fontFamily: 'monospace',
                fontSize: 10.5,
                fontWeight: 600,
                textTransform: 'uppercase',
                letterSpacing: '0.04em',
              }}
            >
              {protection.label}
            </Typography>
          </Box>
        </Tooltip>
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

        {/* The only way out of a mounted adapter with no tunnel, and it has to
            be on screen: the session is over, the primary button offers to
            build another one, and without this the user would have no gesture
            left to take the adapter down — while nothing on the machine
            reaches the network. */}
        {!meta.active && !meta.transitioning && adapterUp && (
          <Button
            fullWidth
            variant="text"
            color="inherit"
            onClick={onDisconnect}
            sx={{ fontSize: 12, textTransform: 'none', color: 'text.secondary' }}
          >
            Démonter l’adaptateur WireGuard
          </Button>
        )}

        {/* The terminal is launched from the **standard-user** token Windows
            keeps linked to Orion's elevated one: Orion is Administrator to
            load the WireGuard driver, and a child built the ordinary way would
            inherit that. Rust refuses to launch until Windows confirms the
            token is not elevated, and the hook then falls back to copying.

            Shown only while the tunnel carries traffic: the gateway answers
            SSH on its tunnel address alone, and offering it earlier would hand
            out a command whose host could resolve elsewhere on the clear
            network. Rust enforces the same gate. */}
        {state === 'up' && profile?.ssh_target && (
          <Button
            fullWidth
            variant="text"
            color="inherit"
            startIcon={<TerminalSquare size={16} aria-hidden />}
            onClick={onOpenSsh}
            sx={{ fontSize: 12, textTransform: 'none', color: 'text.secondary' }}
          >
            Terminal SSH — {profile.ssh_target}
          </Button>
        )}

        {/* Shown only on a tunnel carrying traffic under an ML-KEM PSK: the
            renewal rides that tunnel, and Rust refuses it otherwise. Held
            disabled while one runs: a second renewal on top of the first is
            refused by Rust too, and offering it only invites the click. */}
        {state === 'up' && psk === 'ml_kem' && (
          <Button
            fullWidth
            variant="text"
            color="inherit"
            startIcon={<KeyRound size={16} aria-hidden />}
            onClick={onRenewKey}
            disabled={renewing}
            sx={{ fontSize: 12, textTransform: 'none', color: 'text.secondary' }}
          >
            {renewing
              ? 'Renouvellement en cours de la clé post-quantique…'
              : 'Renouveler la clé post-quantique'}
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

/** Scale shared by both series — see `Sparkline`'s doc-comment. */
function ceilingOf(history: TelemetrySample[]): number {
  return Math.max(1, ...history.map((sample) => Math.max(sample.rx_bps, sample.tx_bps)))
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
