import Box from '@mui/material/Box'
import Divider from '@mui/material/Divider'
import Popover from '@mui/material/Popover'
import Typography from '@mui/material/Typography'
import { AlertTriangle } from 'lucide-react'
import type { ClientProfile, PskKind, TunnelState } from '../types'
import { modeMeta, postureMeta, protectionMeta, stateMeta } from './state'
import { CopyButton } from './CopyButton'
import { GUTTER } from '../theme'

/**
 * Security posture, in full — what the header chip states in one word.
 *
 * The chip answers "am I protected"; this panel answers "on what grounds",
 * and it is the only place in Orion that does. Everything technical the
 * Connect view used to carry permanently lives here instead: that view has
 * one job, and a line reading `backend wireguard-nt` was never part of it.
 *
 * **The DNS row is permanent, and that is the point.** A client's DNS queries
 * leave outside the tunnel even with the tunnel up — a documented limit of
 * `helios-firewall::ruleset`, not an incident, hence a stated property rather
 * than an alert. It is also the one gap between what "Protégé" suggests and
 * what actually happens, so the panel that justifies the chip is exactly
 * where it belongs.
 */

/** Range that captures all traffic — the one that holds up the fail-open invariant. */
const CAPTURE_ALL = '0.0.0.0/0'

const AMBER = '#A16207'

interface Props {
  /** The chip. `null` closes the panel. */
  anchor: HTMLElement | null
  onClose: () => void
  state: TunnelState
  adapterUp: boolean
  profile: ClientProfile | null
  psk: PskKind | null
  backend: string
}

export function PosturePanel({ anchor, onClose, state, adapterUp, profile, psk, backend }: Props) {
  const posture = postureMeta(state, adapterUp)
  const protection = protectionMeta(profile, psk, state)
  const negotiation = profile?.key_negotiation
  const narrowed = profile ? profile.allowed_ips.trim() !== CAPTURE_ALL : false

  return (
    <Popover
      open={Boolean(anchor)}
      anchorEl={anchor}
      onClose={onClose}
      anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      transformOrigin={{ vertical: 'top', horizontal: 'right' }}
      slotProps={{ paper: { sx: { mt: 0.75, width: 348, maxWidth: '92vw' } } }}
    >
      <Box sx={{ px: GUTTER, py: 1.5 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
          <Box
            aria-hidden
            sx={{ width: 7, height: 7, borderRadius: '50%', flexShrink: 0, bgcolor: posture.accent }}
          />
          <Typography component="h2" sx={{ color: posture.color, fontSize: 13, fontWeight: 700 }}>
            {posture.label}
          </Typography>
        </Box>
        <Typography color="text.secondary" sx={{ mt: 0.4, fontSize: 11.5, lineHeight: 1.5 }}>
          {posture.detail}
        </Typography>
      </Box>

      <Divider />

      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, px: GUTTER, py: 1.5 }}>
        <Row label="tunnel" value={stateMeta(state).label} />
        <Row
          label="adaptateur"
          value={adapterUp ? 'monté' : 'démonté'}
          note={
            adapterUp
              ? 'Tant qu’il est monté, WireGuard jette les paquets faute de handshake — rien ne sort en clair.'
              : 'Le trafic ne passe plus par WireGuard.'
          }
        />
        <Row label="protection" value={protection.label} note={protection.detail} />
        {negotiation && (
          <Row
            label="négociation"
            value={modeMeta(negotiation.mode).label}
            copy={negotiation.endpoint || undefined}
            copyLabel="l’endpoint de négociation"
            note={`Échange authentifié en ML-DSA-65 sur ${negotiation.endpoint || '—'}, avant le montage de WireGuard.`}
          />
        )}
      </Box>

      <Divider />

      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, px: GUTTER, py: 1.5 }}>
        <Row
          label="adresse"
          value={profile?.address ?? '—'}
          copy={profile?.address ?? undefined}
          copyLabel="l’adresse virtuelle"
        />
        <Row
          label="trafic capté"
          value={profile?.allowed_ips ?? '—'}
          tone={narrowed ? AMBER : undefined}
          note={
            narrowed
              ? 'Plage restreinte : ce qui en sort part en clair. 0.0.0.0/0 capte tout.'
              : undefined
          }
        />
        {/* Permanent, tunnel up or down: it is a property of the product. */}
        <Row
          label="DNS"
          value="hors tunnel"
          note="Les requêtes DNS de ce poste ne passent pas par Helios, même tunnel monté : le résolveur du réseau local voit les noms consultés. Le contenu des échanges, lui, reste chiffré."
        />
        <Row label="backend" value={backend || '—'} />
      </Box>
    </Popover>
  )
}

/**
 * One fact: its instrument label, its value, and why it matters.
 *
 * `note` is not optional prose — it carries what the value alone gets wrong.
 * A row that needs no explanation simply omits it rather than filling the
 * space with a paraphrase.
 */
function Row({
  label,
  value,
  note,
  tone,
  copy,
  copyLabel,
}: {
  label: string
  value: string
  note?: string
  /** Overrides the value's color when the fact itself is a caution. */
  tone?: string
  /** Value handed to the clipboard, when it is one worth carrying out. */
  copy?: string
  copyLabel?: string
}) {
  return (
    <Box sx={{ minWidth: 0 }}>
      <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 0.75, minWidth: 0 }}>
        <Typography
          color="text.disabled"
          sx={{
            width: 76,
            flexShrink: 0,
            fontFamily: 'monospace',
            fontSize: 9.5,
            letterSpacing: '0.08em',
            textTransform: 'uppercase',
          }}
        >
          {label}
        </Typography>
        <Typography
          sx={{
            minWidth: 0,
            color: tone ?? 'text.primary',
            fontFamily: 'monospace',
            fontSize: 11,
            overflowWrap: 'anywhere',
          }}
        >
          {value}
        </Typography>
        {tone && <AlertTriangle size={12} aria-hidden style={{ color: tone, flexShrink: 0 }} />}
        {copy && (
          <Box sx={{ ml: 'auto' }}>
            <CopyButton value={copy} label={copyLabel ?? label} />
          </Box>
        )}
      </Box>
      {note && (
        <Typography
          color="text.secondary"
          sx={{ mt: 0.25, ml: '84px', fontSize: 10.5, lineHeight: 1.5 }}
        >
          {note}
        </Typography>
      )}
    </Box>
  )
}
