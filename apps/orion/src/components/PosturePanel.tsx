import Box from '@mui/material/Box'
import Divider from '@mui/material/Divider'
import Popover from '@mui/material/Popover'
import Typography from '@mui/material/Typography'
import { AlertTriangle } from 'lucide-react'
import type { CaptureCheck, ClientProfile, PskKind, TunnelState, VaultPosture } from '../types'
import { modeMeta, postureMeta, protectionMeta, stateMeta } from './state'
import { CopyButton } from './CopyButton'
import { GUTTER } from '../theme'

/**
 * Security posture, in short — what the header chip states in one word.
 *
 * The chip answers "am I protected"; this panel answers "on what grounds".
 * It carries values, not prose: a row states a fact and nothing else, and a
 * fact that needs a paragraph to be worth reading does not belong on a screen
 * whose whole job is to be scanned in two seconds.
 *
 * **The vault block is alerts only.** Rows that describe a healthy vault —
 * secrets sealed to the TPM, volume encrypted, memory locked — told the user
 * nothing they could act on, and pushed the rows that *do* matter below the
 * fold. What is nominal is silent; what is degraded appears.
 */

const AMBER = '#A16207'

interface Props {
  /** The chip. `null` closes the panel. */
  anchor: HTMLElement | null
  onClose: () => void
  state: TunnelState
  adapterUp: boolean
  profile: ClientProfile | null
  psk: PskKind | null
  /**
   * What the core read back from the mounted adapter. `null` when there is no
   * verdict — nothing mounted, or the simulation — and the row then shows the
   * profile's list without claiming anything about it.
   */
  capture: CaptureCheck | null
  /**
   * What the vault can claim about itself. `null` while it is being read, or
   * when it could not be — in which case the rows simply do not appear.
   *
   * Passed in rather than fetched here: this component is presentational, and
   * the shell already owns every other fact it displays. Fetching inside would
   * also make it untestable without a Tauri runtime.
   */
  vault: VaultPosture | null
}

export function PosturePanel({
  anchor,
  onClose,
  state,
  adapterUp,
  profile,
  psk,
  capture,
  vault,
}: Props) {
  const posture = postureMeta(state, adapterUp)
  const protection = protectionMeta(profile, psk, state)
  const traffic = trafficFact(profile, capture)
  const address = addressFact(profile, capture)
  const negotiation = profile?.key_negotiation
  // Nominal is silent: the block only exists when it has something to report.
  const degraded =
    vault !== null &&
    (!vault.hardwareBacked ||
      !vault.volumeProtected ||
      !vault.memoryLocked ||
      !vault.dumpsExcluded ||
      vault.legacyPresent ||
      vault.rotationRequired.length > 0)

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
      </Box>

      <Divider />

      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, px: GUTTER, py: 1.5 }}>
        <Row label="tunnel" value={stateMeta(state).label} />
        <Row label="protection" value={protection.label} />
        {negotiation && (
          <Row
            label="négociation"
            // The endpoint sits in the value rather than behind the copy
            // button alone: a button that carries a string the panel never
            // shows copies something the user cannot check.
            value={
              negotiation.endpoint
                ? `${modeMeta(negotiation.mode).label} · ${negotiation.endpoint}`
                : modeMeta(negotiation.mode).label
            }
            copy={negotiation.endpoint || undefined}
            copyLabel="l’endpoint de négociation"
          />
        )}
        <Row
          label="adresse"
          value={address.value}
          tone={address.tone}
          copy={address.copy}
          copyLabel={address.count > 1 ? 'les adresses virtuelles' : 'l’adresse virtuelle'}
        />
        {/* Amber only for what the machine reports: see `trafficFact`. */}
        <Row label="trafic via le tunnel" value={traffic.value} tone={traffic.tone} />
      </Box>

      {degraded && vault && (
        <>
          <Divider />
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1, px: GUTTER, py: 1.5 }}>
            {!vault.hardwareBacked && (
              <Row label="secrets" value="scellés au compte uniquement" tone={AMBER} />
            )}
            {!vault.volumeProtected && (
              <Row
                label="volume"
                value={vault.unencryptedVolumeWaived ? 'non chiffré' : 'non couvert'}
                tone={AMBER}
              />
            )}
            {!vault.memoryLocked && <Row label="mémoire" value="non verrouillée" tone={AMBER} />}
            {/* Defence in depth, so it is stated without an amber tone: the
                exclusion covers WER reports only, never a debugger. */}
            {!vault.dumpsExcluded && <Row label="vidages" value="non exclus" />}
            {vault.legacyPresent && (
              <Row label="migration" value="fichier en clair présent" tone={AMBER} />
            )}
            {vault.rotationRequired.length > 0 && (
              <Row
                label="rotation"
                value={`${vault.rotationRequired.join(', ')} — conseillée`}
                tone={AMBER}
              />
            )}
          </Box>
        </>
      )}
    </Popover>
  )
}

/**
 * The «trafic via le tunnel» row: what the profile asks for, unless the
 * machine says otherwise.
 *
 * No amber for a narrowed range. Split tunnelling is a decision the operator
 * made — routing a subnet and leaving the rest alone is the normal shape of a
 * corporate profile, not a degradation. Amber is for facts the machine reports
 * about itself, most severe first:
 *
 * 1. the driver applied less than asked — read back by the core after
 *    mounting. On Windows a family the adapter does not carry is dropped
 *    without an error, and that traffic leaves through the physical
 *    interface while everything else looks connected;
 * 2. the read-back failed: unknown is not fine;
 * 3. `0.0.0.0/0` alone, the full tunnel as it was before `::/0` joined the
 *    default: on a dual-stack machine its IPv6 leaves in clear with the tunnel
 *    up. The core decides which profiles that is; the list is never rewritten
 *    for the user.
 */
function trafficFact(
  profile: ClientProfile | null,
  capture: CaptureCheck | null,
): { value: string; tone?: string } {
  if (capture?.status === 'incomplete' && capture.missing.length > 0) {
    const verb = capture.missing.length > 1 ? 'non appliqués' : 'non appliqué'
    return { value: `${capture.missing.join(', ')} ${verb} par le pilote — hors tunnel`, tone: AMBER }
  }
  if (capture?.status === 'unverified') {
    return { value: `${profile?.allowed_ips ?? '—'} — non vérifié sur l’adaptateur`, tone: AMBER }
  }
  if (profile?.ipv6_uncaptured_full_tunnel) {
    return { value: `${profile.allowed_ips} — IPv4 seulement, l’IPv6 sort en clair`, tone: AMBER }
  }
  return { value: profile?.allowed_ips ?? '—' }
}

/**
 * The «adresse» row: the profile's addresses, IPv4 first, then IPv6 when the
 * profile has one — unless the machine says the driver left one off.
 *
 * A profile without `address_v6` reads exactly as before. The amber case is
 * the same kind of fact as a stripped prefix: on Windows, the IPv6 address of
 * an adapter without IPv6 is skipped without an error, and only the core's
 * read-back knows. The copy carries what the row shows, never the gap.
 */
function addressFact(
  profile: ClientProfile | null,
  capture: CaptureCheck | null,
): { value: string; tone?: string; copy?: string; count: number } {
  const addresses = [profile?.address, profile?.address_v6].filter(
    (address): address is string => Boolean(address),
  )
  if (addresses.length === 0) return { value: '—', count: 0 }
  const listed = addresses.join(', ')
  if (capture?.status === 'incomplete' && capture.missing_addresses.length > 0) {
    const verb = capture.missing_addresses.length > 1 ? 'non posées' : 'non posée'
    return {
      value: `${listed} — ${capture.missing_addresses.join(', ')} ${verb} par le pilote`,
      tone: AMBER,
      copy: listed,
      count: addresses.length,
    }
  }
  return { value: listed, copy: listed, count: addresses.length }
}

/** One fact: its instrument label and its value. */
function Row({
  label,
  value,
  tone,
  copy,
  copyLabel,
}: {
  label: string
  value: string
  /** Overrides the value's color when the fact itself is a caution. */
  tone?: string
  /** Value handed to the clipboard, when it is one worth carrying out. */
  copy?: string
  copyLabel?: string
}) {
  return (
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
  )
}
