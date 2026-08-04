import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Chip from '@mui/material/Chip'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogTitle from '@mui/material/DialogTitle'
import FormControlLabel from '@mui/material/FormControlLabel'
import IconButton from '@mui/material/IconButton'
import Stack from '@mui/material/Stack'
import Switch from '@mui/material/Switch'
import TextField from '@mui/material/TextField'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { ArrowDownRight, ArrowUpRight, Plus, ShieldAlert, Trash2, UserRound, Wifi } from 'lucide-react'
import { useState } from 'react'
import { admitPeer, revokePeer } from '../api'
import { KnownLimit } from '../components/KnownLimit'
import { Metric } from '../components/Metric'
import { SectionCard } from '../components/SectionCard'
import { formatAge, formatBytes, shortKey } from '../format'
import type { PeerSummary, ProtectionMode, Status } from '../types'

/**
 * Who is connected, and what it took to let them in.
 *
 * This is the screen the console exists for, and until now it did not exist:
 * peers were listed from the configuration file, with no way to tell a client
 * that handshaked a minute ago from one that has been gone for a week, and no
 * way to admit or remove one without an SSH session and `helios-ctl`.
 */

/**
 * How a negotiation floor reads on screen.
 *
 * The floor is not the mode in use — the gateway keeps none — it is what this
 * peer can no longer fall back below. Saying "ML-KEM-1024" alone would suggest
 * an observed state, so the label says "plancher".
 */
const FLOOR: Record<ProtectionMode, { label: string; hint: string; bg: string; fg: string }> = {
  classic: {
    label: 'aucun',
    hint: 'Ce pair peut encore négocier sans PSK. Le plancher s’élèvera de lui-même à la première négociation aboutie.',
    bg: 'transparent',
    fg: 'text.secondary',
  },
  static_psk: {
    label: 'PSK statique',
    hint: 'Une négociation classique est refusée pour ce pair. Ce PSK ne tourne jamais.',
    bg: 'warning.container',
    fg: 'warning.onContainer',
  },
  ml_kem: {
    label: 'ML-KEM-1024',
    hint: 'Ni classique ni PSK statique ne sont acceptés. Seule une édition locale de network.toml peut redescendre ce plancher.',
    bg: 'tertiary.container',
    fg: 'tertiary.onContainer',
  },
}

/** A peer is online when its handshake is fresher than the daemon's threshold. */
function isOnline(peer: PeerSummary, staleAfter: number): boolean {
  return peer.last_handshake_age_seconds !== null && peer.last_handshake_age_seconds < staleAfter
}

function PeerRow({
  peer,
  staleAfter,
  onRevoke,
}: {
  peer: PeerSummary
  staleAfter: number
  onRevoke: (peer: PeerSummary) => void
}) {
  const online = isOnline(peer, staleAfter)
  const floor = FLOOR[peer.minimum_key_negotiation_mode] ?? FLOOR.classic

  return (
    <Box
      sx={{
        display: 'grid',
        gridTemplateColumns: { xs: '1fr', md: '2fr 1.4fr 1.5fr 1.3fr auto' },
        alignItems: 'center',
        gap: 2,
        px: 2.5,
        py: 1.75,
        borderTop: '1px solid',
        borderColor: 'divider',
        '&:hover': { bgcolor: 'surfaceContainer.main' },
      }}
    >
      <Stack direction="row" spacing={1.5} sx={{ alignItems: 'center', minWidth: 0 }}>
        <Box
          sx={{
            width: 8,
            height: 8,
            borderRadius: '50%',
            flexShrink: 0,
            bgcolor: online ? 'state.up.main' : 'state.down.main',
          }}
        />
        <Box sx={{ minWidth: 0 }}>
          <Stack direction="row" spacing={0.75} sx={{ alignItems: 'center' }}>
            <Typography variant="body2" sx={{ fontWeight: 600 }} noWrap>
              {peer.name}
            </Typography>
            {peer.admin && (
              <Chip
                size="small"
                label="admin"
                sx={{ bgcolor: 'primary.container', color: 'primary.onContainer' }}
              />
            )}
          </Stack>
          <Tooltip title={peer.public_key}>
            <Typography
              sx={{ fontFamily: 'monospace', fontSize: '0.6875rem', color: 'text.disabled' }}
            >
              {shortKey(peer.public_key)}
            </Typography>
          </Tooltip>
        </Box>
      </Stack>

      <Box sx={{ minWidth: 0 }}>
        <Typography sx={{ fontFamily: 'monospace', fontSize: '0.8125rem' }} noWrap>
          {peer.address}
        </Typography>
        <Typography
          sx={{ fontFamily: 'monospace', fontSize: '0.6875rem', color: 'text.disabled' }}
          noWrap
        >
          {peer.endpoint ?? 'endpoint inconnu'}
        </Typography>
      </Box>

      <Box>
        <Typography
          variant="body2"
          sx={{ color: online ? 'state.up.main' : 'text.secondary', fontWeight: online ? 600 : 400 }}
        >
          {formatAge(peer.last_handshake_age_seconds)}
        </Typography>
        <Typography variant="caption" sx={{ color: 'text.disabled' }}>
          {online ? 'en ligne' : 'dernier handshake'}
        </Typography>
      </Box>

      <Stack spacing={0.25}>
        <Stack direction="row" spacing={0.75} sx={{ alignItems: 'center', color: 'text.secondary' }}>
          <ArrowDownRight size={13} strokeWidth={2.2} />
          <Typography sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
            {formatBytes(peer.rx_bytes)}
          </Typography>
        </Stack>
        <Stack direction="row" spacing={0.75} sx={{ alignItems: 'center', color: 'text.secondary' }}>
          <ArrowUpRight size={13} strokeWidth={2.2} />
          <Typography sx={{ fontFamily: 'monospace', fontSize: '0.75rem' }}>
            {formatBytes(peer.tx_bytes)}
          </Typography>
        </Stack>
      </Stack>

      <Stack direction="row" spacing={1} sx={{ alignItems: 'center', justifySelf: 'end' }}>
        <Tooltip title={floor.hint}>
          <Chip
            size="small"
            label={floor.label}
            sx={{
              bgcolor: floor.bg,
              color: floor.fg,
              border: floor.bg === 'transparent' ? '1px solid' : 'none',
              borderColor: 'divider',
              fontFamily: 'monospace',
            }}
          />
        </Tooltip>
        <Tooltip title={`Révoquer ${peer.name}`}>
          <IconButton
            size="small"
            onClick={() => onRevoke(peer)}
            aria-label={`Révoquer ${peer.name}`}
            sx={{ color: 'text.disabled', '&:hover': { color: 'error.main' } }}
          >
            <Trash2 size={16} strokeWidth={1.9} />
          </IconButton>
        </Tooltip>
      </Stack>
    </Box>
  )
}

function AdmitDialog({
  open,
  onClose,
  onAdmitted,
}: {
  open: boolean
  onClose: () => void
  onAdmitted: (peer: PeerSummary) => void
}) {
  const [name, setName] = useState('')
  const [publicKey, setPublicKey] = useState('')
  const [fingerprint, setFingerprint] = useState('')
  const [admin, setAdmin] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const reset = () => {
    setName('')
    setPublicKey('')
    setFingerprint('')
    setAdmin(false)
    setError(null)
  }

  const submit = async () => {
    setBusy(true)
    setError(null)
    try {
      const peer = await admitPeer({
        name: name.trim(),
        public_key: publicKey.trim(),
        admin,
        key_negotiation_pq_certificate_sha256: fingerprint.trim() || null,
      })
      onAdmitted(peer)
      reset()
      onClose()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setBusy(false)
    }
  }

  const complete = name.trim().length > 0 && publicKey.trim().length > 0

  return (
    <Dialog open={open} onClose={busy ? undefined : onClose} fullWidth maxWidth="sm">
      <DialogTitle sx={{ pb: 1 }}>Admettre un client</DialogTitle>
      <DialogContent>
        <Stack spacing={2.5} sx={{ pt: 1 }}>
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            La VIP est dérivée de la clé publique par la passerelle — elle ne se choisit pas et ne
            peut donc pas entrer en collision.
          </Typography>

          <TextField
            label="Nom"
            value={name}
            onChange={event => setName(event.target.value)}
            fullWidth
            autoFocus
            placeholder="portable-atelier"
            helperText="Unique sur la passerelle."
          />

          <TextField
            label="Clé publique WireGuard"
            value={publicKey}
            onChange={event => setPublicKey(event.target.value)}
            fullWidth
            placeholder="base64, 44 caractères"
            slotProps={{ input: { sx: { fontFamily: 'monospace', fontSize: '0.8125rem' } } }}
          />

          <TextField
            label="Empreinte du certificat PQ du client"
            value={fingerprint}
            onChange={event => setFingerprint(event.target.value)}
            fullWidth
            placeholder="SHA-256, facultatif"
            helperText="Sa présence choisit à elle seule un plancher ML-KEM. Sans elle, le client négociera d’abord en classique."
            slotProps={{ input: { sx: { fontFamily: 'monospace', fontSize: '0.8125rem' } } }}
          />

          <FormControlLabel
            control={<Switch checked={admin} onChange={event => setAdmin(event.target.checked)} />}
            label={
              <Box>
                <Typography variant="body2" sx={{ fontWeight: 600 }}>
                  Accès d’administration
                </Typography>
                <Typography variant="caption" sx={{ color: 'text.secondary' }}>
                  Autorise ce client à modifier la configuration et à installer des mises à jour.
                </Typography>
              </Box>
            }
          />

          {error && (
            <KnownLimit register="danger" title="Admission refusée">
              {error}
            </KnownLimit>
          )}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2.5 }}>
        <Button color="inherit" onClick={onClose} disabled={busy} sx={{ color: 'text.secondary' }}>
          Annuler
        </Button>
        <Button variant="contained" onClick={() => void submit()} disabled={!complete || busy}>
          {busy ? 'Admission…' : 'Admettre'}
        </Button>
      </DialogActions>
    </Dialog>
  )
}

function RevokeDialog({
  peer,
  onClose,
  onRevoked,
}: {
  peer: PeerSummary | null
  onClose: () => void
  onRevoked: () => void
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const submit = async () => {
    if (!peer) return
    setBusy(true)
    setError(null)
    try {
      await revokePeer(peer.name)
      onRevoked()
      onClose()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={peer !== null} onClose={busy ? undefined : onClose} fullWidth maxWidth="xs">
      <DialogTitle sx={{ pb: 1 }}>Révoquer {peer?.name} ?</DialogTitle>
      <DialogContent>
        <Stack spacing={2}>
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            Ce client perdra l’accès à son prochain handshake. Ce n’est pas une révocation
            cryptographique : il n’existe pas de liste de révocation, et le pair reste hors ligne
            simplement parce que la passerelle ne le connaît plus.
          </Typography>
          {error && (
            <KnownLimit register="danger" title="Révocation refusée">
              {error}
            </KnownLimit>
          )}
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2.5 }}>
        <Button color="inherit" onClick={onClose} disabled={busy} sx={{ color: 'text.secondary' }}>
          Annuler
        </Button>
        <Button variant="contained" color="error" onClick={() => void submit()} disabled={busy}>
          {busy ? 'Révocation…' : 'Révoquer'}
        </Button>
      </DialogActions>
    </Dialog>
  )
}

interface Props {
  status: Status | null
  /** Re-reads the daemon after a mutation. */
  refresh: () => Promise<unknown>
  /** Opened from the header's "Admettre" button. */
  admitOpen: boolean
  onAdmitOpenChange: (open: boolean) => void
}

export function ClientsView({ status, refresh, admitOpen, onAdmitOpenChange }: Props) {
  const [revoking, setRevoking] = useState<PeerSummary | null>(null)
  const peers = status?.peers ?? []
  const staleAfter = status?.handshake_stale_after_seconds ?? 150
  const online = peers.filter(peer => isOnline(peer, staleAfter)).length
  const classic = peers.filter(peer => peer.minimum_key_negotiation_mode === 'classic').length

  return (
    <Stack spacing={2.5}>
      <Box
        sx={{
          display: 'grid',
          gap: 2,
          gridTemplateColumns: { xs: 'repeat(2, 1fr)', md: 'repeat(4, 1fr)' },
        }}
      >
        <Metric label="Admis" value={String(peers.length)} icon={UserRound} />
        <Metric
          label="En ligne"
          value={String(online)}
          icon={Wifi}
          accent={online > 0 ? 'state.up.main' : undefined}
          hint={`Handshake de moins de ${staleAfter} s — le même seuil que celui qui décide de la levée du kill-switch.`}
        />
        <Metric
          label="Trafic reçu"
          icon={ArrowDownRight}
          value={formatBytes(peers.reduce((total, peer) => total + (peer.rx_bytes ?? 0), 0))}
        />
        <Metric
          label="Sans plancher"
          value={String(classic)}
          icon={ShieldAlert}
          accent={classic > 0 ? 'warning.main' : undefined}
          hint="Clients pouvant encore négocier sans PSK. Le plancher s’élève de lui-même à leur première négociation aboutie."
        />
      </Box>

      <SectionCard
        title={`Clients admis (${peers.length})`}
        icon={UserRound}
        action={
          <Button
            variant="contained"
            size="small"
            startIcon={<Plus size={16} />}
            onClick={() => onAdmitOpenChange(true)}
          >
            Admettre
          </Button>
        }
        disableContentPadding
      >
        {peers.length === 0 ? (
          <Box sx={{ px: 2.5, py: 5, textAlign: 'center', borderTop: '1px solid', borderColor: 'divider' }}>
            <Typography variant="body2" sx={{ color: 'text.secondary' }}>
              Aucun client admis. Ajoutez-en un pour qu’il puisse monter un tunnel.
            </Typography>
          </Box>
        ) : (
          peers.map(peer => (
            <PeerRow
              key={peer.public_key}
              peer={peer}
              staleAfter={staleAfter}
              onRevoke={setRevoking}
            />
          ))
        )}
      </SectionCard>

      {status && status.peers.length > 0 && !status.dry_run && peers.every(p => p.rx_bytes === null) && (
        <KnownLimit title="Aucune observation du plan de données">
          L’interface est arrêtée, ou aucun relevé n’a encore eu lieu — le sondeur interroge
          WireGuard toutes les dix secondes. Les colonnes de trafic et de handshake restent vides
          jusque-là plutôt que d’afficher des zéros qui ressembleraient à des mesures.
        </KnownLimit>
      )}

      <AdmitDialog
        open={admitOpen}
        onClose={() => onAdmitOpenChange(false)}
        onAdmitted={() => void refresh()}
      />
      <RevokeDialog
        peer={revoking}
        onClose={() => setRevoking(null)}
        onRevoked={() => void refresh()}
      />
    </Stack>
  )
}
