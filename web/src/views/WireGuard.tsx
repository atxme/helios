import Box from '@mui/material/Box'
import Chip from '@mui/material/Chip'
import Stack from '@mui/material/Stack'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { KeyRound, Lock, Network, RadioTower } from 'lucide-react'
import { Metric } from '../components/Metric'
import { SectionCard } from '../components/SectionCard'
import type { PeerSummary, ProtectionMode, Status } from '../types'

/**
 * How a floor reads on screen.
 *
 * The floor is not the mode currently in use — the gateway doesn't keep one —
 * it's what this peer can no longer fall back below. Saying "ML-KEM-1024"
 * alone would suggest an observed state; the label says "plancher".
 *
 * The three tones form a ladder of *commitment*, not of quality: an outline
 * for a peer that has committed to nothing, a caution tone for a floor that
 * holds but never rotates, and the tertiary accent for the one floor that
 * refuses everything below ML-KEM.
 */
const FLOOR: Record<ProtectionMode, { label: string; hint: string; bg: string; fg: string }> = {
  classic: {
    label: 'plancher : aucun',
    hint: 'Ce pair peut encore négocier sans PSK. Le plancher s’élèvera de lui-même à la première négociation aboutie.',
    bg: 'transparent',
    fg: 'text.secondary',
  },
  static_psk: {
    label: 'plancher : PSK statique',
    hint: 'Une négociation classique est refusée pour ce pair, avant toute pose sur le plan de données. Ce PSK ne tourne jamais.',
    bg: 'warning.container',
    fg: 'warning.onContainer',
  },
  ml_kem: {
    label: 'plancher : ML-KEM-1024',
    hint: 'Ni classique ni PSK statique ne sont acceptés pour ce pair. Seule une édition locale de network.toml peut redescendre ce plancher.',
    bg: 'tertiary.container',
    fg: 'tertiary.onContainer',
  },
}

function shortKey(key: string): string {
  return key.length <= 20 ? key : `${key.slice(0, 10)}…${key.slice(-8)}`
}

function ToneChip({ label, hint, bg, fg }: { label: string; hint: string; bg: string; fg: string }) {
  return (
    <Tooltip title={hint}>
      <Chip
        size="small"
        label={label}
        sx={{
          bgcolor: bg,
          color: fg,
          border: bg === 'transparent' ? '1px solid' : 'none',
          borderColor: 'divider',
          fontFamily: 'monospace',
          fontSize: '0.6875rem',
        }}
      />
    </Tooltip>
  )
}

function PeerRow({ peer }: { peer: PeerSummary }) {
  const floor = FLOOR[peer.minimum_key_negotiation_mode] ?? FLOOR.classic

  return (
    <Stack
      direction="row"
      spacing={2}
      sx={{
        alignItems: 'center',
        flexWrap: 'wrap',
        rowGap: 1.5,
        px: 3,
        py: 2,
        borderBottom: '1px solid',
        borderColor: 'divider',
        '&:last-of-type': { borderBottom: 0 },
      }}
    >
      <Box sx={{ color: 'text.disabled', display: 'flex' }}>
        <KeyRound size={18} strokeWidth={1.6} />
      </Box>

      <Box sx={{ minWidth: 180, flex: 1 }}>
        <Stack direction="row" spacing={1} sx={{ alignItems: 'center' }}>
          <Typography variant="body2" sx={{ fontWeight: 600 }}>
            {peer.name}
          </Typography>
          {peer.admin && (
            <Chip
              size="small"
              label="admin"
              sx={{ bgcolor: 'secondary.container', color: 'secondary.onContainer', fontSize: '0.6875rem' }}
            />
          )}
        </Stack>
        <Tooltip title={peer.public_key}>
          <Typography
            sx={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'text.secondary', mt: 0.25 }}
          >
            {shortKey(peer.public_key)}
          </Typography>
        </Tooltip>
      </Box>

      <Typography sx={{ fontFamily: 'monospace', fontSize: '0.8125rem', flexShrink: 0 }}>
        {peer.address}
      </Typography>

      <ToneChip {...floor} />

      <ToneChip
        label={peer.post_quantum ? 'slot PSK occupé' : 'slot PSK vide'}
        hint={
          peer.post_quantum
            ? 'Un secret occupe le slot PresharedKey de ce pair. Sa valeur n’est jamais exposée par l’API.'
            : 'Aucun PSK posé : la confidentialité repose sur Curve25519 seul.'
        }
        bg={peer.post_quantum ? 'tertiary.container' : 'transparent'}
        fg={peer.post_quantum ? 'tertiary.onContainer' : 'text.secondary'}
      />
    </Stack>
  )
}

function Explanation({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Box sx={{ mb: 2, '&:last-of-type': { mb: 0 } }}>
      <Typography variant="body2" sx={{ color: 'text.secondary' }}>
        <Box component="strong" sx={{ color: 'text.primary' }}>
          {title}
        </Box>{' '}
        {children}
      </Typography>
    </Box>
  )
}

export function WireGuardView({ status }: { status: Status | null }) {
  const negotiation = status?.key_negotiation_port ?? null
  const peers = status?.peers ?? []

  return (
    <Stack spacing={2.5}>
      <Box
        sx={{
          display: 'grid',
          gap: 2,
          gridTemplateColumns: { xs: 'repeat(2, 1fr)', md: 'repeat(3, 1fr)' },
        }}
      >
        <Metric label="Interface" value={status?.wg_iface || '—'} icon={RadioTower} />
        <Metric
          label="Écoute"
          value={status?.wg_listen_port ? `UDP ${status.wg_listen_port}` : 'fermée'}
          icon={Network}
        />
        <Metric
          label="Négociation"
          value={negotiation ? `UDP ${negotiation}` : 'inactive'}
          icon={Lock}
          hint="Seul key_negotiation_port décide de l’ouverture du service. Absent, il reste fermé, sans erreur."
        />
      </Box>

      <SectionCard
        title={`Clients admis (${peers.length})`}
        subtitle="Admis hors bande par helios-ctl peer add ; ce port n’étend jamais la liste."
        disableContentPadding
      >
        {!status ? (
          <Box sx={{ px: 3, py: 4 }}>
            <Typography variant="body2" sx={{ color: 'text.disabled' }}>
              Statut non encore reçu du démon.
            </Typography>
          </Box>
        ) : peers.length === 0 ? (
          <Box sx={{ px: 3, py: 4 }}>
            <Typography variant="body2" sx={{ color: 'text.secondary' }}>
              Aucun pair déclaré dans <code>network.toml</code>.
            </Typography>
          </Box>
        ) : (
          <Box sx={{ borderTop: '1px solid', borderColor: 'divider' }}>
            {peers.map(peer => (
              <PeerRow key={peer.public_key} peer={peer} />
            ))}
          </Box>
        )}
      </SectionCard>

      <SectionCard
        title="Négociation de clé"
        subtitle={
          <>
            Port public {negotiation ? <code>UDP {negotiation}</code> : 'non ouvert'} — il ne transporte
            aucun trafic utilisateur, il prépare le slot PSK du <em>premier</em> handshake WireGuard.
          </>
        }
      >
        <Box
          sx={{
            display: 'grid',
            gap: 3,
            gridTemplateColumns: { xs: '1fr', sm: 'repeat(3, 1fr)' },
            mb: 3,
          }}
        >
          <Field
            label="Ancre d’authentification"
            value="ML-DSA-65"
            note="Requête, réponse, confirmation et commit sont signés. TLS 1.3 mutuel reste le transport QUIC, il n’est plus l’ancre : casser ECDSA ne permet ni de substituer kpub, ni de modifier le ciphertext."
          />
          <Field
            label="Établissement du secret"
            value="ML-KEM-1024"
            note="Orion génère la paire éphémère, Helios encapsule. HKDF lie le PSK à la version, au mode, à la transaction, aux deux nonces et aux deux identités WireGuard."
          />
          <Field
            label="Ordre de pose"
            value="poser puis annoncer"
            note="Le slot est posé sur le plan de données avant la réponse. Si aucun handshake ne réussit avec ce PSK, puis n’est confirmé par signature, Helios restaure le slot précédent."
          />
        </Box>

        <Typography variant="overline" sx={{ color: 'text.secondary' }}>
          Modes acceptés
        </Typography>
        <Box
          sx={{
            display: 'grid',
            gap: 1.5,
            gridTemplateColumns: { xs: '1fr', sm: 'repeat(3, 1fr)' },
            mt: 1,
            mb: 3,
          }}
        >
          <Mode name="classic" detail="Slot PSK vidé. Aucune protection contre « récolter maintenant, déchiffrer plus tard »." />
          <Mode name="static_psk" detail="PSK déjà configuré, retrouvé par comparaison d’empreinte. Il ne tourne jamais." />
          <Mode name="ml_kem" detail="PSK frais dérivé à chaque connexion, jamais écrit sur disque." />
        </Box>

        <Explanation title="La sécurité ne redescend jamais.">
          Chaque pair porte un plancher, montré ci-dessus. Une demande située en dessous est refusée
          <em> avant</em> toute modification du plan de données, et chaque négociation aboutie élève le
          plancher au mode utilisé — y compris après redémarrage. Aucun message réseau ni aucune
          renégociation ne peut l’abaisser : seule une édition locale de <code>network.toml</code> le peut.
        </Explanation>
        <Explanation title="Deux ports à rediriger.">
          <code>UDP {status?.wg_listen_port ?? 51820}</code> pour WireGuard et{' '}
          <code>UDP {negotiation ?? 51821}</code> pour la négociation. Sans le second, les clients
          retombent sur l’ancien chemin : tunnel classique d’abord, PSK ensuite — son premier handshake
          n’est alors pas protégé.
        </Explanation>
        <Explanation title="Rotation à chaud, non.">
          L’identité de négociation est lue une fois au démarrage et servie jusqu’à l’arrêt. Après un{' '}
          <code>init-key-negotiation --rotate</code>, les profils émis épinglent un certificat que la
          passerelle ne sert pas encore, et le client refuse le handshake QUIC sur{' '}
          <code>BadSignature</code>. Une rotation s’applique par <code>systemctl restart heliosd</code>.
        </Explanation>
      </SectionCard>

      <SectionCard
        title="Enrôlement hérité"
        subtitle={
          <>
            <code>POST /api/provision</code> — joignable uniquement à travers le tunnel, comme le reste
            de cette interface.
          </>
        }
      >
        <Box
          sx={{
            display: 'grid',
            gap: 3,
            gridTemplateColumns: { xs: '1fr', sm: 'repeat(3, 1fr)' },
            mb: 3,
          }}
        >
          <Field
            label="Échange de clés"
            value="ML-KEM-1024"
            note="Le secret alimente le slot PresharedKey de WireGuard, sans toucher au handshake."
          />
          <Field
            label="Plage d’adressage"
            value="100.64.0.0/10"
            note="VIP CGNAT dérivée de la clé publique du pair. Aucun état sur disque."
          />
          <Field
            label="Durée de vie du PSK"
            value="3600 s"
            note="Au-delà, le client redemande un PSK par un nouvel échange."
          />
        </Box>

        <Explanation title="Chemin de compatibilité, plus le chemin nominal.">
          Ce provisioning exige un tunnel déjà monté : il ne peut donc pas protéger le premier
          handshake, celui qu’un adversaire enregistre aujourd’hui pour le déchiffrer plus tard. Il
          reste servi pour les profils Orion dépourvus de bloc de négociation.
        </Explanation>
        <Explanation title="Provisioning post-quantique.">
          Le PSK est dérivé par ML-KEM-1024 puis posé sur le pair <em>avant</em> d’être annoncé au
          client : un PSK présent d’un seul côté ferait échouer tous les handshakes. En cas d’échec, la
          demande est refusée et le tunnel reste classique.
        </Explanation>
      </SectionCard>
    </Stack>
  )
}

function Mode({ name, detail }: { name: string; detail: string }) {
  return (
    <Box sx={{ px: 2, py: 1.5, borderRadius: '12px', bgcolor: 'surfaceContainer.high' }}>
      <Typography sx={{ fontFamily: 'monospace', fontSize: '0.8125rem', fontWeight: 600 }}>
        {name}
      </Typography>
      <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mt: 0.5 }}>
        {detail}
      </Typography>
    </Box>
  )
}

function Field({ label, value, note }: { label: string; value: string; note: string }) {
  return (
    <Box>
      <Typography variant="overline" sx={{ color: 'text.secondary' }}>
        {label}
      </Typography>
      <Typography sx={{ fontFamily: 'monospace', fontSize: '0.875rem', fontWeight: 600, mt: 0.25 }}>
        {value}
      </Typography>
      <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', mt: 0.75 }}>
        {note}
      </Typography>
    </Box>
  )
}
