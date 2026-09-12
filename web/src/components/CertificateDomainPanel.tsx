import Box from '@mui/material/Box'
import Chip from '@mui/material/Chip'
import Skeleton from '@mui/material/Skeleton'
import Stack from '@mui/material/Stack'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { BadgeCheck, CalendarClock, Fingerprint, KeyRound, Users } from 'lucide-react'
import { useEffect, useState } from 'react'
import { fetchCertificateDomain } from '../api'
import { shortKey } from '../format'
import type { CertificateDomain, CertificatePhase, PeerCertificateView } from '../types'
import { DataRow } from './DataRow'
import { GatewayIdentityActions } from './GatewayIdentityActions'
import { KnownLimit } from './KnownLimit'
import { SectionCard } from './SectionCard'

/**
 * The certificate lifecycle, as the operator of a gateway reads it (ADR-008).
 *
 * # What this screen is for
 *
 * One question, asked often and answerable nowhere else: *is every admitted
 * client's identity still going to be there next month*. The answer is a
 * generation, an expiry and a rung on the renewal ladder, per peer, beside the
 * epochs those identities were issued under.
 *
 * # Why the phases are not computed here
 *
 * The 80 / 90 / 95 % thresholds of spec §4.3 arrive already applied, against
 * the **gateway's** clock. Two reasons, and both have bitten interfaces
 * before: an operator workstation minutes off would place every leaf on the
 * wrong rung, and a screen doing its own arithmetic drifts from the planner
 * that actually schedules renewals — at which point the screen is believed and
 * the planner is not.
 */

interface PhaseSkin {
  label: string
  tone: string
  container: string
  onContainer: string
  hint: string
  severity: number
}

/**
 * The same six rungs Orion names, in the same words.
 *
 * Deliberately identical: an operator on the console and a user in Orion are
 * looking at the same certificate, and two vocabularies for one state is how a
 * support call spends ten minutes establishing that they agree.
 */
const PHASE: Record<CertificatePhase, PhaseSkin> = {
  not_yet_valid: {
    label: 'pas encore valide',
    tone: 'state.connecting.main',
    container: 'state.connecting.container',
    onContainer: 'state.connecting.onContainer',
    hint: 'Préparé pour plus tard : sa validité n’a pas commencé.',
    severity: 1,
  },
  valid: {
    label: 'valide',
    tone: 'state.up.main',
    container: 'state.up.container',
    onContainer: 'state.up.onContainer',
    hint: 'Dans sa période de validité, avant les 80 % qui ouvrent le renouvellement.',
    severity: 0,
  },
  renewal_due: {
    label: 'renouvellement ouvert',
    tone: 'warning.main',
    container: 'warning.container',
    onContainer: 'warning.onContainer',
    hint: 'Passé 80 % de sa durée de vie : c’est la fenêtre où le renouvellement doit avoir lieu.',
    severity: 2,
  },
  warning: {
    label: 'renouvellement en retard',
    tone: 'warning.main',
    container: 'warning.container',
    onContainer: 'warning.onContainer',
    hint: 'Passé 90 % de sa durée de vie. Le renouvellement aurait dû aboutir.',
    severity: 3,
  },
  critical: {
    label: 'expiration imminente',
    tone: 'state.failed.main',
    container: 'state.failed.container',
    onContainer: 'state.failed.onContainer',
    hint: 'Passé 95 % de sa durée de vie. À l’échéance, ce client échoue avant WireGuard.',
    severity: 4,
  },
  expired: {
    label: 'expiré',
    tone: 'state.failed.main',
    container: 'state.failed.container',
    onContainer: 'state.failed.onContainer',
    hint: 'Hors validité : ce client échoue avant WireGuard et ne peut plus demander d’aide par le tunnel.',
    severity: 5,
  },
}

/** A date in Europe/Paris civil time, from a Unix instant. */
function formatDate(unix: number): string {
  return new Date(unix * 1000).toLocaleString('fr-FR', {
    dateStyle: 'medium',
    timeStyle: 'short',
    timeZone: 'Europe/Paris',
  })
}

/**
 * A delay stated in whole days, or in hours when a day would round it away.
 *
 * Negative is kept and shown as such: "expiré depuis 3 j" is the fact, and a
 * clamp to zero would report an expired identity as expiring today.
 */
function formatDelay(seconds: number): string {
  const past = seconds < 0
  const absolute = Math.abs(seconds)
  const days = Math.floor(absolute / 86400)
  const spoken =
    days >= 1 ? `${days} j` : absolute >= 3600 ? `${Math.floor(absolute / 3600)} h` : '< 1 h'
  return past ? `expiré depuis ${spoken}` : `dans ${spoken}`
}

function PhaseChip({ phase }: { phase: CertificatePhase }) {
  const skin = PHASE[phase]
  return (
    <Tooltip title={skin.hint}>
      <Chip
        size="small"
        label={skin.label}
        sx={{ bgcolor: skin.container, color: skin.onContainer, fontWeight: 600 }}
      />
    </Tooltip>
  )
}

/**
 * The transitions in flight, with the two instants that decide them.
 *
 * # Why this is not a chip saying « en cours »
 *
 * A staged transition is a decision already taken, waiting on two instants an
 * operator has to plan around: `activation_at`, when both halves start being
 * accepted, and `not_after`, when the outgoing one is destroyed and — for the
 * gateway identity — a restart becomes mandatory. Those instants live in the
 * domain view and were reachable nowhere on this screen: they appeared once,
 * in the echo of the document that had just been pasted, and a reload lost
 * them. An operator asking «quand est-ce que ça bascule» had to go back to the
 * CLI to answer.
 *
 * # Why `published` is stated rather than implied
 *
 * It is the door of §6.3 closing. Before distribution a transition can be
 * aborted and its epoch consumed; after it, the only thing left is the bounded
 * rollback of §4.4. Those are two different sets of options, and which one the
 * operator has is not something to deduce from a date.
 *
 * Nothing pending renders nothing at all: a domain at rest must not leave a
 * card of dashes on the screen, and what stays visible is what somebody has to
 * look at.
 */
function TransitionTimeline({ domain }: { domain: CertificateDomain }) {
  const anything =
    domain.ca_transition_pending ||
    domain.client_tls_ca_transition_pending ||
    domain.gateway_transition_pending ||
    domain.gateway_rollback_expires_at !== null
  if (!anything) return null

  const now = domain.now_unix
  const at = (unix: number | null): string =>
    unix === null ? '—' : `${formatDate(unix)} · ${formatDelay(unix - now)}`

  return (
    <SectionCard
      title="Transitions en cours"
      subtitle="Un successeur est installé. Rien ne bascule avant son instant d’activation."
      icon={CalendarClock}
      accent="tertiary.main"
    >
      <Box>
        {domain.ca_transition_pending && (
          <>
            <DataRow
              label="CA-PQ"
              value={`époque ${domain.ca_epoch} → ${domain.ca_epoch + 1}`}
              hint="L’époque ne bouge qu’au retrait de l’ancre sortante, par la même passe qui promeut les générations clientes."
            />
            <DataRow
              label="Ancre entrante"
              value={domain.next_ca_fingerprint}
              hint="À comparer avec l’empreinte qu’affiche le compagnon : au §9.1, c’est cette comparaison qui fait foi, pas la signature seule."
              wrap
            />
            <DataRow
              label="Activation CA-PQ"
              value={at(domain.ca_activation_at)}
              hint="À partir de cet instant les deux ancres vérifient."
            />
            <DataRow
              label="Retrait CA-PQ"
              value={at(domain.ca_retire_active_at)}
              hint="L’ancre sortante est retirée et l’époque avance."
            />
          </>
        )}

        {domain.client_tls_ca_transition_pending && (
          <DataRow
            label="CA TLS cliente"
            value={`époque ${domain.client_tls_ca_epoch} → ${domain.client_tls_ca_epoch + 1}`}
            hint="Une CA TLS cliente suivante est installée. Elle est refusée sans signature CA-PQ et ne peut pas précéder la persistance gateway."
          />
        )}

        {domain.gateway_transition_pending && (
          <>
            <DataRow
              label="Identité gateway"
              value={`époque ${domain.gateway_identity_epoch} → ${
                domain.gateway_identity_epoch + 1
              }`}
              hint="La feuille servie ne change pas ici : le basculement appartient à activation_at et demande un redémarrage."
            />
            <DataRow
              label="Activation gateway"
              value={at(domain.gateway_activation_at)}
              hint="Début du chevauchement : les deux feuilles sont acceptées."
            />
            <DataRow
              label="Retrait gateway"
              value={at(domain.gateway_retire_active_at)}
              hint="Fin du chevauchement : la feuille sortante est détruite et la suivante promue."
            />
            <DataRow
              label="Distribution"
              value={
                domain.gateway_transition_published
                  ? 'distribuée — l’avortement n’est plus accepté'
                  : 'non distribuée — encore annulable'
              }
              hint="§6.3 : l’avortement n’est accepté que tant que rien n’a été distribué. Passé ce point il ne reste que le rollback borné du §4.4."
            />
          </>
        )}

        {domain.gateway_rollback_expires_at !== null && (
          <DataRow
            label="Rollback en force"
            value={`ancienne feuille servie · jusqu’à ${at(domain.gateway_rollback_expires_at)}`}
            hint="Rollback de service, pas d’état : aucun compteur ne bouge et la promotion a lieu comme prévu. Son expiration est elle aussi un redémarrage."
          />
        )}
      </Box>
    </SectionCard>
  )
}

/**
 * One admitted client's identity.
 *
 * The transient rows — a candidate under lease, a committed successor, queued
 * fragments — appear only while they exist. A renewal that is not happening
 * must not leave three permanent dashes on every row: nominal is silent, and
 * what is left on screen is what somebody has to look at.
 */
function PeerRow({ peer, now }: { peer: PeerCertificateView; now: number }) {
  return (
    <Box
      sx={{
        py: 1.5,
        borderBottom: '1px solid',
        borderColor: 'divider',
        '&:last-of-type': { borderBottom: 0 },
      }}
    >
      <Stack
        direction="row"
        spacing={1.5}
        sx={{ alignItems: 'center', flexWrap: 'wrap', rowGap: 1 }}
      >
        <Typography sx={{ fontWeight: 600, minWidth: 0 }}>{peer.name}</Typography>
        <Tooltip title={peer.wg_public_key}>
          <Typography
            sx={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'text.secondary' }}
          >
            {shortKey(peer.wg_public_key)}
          </Typography>
        </Tooltip>
        <Box sx={{ flex: 1 }} />
        {peer.revoked && (
          <Tooltip title="Identité révoquée : ce pair ne négocie plus.">
            <Chip
              size="small"
              label="révoqué"
              sx={{
                bgcolor: 'state.failed.container',
                color: 'state.failed.onContainer',
                fontWeight: 600,
              }}
            />
          </Tooltip>
        )}
        <PhaseChip phase={peer.phase} />
      </Stack>

      <Box sx={{ mt: 0.5 }}>
        <DataRow
          label="Génération"
          value={String(peer.generation)}
          hint="Compteur d’identité du pair. Il avance d’exactement un par renouvellement abouti ; un saut est refusé."
        />
        <DataRow
          label="Échéance"
          value={`${formatDate(peer.not_after)} · ${formatDelay(peer.not_after - now)}`}
        />
        {peer.pending && (
          <DataRow
            label="En cours"
            value={`génération ${peer.pending.generation} · ${
              peer.pending.state === 'pending_grant' ? 'attend le grant' : 'attend le commit'
            }`}
            hint="Un candidat sous bail. « attend le grant » : la gateway l’a persisté, le client n’a rien reçu. « attend le commit » : le client détient le grant et n’a pas encore committé."
          />
        )}
        {peer.next_generation !== null && (
          <DataRow
            label="Suivante"
            value={
              peer.activation_at !== null
                ? `génération ${peer.next_generation} · active le ${formatDate(peer.activation_at)}`
                : `génération ${peer.next_generation}`
            }
            hint="Committée et en attente de son instant d’activation. Les deux identités sont acceptées pendant le chevauchement."
          />
        )}
        {peer.distribution_chunks_pending > 0 && (
          <DataRow
            label="À distribuer"
            value={`${peer.distribution_chunks_pending} fragment${
              peer.distribution_chunks_pending > 1 ? 's' : ''
            }`}
            hint="Fragments d’une transaction signée que ce pair n’a pas encore collectés. Il les récupère un par requête trust-update fraîche."
          />
        )}
      </Box>
    </Box>
  )
}

export function CertificateDomainPanel() {
  const [domain, setDomain] = useState<CertificateDomain | null>(null)
  const [absent, setAbsent] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchCertificateDomain()
      .then(answer => {
        if (answer === null) setAbsent(true)
        else setDomain(answer)
      })
      .catch((cause: unknown) => setError(cause instanceof Error ? cause.message : 'illisible'))
  }, [])

  if (error) {
    return (
      <KnownLimit register="danger" title="Registre de certificats illisible">
        Le démon ne répond pas sur <code>/api/certificates</code> — {error}
      </KnownLimit>
    )
  }

  // Not an error, and not an empty domain either: without `CA-PQ` there is no
  // anchor to verify anything against, so the lifecycle routes stay closed and
  // no client can renew. Naming the command is the whole content.
  if (absent) {
    return (
      <KnownLimit register="caution" title="Aucun domaine de confiance sur cette gateway">
        Les routes de cycle de vie restent fermées et aucun client ne peut renouveler son identité.
        Amorcer avec <code>heliosd init-trust-domain</code>.
      </KnownLimit>
    )
  }

  if (!domain) return <Skeleton variant="rounded" height={220} />

  const peers = [...domain.peers].sort(
    (left, right) => PHASE[right.phase].severity - PHASE[left.phase].severity,
  )

  return (
    <Stack spacing={2.5}>
      {domain.issuer !== null && !domain.issuer.usable && (
        <KnownLimit register="danger" title="L’émetteur délégué ne peut plus signer">
          Aucun renouvellement client n’aboutira tant qu’il n’est pas réautorisé —{' '}
          <code>astra issuer request</code>, <code>astra-signer authorize-issuer</code>,{' '}
          <code>astra issuer install</code>.
        </KnownLimit>
      )}

      {domain.gateway_restart_due !== null && (
        <KnownLimit register="danger" title="La feuille en service n’est plus la bonne">
          {domain.gateway_restart_due}. L’identité servie est descellée une seule fois et tenue
          pour la vie du processus — recharger la remplacerait sous des négociations qui
          détiennent déjà des PSK. Chaque bascule est donc un redémarrage&nbsp;:{' '}
          <code>systemctl restart heliosd</code>.
        </KnownLimit>
      )}

      <Box sx={{ display: 'grid', gap: 2.5, gridTemplateColumns: { xs: '1fr', lg: '1fr 1fr' } }}>
        <SectionCard title="Domaine de confiance" icon={Fingerprint} accent="tertiary.main">
          <Box>
            <DataRow label="Domaine" value={domain.trust_domain_id} wrap />
            <DataRow label="Service" value={domain.server_name} />
            <DataRow
              label="CA-PQ"
              value={`époque ${domain.ca_epoch} · ${domain.ca_pq_fingerprint}`}
              hint="Ancre ML-DSA-87 du domaine. C’est elle qui signe les délégations et les liaisons de credentials ; elle ne vit jamais sur la gateway."
              wrap
            />
            <DataRow
              label="CA TLS cliente"
              value={`époque ${domain.client_tls_ca_epoch}`}
              hint="Ancre sous laquelle les feuilles mTLS des clients sont émises."
            />
            <DataRow
              label="Identité gateway"
              value={`époque ${domain.gateway_identity_epoch} · ${domain.gateway_pq_fingerprint}`}
              hint="La feuille PQ que ce démon sert réellement. Une rotation sans redémarrage laisse un certificat plus récent sur disque que celui-ci."
              wrap
            />
            <DataRow
              label="Feuille TLS gateway"
              value={domain.gateway_tls_fingerprint}
              hint="La feuille TLS servie sur le même chemin. Le §6.1 fait de chaque moitié une rotation indépendante : celle-ci peut rester inchangée pendant qu’une transition PQ court."
              wrap
            />
          </Box>
        </SectionCard>

        <SectionCard title="Autorité Astra" icon={KeyRound} accent="tertiary.main">
          <Box>
            <DataRow label="Autorité" value={domain.astra_authority_url} wrap />
            <DataRow
              label="Clé de service"
              value={`époque ${domain.astra_service_key_epoch}`}
              hint="Clé sous laquelle Astra signe demandes d’approbation et statuts. Les profils l’épinglent."
            />
            <DataRow
              label="Politique"
              value={domain.astra_policy_fingerprint}
              hint="Empreinte confirmée hors bande et épinglée dans les profils. Une signature CA-PQ ne peut pas la remplacer."
              wrap
            />
            <DataRow label="RP ID" value={domain.webauthn_rp_id} />
            <DataRow
              label="Credentials"
              value={`${domain.credential_bindings} · époque ${domain.credential_registry_epoch}`}
              hint="Clés de sécurité pouvant approuver un renouvellement. Le coffre en exige deux : une seule, et une perte laisse le domaine sans approbateur."
            />
            {domain.issuer ? (
              <DataRow
                label="Émetteur délégué"
                value={`époque ${domain.issuer.issuer_epoch} · ${domain.issuer.lifecycle} · ${formatDelay(
                  domain.issuer.not_after - domain.now_unix,
                )}`}
                hint="Délégation bornée sous laquelle les renouvellements ordinaires sont émis. Elle expire d’elle-même."
              />
            ) : (
              <DataRow
                label="Émetteur délégué"
                value="absent"
                hint="Aucun renouvellement ordinaire ne peut être émis : l’installer par astra issuer request, astra-signer authorize-issuer puis astra issuer install."
              />
            )}
          </Box>
        </SectionCard>
      </Box>

      <TransitionTimeline domain={domain} />

      <GatewayIdentityActions domain={domain} />

      <SectionCard
        title="Identités clientes"
        icon={Users}
        accent="tertiary.main"
        action={
          <Chip
            size="small"
            icon={<BadgeCheck size={14} />}
            label={`${peers.length}`}
            sx={{ bgcolor: 'tertiary.container', color: 'tertiary.onContainer' }}
          />
        }
      >
        {peers.length === 0 ? (
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            Aucun pair au registre. Un client admis sans ses deux certificats n’y entre pas — son
            profil se connecte, mais ne renouvellera jamais.
          </Typography>
        ) : (
          <Box>
            {peers.map(peer => (
              <PeerRow key={peer.wg_public_key} peer={peer} now={domain.now_unix} />
            ))}
          </Box>
        )}
      </SectionCard>
    </Stack>
  )
}
