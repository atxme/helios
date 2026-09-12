import { useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import CircularProgress from '@mui/material/CircularProgress'
import Paper from '@mui/material/Paper'
import Typography from '@mui/material/Typography'
import { KeyRound, X } from 'lucide-react'

import * as api from '../api'
import { RULE } from '../theme'
import type {
  AstraManifest,
  GestureState,
  OperationKind,
  OperatorStatus,
  RemoteState,
  Refusal,
} from '../types'

/**
 * One operator ceremony, whatever it is.
 *
 * # Why one component serves six operations
 *
 * Because the *shape* is the same for all of them — verify, show what is about
 * to be signed, wait for a human, act — and only the fields differ. What is
 * emphatically not shared is the wording: every sentence and every label below
 * is chosen here, from a typed variant. Nothing renders a string the helper or
 * the network supplied, which is what makes «ce qui est signé est ce qui a été
 * montré» checkable rather than promised (§12.2).
 */

const TITLES: Record<OperationKind, string> = {
  recover_identity: 'Récupérer une identité expirée',
  approve_campaign: 'Approuver une campagne',
  authorize_issuer: 'Autoriser l’émetteur délégué',
  rotate_client_tls_ca: 'Renouveler la CA-TLS cliente',
  rotate_anchor: 'Renouveler l’ancre du domaine',
  revoke_certificate: 'Révoquer un certificat',
}

/** The verb of the button that goes through with it, per operation. */
const VERBS: Record<OperationKind, string> = {
  recover_identity: 'Récupérer avec la clé',
  approve_campaign: 'Approuver avec la clé',
  authorize_issuer: 'Autoriser avec la clé',
  rotate_client_tls_ca: 'Signer avec la clé',
  rotate_anchor: 'Signer avec la clé',
  revoke_certificate: 'Révoquer avec la clé',
}

function instant(unix: number): string {
  return new Date(unix * 1000).toLocaleString()
}

function duration(seconds: number): string {
  const days = Math.floor(seconds / 86_400)
  if (days >= 1) return `${days} jour${days > 1 ? 's' : ''}`
  const hours = Math.floor(seconds / 3_600)
  if (hours >= 1) return `${hours} h`
  return `${Math.max(0, Math.floor(seconds / 60))} min`
}

const CA_NAMES = { ca_pq: 'CA-PQ (ancre du domaine)', ca_tls: 'CA-TLS cliente' } as const
const CAMPAIGN_SCOPES = {
  orion_profile: 'un profil Orion',
  orion_device: 'les profils Orion de cet appareil',
  fleet_leafs: 'les certificats clients de la flotte',
  full_certificate_chain: 'la chaîne complète',
  trust_authorities: 'les ancres du domaine',
  emergency_revocation: 'une révocation d’urgence',
  gateway_identity: 'l’identité de la gateway',
  issuer_delegation: 'la délégation Astra',
  gateway_bootstrap: 'l’identité initiale de la gateway',
} as const
const CERTIFICATE_KINDS = {
  gateway_tls: 'TLS gateway',
  gateway_pq: 'PQ gateway',
  client_tls: 'TLS client',
  client_pq: 'PQ client',
  ca_pq: 'CA-PQ',
  ca_tls: 'CA-TLS cliente',
  astra_issuer: 'émetteur Astra',
  astra_service_key: 'clé de service Astra',
} as const

/** The rows of one manifest, named here and never carried as text. */
function rowsOf(manifest: AstraManifest): [string, string][] {
  switch (manifest.operation) {
    case 'recovery':
      return [
        ['pair', manifest.peer_name],
        ['clé publique', manifest.client_wg_public_key],
        ['génération', `${manifest.expired_generation} → ${manifest.next_generation}`],
        ['expirée depuis', duration(manifest.expired_since_secs)],
        ['activation', instant(manifest.activation_at)],
        ['échéance', instant(manifest.not_after)],
        ['époque CA-PQ', String(manifest.ca_epoch)],
        ['époque CA-TLS', String(manifest.ca_tls_epoch)],
        ['empreinte', manifest.request_fingerprint],
        ['domaine', manifest.trust_domain_id],
      ]
    case 'campaign':
      return [
        ['motif', manifest.campaign.reason],
        ['demandée par', manifest.campaign.requested_by],
        ['portée', CAMPAIGN_SCOPES[manifest.campaign.scope]],
        ['créée le', instant(manifest.campaign.created_at)],
        ['échéance', instant(manifest.campaign.expires_at)],
        ['gateway', manifest.campaign.gateway_wg_public_key],
        ['nom serveur', manifest.campaign.server_name],
        ['politique', manifest.campaign.policy_fingerprint],
        ['clés requises', String(manifest.campaign.required_credentials)],
        ...manifest.campaign.targets.flatMap((target, index): [string, string][] => [
          [
            `cible ${index + 1}`,
            `${CERTIFICATE_KINDS[target.certificate_kind]} — ${target.identity_key}`,
          ],
          [`cible ${index + 1} état`, `époque ${target.epoch}, génération ${target.generation}`],
          [`cible ${index + 1} TLS`, target.active_tls_certificate_fingerprint],
          [`cible ${index + 1} PQ`, target.active_pq_certificate_fingerprint],
        ]),
        ['empreinte', manifest.fingerprint],
        ['domaine', manifest.campaign.trust_domain_id],
      ]
    case 'issuer_authorization':
      return [
        ['époque de délégation', String(manifest.issuer_epoch)],
        ['validité', `${instant(manifest.not_before)} → ${instant(manifest.not_after)}`],
        ['usages autorisés', manifest.allowed_usages.join(', ')],
        ['politique', manifest.policy_fingerprint],
        ['empreinte', manifest.request_fingerprint],
        ['domaine', manifest.trust_domain_id],
      ]
    case 'ca_rotation':
      return [
        ['autorité visée', CA_NAMES[manifest.affected_ca]],
        ['époque', `${manifest.current_epoch} → ${manifest.next_epoch}`],
        ['activation', instant(manifest.activation_at)],
        ['échéance', instant(manifest.not_after)],
        ['ancre sortante', manifest.outgoing_anchor_fingerprint],
        ['ancre entrante', manifest.next_anchor_fingerprint],
        ['pairs concernés', String(manifest.target_count)],
        ['domaine', manifest.trust_domain_id],
      ]
    case 'revocation':
      return [
        ['cible', manifest.target],
        ['portée', manifest.scope],
        ['motif', manifest.reason],
        ['époque de révocation', String(manifest.revocation_epoch)],
        ['effet', instant(manifest.effective_at)],
        ['domaine', manifest.trust_domain_id],
      ]
  }
}

/** What the authority holds, said plainly. */
function remoteSentence(remote: RemoteState): string {
  if (typeof remote === 'object') {
    return `Signée et commitée. La nouvelle génération prend effet le ${instant(
      remote.activation_deferred.activation_at,
    )} — d’ici là, l’ancienne reste servie.`
  }
  switch (remote) {
    case 'local':
      return 'Rien n’a encore été demandé à l’autorité.'
    case 'awaiting_operator':
      return 'L’autorité tient la demande et attend un opérateur.'
    case 'prepared':
      return 'Signé sur ce poste. Rien n’a encore quitté cette machine.'
    case 'deposited':
      return 'Déposé auprès de l’autorité. À partir d’ici, plus rien ne s’annule.'
    case 'staged':
      return 'La gateway a mis la génération candidate en scène.'
    case 'pending_grant':
      return 'Reçu signé par la gateway ; le grant reste à libérer.'
    case 'granted':
      return 'Grant libéré. Le client peut installer et committer.'
    case 'committed':
      return 'Commité des deux côtés.'
    case 'refused':
      return 'L’autorité a décliné.'
  }
}

/** What this machine is doing, said plainly. */
function gestureSentence(gesture: GestureState, operation: OperationKind): string {
  if (typeof gesture === 'object') {
    if ('awaiting_key' in gesture) {
      const { index, of, purpose } = gesture.awaiting_key
      const which = of > 1 ? ` (${index} sur ${of})` : ''
      const why =
        purpose === 'open_vault'
          ? 'pour ouvrir le coffre d’autorité'
          : purpose === 'approve_campaign'
            ? 'pour approuver la campagne affichée'
          : purpose === 'second_approval'
            ? 'pour la seconde approbation, qui doit venir d’une autre clé'
            : 'pour promouvoir ce qui a déjà été préparé'
      return `Brancher la clé autorisée${which}, ${why}.`
    }
    const { index, of } = gesture.processing_key
    return of > 1 ? `Clé ${index} sur ${of} en cours de lecture…` : 'Lecture de la clé…'
  }
  switch (gesture) {
    case 'verifying':
      return 'Vérification de ce qui est demandé, avant qu’aucune clé ne soit sollicitée.'
    case 'idle':
      return 'En attente de l’autorité.'
    case 'signing':
      return 'Signature en cours. Le système peut demander le PIN et le contact de la clé.'
    case 'done':
      return TITLES[operation] + ' : terminé.'
    case 'cancelled':
      return 'Abandonné avant que quoi que ce soit ne quitte cette machine.'
    case 'failed':
      return 'La cérémonie s’est arrêtée.'
  }
}

/** Why it stopped. Typed, so the words are ours. */
function refusalSentence(refusal: Refusal): string {
  switch (refusal.refusal) {
    case 'vault_unavailable':
      return 'Le coffre d’autorité est absent, illisible, ou n’est pas celui de ce domaine.'
    case 'key_declined':
      return 'Aucune clé n’a répondu, ou le geste a été refusé.'
    case 'foreground_unavailable':
      return (
        'Windows n’a pas pu ouvrir la boîte WebAuthn au premier plan. ' +
        'Revenir dans Orion et recommencer le geste.'
      )
    case 'key_not_enrolled':
      return 'La clé qui a répondu n’est pas enrôlée dans ce domaine.'
    case 'key_repeated':
      return 'Les deux approbations doivent venir de deux clés distinctes.'
    case 'window_expired':
      return 'La fenêtre de l’opération s’est refermée avant la fin du geste. En rouvrir une.'
    case 'authority_refused':
      return `L’autorité a décliné${
        refusal.status ? ` (${refusal.status})` : ''
      }. Le motif détaillé reste dans son journal protégé.`
    case 'handoff_mismatch':
      return 'Ce que l’autorité propose ne correspond pas à ce que ce coffre épingle. Rien n’a été signé.'
    case 'manifest_mismatch':
      return 'La réponse ne décrit pas la demande envoyée.'
    case 'protocol_violation':
      return 'Le canal local a été rompu.'
    case 'cancelled':
      return 'Abandonné.'
    case 'internal':
      return 'Le processus opérateur s’est arrêté sans conclure.'
  }
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 1, minWidth: 0, py: 0.35 }}>
      <Typography
        color="text.disabled"
        sx={{ fontSize: 10.5, width: 132, flexShrink: 0, textTransform: 'uppercase' }}
      >
        {label}
      </Typography>
      <Typography
        sx={{
          minWidth: 0,
          flex: '1 1 0',
          fontFamily: 'monospace',
          fontSize: 11,
          overflowWrap: 'anywhere',
        }}
      >
        {value}
      </Typography>
    </Box>
  )
}

export function OperatorCeremonyPanel({
  status,
  onStatus,
  onDismiss,
}: {
  status: OperatorStatus
  onStatus: (next: OperatorStatus) => void
  onDismiss?: () => void
}) {
  const [busy, setBusy] = useState(false)
  const [refusal, setRefusal] = useState<string | null>(null)

  const act = async (action: 'continue' | 'cancel') => {
    setBusy(true)
    setRefusal(null)
    try {
      onStatus(await api.advanceOperatorCeremony(action, status.revision))
    } catch (cause) {
      setRefusal(String(cause))
    } finally {
      setBusy(false)
    }
  }

  const done = status.gesture === 'done'
  const stopped = status.gesture === 'failed' || status.gesture === 'cancelled'

  return (
    <Paper variant="outlined" sx={{ px: 1.75, py: 1.5 }}>
      <Typography component="h3" sx={{ fontSize: 13, fontWeight: 650 }}>
        {TITLES[status.operation]}
      </Typography>
      {status.operation_id && (
        <Typography color="text.disabled" sx={{ mt: 0.25, fontSize: 10.5, fontFamily: 'monospace' }}>
          {status.operation_id}
        </Typography>
      )}

      {status.manifest && (
        <Box sx={{ mt: 1.25, pt: 1.25, borderTop: `1px solid ${RULE}` }}>
          <Typography color="text.disabled" sx={{ fontSize: 11, lineHeight: 1.5, mb: 0.5 }}>
            Vérifié contre ce que ce coffre épingle. C’est cela qui sera signé.
          </Typography>
          {rowsOf(status.manifest).map(([label, value]) => (
            <Row key={label} label={label} value={value} />
          ))}
        </Box>
      )}

      <Box sx={{ mt: 1.25, pt: 1.25, borderTop: `1px solid ${RULE}` }}>
        <Typography sx={{ fontSize: 11.5, lineHeight: 1.55 }}>
          {gestureSentence(status.gesture, status.operation)}
        </Typography>
        <Typography color="text.secondary" sx={{ mt: 0.25, fontSize: 11.5, lineHeight: 1.55 }}>
          {remoteSentence(status.remote)}
        </Typography>
      </Box>

      {status.keys && status.keys.length > 0 && (
        <Box sx={{ mt: 0.75 }}>
          {status.keys.map((key) => (
            <Row key={key.slot} label={`clé ${key.slot}`} value={key.label} />
          ))}
        </Box>
      )}

      {status.refusal && !done && (
        <Alert
          severity={status.refusal.refusal === 'cancelled' ? 'info' : 'error'}
          variant="outlined"
          sx={{ mt: 1, fontSize: 11.5 }}
        >
          {refusalSentence(status.refusal)}
        </Alert>
      )}
      {done && (
        <Alert severity="success" variant="outlined" sx={{ mt: 1, fontSize: 11.5 }}>
          {remoteSentence(status.remote)}
        </Alert>
      )}

      {!stopped && !done && status.allowed.length > 0 && (
        <Box sx={{ mt: 1, display: 'flex', gap: 1 }}>
          {status.allowed.includes('continue') && (
            <Button
              size="small"
              variant="contained"
              disabled={busy}
              startIcon={
                busy ? <CircularProgress size={13} color="inherit" /> : <KeyRound size={14} aria-hidden />
              }
              onClick={() => void act('continue')}
              sx={{ minHeight: 30, fontSize: 11.5 }}
            >
              {VERBS[status.operation]}
            </Button>
          )}
          {status.allowed.includes('cancel') && (
            <Button
              size="small"
              variant="outlined"
              color="inherit"
              disabled={busy}
              startIcon={<X size={14} aria-hidden />}
              onClick={() => void act('cancel')}
              sx={{ minHeight: 30, fontSize: 11.5 }}
            >
              Annuler
            </Button>
          )}
        </Box>
      )}

      {(stopped || done) && onDismiss && (
        <Button
          size="small"
          variant="outlined"
          color="inherit"
          disabled={busy}
          onClick={onDismiss}
          sx={{ mt: 1, minHeight: 30, fontSize: 11.5 }}
        >
          Retour aux opérations
        </Button>
      )}

      {refusal && (
        <Alert severity="error" variant="outlined" sx={{ mt: 0.75, fontSize: 11.5 }}>
          {refusal}
        </Alert>
      )}
    </Paper>
  )
}
