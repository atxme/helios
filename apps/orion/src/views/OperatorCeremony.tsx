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
import { formatDateTime, formatTime, stopSentence } from './astra/rotationRows'
import type {
  AstraManifest,
  CampaignManifest,
  GestureState,
  KeyPurpose,
  KeyRole,
  OperationKind,
  OperatorStatus,
  Refusal,
  RemoteState,
  RotationJournalView,
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
  authorize_issuer: 'Autoriser l’émetteur d’Astra',
  rotate_client_tls_ca: 'Renouveler la CA-TLS cliente',
  rotate_anchor: 'Renouveler l’ancre du domaine',
  revoke_certificate: 'Révoquer un certificat',
  verify_key: 'Vérifier la clé opérateur',
  invite_enrollment: 'Inviter un poste',
  accept_enrollment: 'Accepter une invitation',
  create_domain: 'Créer un domaine',
  add_key: 'Ajouter une clé',
  remove_key: 'Retirer une clé',
  mark_key: 'Changer l’état d’une clé',
  finalize_domain: 'Finaliser le domaine',
  issue_gateway_bootstrap: 'Amorcer la gateway',
}

/** The verb of the button that goes through with it, per operation. */
const VERBS: Record<OperationKind, string> = {
  recover_identity: 'Récupérer avec la clé',
  approve_campaign: 'Approuver avec la clé',
  authorize_issuer: 'Autoriser avec la clé',
  rotate_client_tls_ca: 'Signer avec la clé',
  rotate_anchor: 'Signer avec la clé',
  revoke_certificate: 'Révoquer avec la clé',
  verify_key: 'Vérifier avec la clé',
  invite_enrollment: 'Inviter avec la clé',
  accept_enrollment: 'Accepter avec la clé',
  create_domain: 'Créer avec les clés',
  add_key: 'Ajouter avec les clés',
  remove_key: 'Retirer avec la clé',
  mark_key: 'Signer avec la clé',
  finalize_domain: 'Finaliser avec la clé',
  issue_gateway_bootstrap: 'Amorcer avec les deux clés',
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

/** The role of a key, as the vault gestures name it. */
const KEY_ROLES: Record<KeyRole, string> = {
  principale: 'principale',
  recuperation: 'de récupération',
}

/** Hexadecimal read aloud, four digits at a time, as the Domaine panel shows it. */
export function groupedHex(hex: string): string {
  return hex.replace(/\s+/g, '').replace(/(.{4})(?=.)/g, '$1 ')
}

/** Every target a campaign binds: the touch signs them all. */
function targetRows(campaign: CampaignManifest['campaign']): [string, string][] {
  return campaign.targets.flatMap((target, index): [string, string][] => [
    [
      `cible ${index + 1}`,
      `${CERTIFICATE_KINDS[target.certificate_kind]} — ${target.identity_key}`,
    ],
    [`cible ${index + 1} état`, `époque ${target.epoch}, génération ${target.generation}`],
    [`cible ${index + 1} TLS`, target.active_tls_certificate_fingerprint],
    [`cible ${index + 1} PQ`, target.active_pq_certificate_fingerprint],
  ])
}

/** The rows of one manifest, named here and never carried as text. */
export function rowsOf(manifest: AstraManifest): [string, string][] {
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
        ...targetRows(manifest.campaign),
        ['empreinte', manifest.fingerprint],
        ['domaine', manifest.campaign.trust_domain_id],
      ]
    case 'issuer_authorization': {
      const rows: [string, string][] = [
        ['domaine', manifest.trust_domain_id],
        ['époque de l’émetteur', String(manifest.issuer_epoch)],
        [
          'valide du / jusqu’au',
          `${instant(manifest.not_before)} → ${instant(manifest.not_after)}`,
        ],
        [
          'leaf au plus (jours)',
          String(Number((manifest.maximum_leaf_lifetime_secs / 86_400).toFixed(2))),
        ],
        ['usages', manifest.allowed_usages.join(', ')],
        ['clé PQ (empreinte)', manifest.pq_public_key_fingerprint],
        ['clé TLS (empreinte)', manifest.tls_public_key_info_fingerprint],
        ['demande (empreinte)', manifest.request_fingerprint],
        ['politique', manifest.policy_fingerprint],
      ]
      if (manifest.campaign) {
        rows.push(
          ['campagne', manifest.campaign.campaign.campaign_id],
          ['motif', manifest.campaign.campaign.reason],
          ['demandée par', manifest.campaign.campaign.requested_by],
          ['empreinte de campagne', manifest.campaign.fingerprint],
        )
      }
      return rows
    }
    case 'ca_rotation': {
      const rows: [string, string][] = [
        ['autorité visée', CA_NAMES[manifest.affected_ca]],
        ['époque', `${manifest.current_epoch} → ${manifest.next_epoch}`],
        ['activation', instant(manifest.activation_at)],
        ['échéance', instant(manifest.not_after)],
        ['ancre sortante', manifest.outgoing_anchor_fingerprint],
        ['ancre entrante', manifest.next_anchor_fingerprint ?? 'créée à la signature'],
        ['domaine', manifest.trust_domain_id],
      ]
      if (manifest.campaign) {
        rows.push(
          ['campagne', manifest.campaign.campaign.campaign_id],
          ['portée', CAMPAIGN_SCOPES[manifest.campaign.campaign.scope]],
          ['motif', manifest.campaign.campaign.reason],
          ['demandée par', manifest.campaign.campaign.requested_by],
          ['clés requises', String(manifest.campaign.campaign.required_credentials)],
          ['cibles', String(manifest.campaign.campaign.targets.length)],
          ...targetRows(manifest.campaign.campaign),
          ['empreinte de campagne', manifest.campaign.fingerprint],
        )
      }
      return rows
    }
    case 'revocation':
      return [
        ['cible', manifest.target],
        ['portée', manifest.scope],
        ['motif', manifest.reason],
        ['époque de révocation', String(manifest.revocation_epoch)],
        ['effet', instant(manifest.effective_at)],
        ['domaine', manifest.trust_domain_id],
      ]
    case 'key_check':
      return [['coffre', manifest.vault_fingerprint]]
    case 'invitation':
      return [
        ['nom serveur', manifest.server_name],
        ['gateway', manifest.gateway_wg_public_key],
        ['échéance', instant(manifest.not_after_unix)],
        ['réadmission', manifest.allow_readmission ? 'autorisée' : 'refusée'],
        ['CA-PQ', groupedHex(manifest.ca_pq_fingerprint)],
      ]
    case 'enrollment_acceptance':
      return [
        ['invitation', manifest.invitation_id],
        ['nom demandé', manifest.requested_name],
        ['clé publique', manifest.client_wg_public_key],
        ['empreinte', manifest.request_fingerprint],
        ['échéance des certificats', instant(manifest.leaves_not_after_unix)],
        ['point d’accès', manifest.endpoint],
        ...(manifest.allowed_ips ? [['routes autorisées', manifest.allowed_ips] as [string, string]] : []),
        ...(manifest.ssh_target ? [['cible SSH', manifest.ssh_target] as [string, string]] : []),
      ]
    case 'domain_creation':
      return [
        ['nom WebAuthn', manifest.rp_id],
        ['origine d’Astra', manifest.authority_url],
        ['première clé', manifest.first_label],
        ['seconde clé', manifest.second_label],
      ]
    case 'key_addition':
      return [
        ['coffre', manifest.vault_fingerprint],
        ['libellé', manifest.label],
        ['rôle', KEY_ROLES[manifest.role]],
      ]
    case 'key_removal':
      return [
        ['coffre', manifest.vault_fingerprint],
        ['clé', manifest.label],
        ['rôle', KEY_ROLES[manifest.role]],
      ]
    case 'key_marking':
      return [
        ['coffre', manifest.vault_fingerprint],
        ['clé', manifest.label],
        ['nouvel état', manifest.lost ? 'perdue' : 'active'],
      ]
    case 'domain_finalization':
      return [
        ['coffre', manifest.vault_fingerprint],
        ['nom serveur', manifest.server_name],
        ['gateway', manifest.gateway_wg_public_key],
        [
          'CA-TLS',
          manifest.issues_ca_tls ? `émise, ${manifest.ca_tls_days} jours` : 'déjà en place',
        ],
        ['credentials', manifest.issues_credentials ? 'émis' : 'à jour'],
      ]
    case 'gateway_bootstrap': {
      const rows: [string, string][] = [
        ['coffre', manifest.vault_fingerprint],
        ['gateway', manifest.server_name],
        ['identité WireGuard', manifest.gateway_wg_public_key],
        ['demande', manifest.request_fingerprint],
        ['époque', '1'],
        ['validité de la feuille', `${manifest.leaf_days} jours`],
        ['approbations', 'deux clés distinctes'],
      ]
      if (manifest.issues_ca_tls) {
        rows.push(['émettre la CA-TLS', `${manifest.ca_tls_days} jours`])
      }
      if (manifest.issues_credentials) {
        rows.push(['signer le document de credentials', 'oui'])
      }
      return rows
    }
  }
}

/** What the authority holds, said plainly. */
export function remoteSentence(remote: RemoteState): string {
  if (typeof remote === 'object') {
    return `Signée et commitée. La nouvelle génération prend effet le ${instant(
      remote.activation_deferred.activation_at,
    )}.`
  }
  switch (remote) {
    case 'local':
      return 'Rien n’a encore été demandé à l’autorité.'
    case 'awaiting_operator':
      return 'L’autorité tient la demande et attend un opérateur.'
    case 'prepared':
      return 'Signé sur ce poste.'
    case 'deposited':
      return 'Déposé auprès de l’autorité. Plus rien ne s’annule.'
    case 'staged':
      return 'La gateway a préparé la génération candidate.'
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
export function gestureSentence(
  gesture: GestureState,
  operation: OperationKind,
  /** A campaign exists at the authority: abandoning does not undo it. */
  opened = false,
): string {
  if (typeof gesture === 'object') {
    if ('awaiting_key' in gesture) {
      const { index, of, purpose } = gesture.awaiting_key
      const which = of > 1 ? ` (${index} sur ${of})` : ''
      if (operation === 'issue_gateway_bootstrap') {
        return purpose === 'second_approval'
          ? `Débrancher la clé précédente. Brancher une autre clé du coffre${which}, pour approuver l’amorçage.`
          : `Brancher une clé du coffre${which}, pour ouvrir le coffre.`
      }
      if (purpose === 'register_key') {
        const previous = index > 1 ? 'Débrancher la clé précédente. ' : ''
        return `${previous}Brancher la nouvelle clé${which}, pour l’enregistrer dans le coffre.`
      }
      const why =
        purpose === 'open_vault'
          ? 'pour ouvrir le coffre d’autorité'
          : purpose === 'approve_campaign'
            ? 'pour approuver la campagne affichée'
          : purpose === 'second_approval'
            ? 'pour la seconde approbation'
          : purpose === 'validate_key'
            ? 'pour la valider'
            : 'pour promouvoir ce qui a été préparé'
      return `Brancher la clé autorisée${which}, ${why}.`
    }
    const { index, of } = gesture.processing_key
    return of > 1 ? `Clé ${index} sur ${of} en cours de lecture…` : 'Lecture de la clé…'
  }
  switch (gesture) {
    case 'verifying':
      return 'Vérification de la demande.'
    case 'idle':
      return 'En attente de l’autorité.'
    case 'signing':
      return 'Signature en cours.'
    case 'done':
      return TITLES[operation] + ' : terminé.'
    case 'cancelled':
      // Open for up to its window, unable to be approved without the openings, and
      // blocking its family: not « rien n'a quitté cette machine ».
      return opened
        ? 'Abandonné. Campagne encore ouverte, 5 min au plus.'
        : 'Abandonné. Rien n’a quitté cette machine.'
    case 'failed':
      return 'La cérémonie s’est arrêtée.'
  }
}

/**
 * Refusals a rotation does not word like the other ceremonies: nothing of the enrollment's
 * `admission.txt`, and the door's classes by their label. `null` leaves the usual sentence.
 */
function rotationRefusal(
  refusal: Refusal,
  journal: RotationJournalView | null,
  opened: boolean,
): string | null {
  const kept = (said: string) => (journal ? `${said}. Rotation conservée.` : said)
  switch (refusal.refusal) {
    case 'gateway_unavailable':
      return kept('Gateway injoignable')
    case 'gateway_refused':
      return kept(`Gateway refuse l’installation (HTTP ${refusal.status})`)
    case 'signer_revoked':
      // Found by `open`, once both keys were validated: the ceremony starts again.
      return 'Clé validée marquée perdue ou révoquée. Recommencer avec une clé active.'
    case 'window_expired':
      // At the key steps and the terms nothing exists at the authority, and the keys
      // held in memory are what ran out.
      return opened ? 'Campagne expirée' : 'Délai écoulé. Clés oubliées. Recommencer'
    case 'authority_refused':
      if (refusal.status === 429) return 'Trop d’opérations en attente'
      // The door answers 403 to a campaign already open and to a peer that is no admin.
      if (refusal.status === 403) return 'Opération déjà ouverte, ou poste non administrateur'
      return null
    default:
      return null
  }
}

/**
 * Why a key is asked for again, in a few words. The purpose tells a second key that
 * repeats the first at validation from one that was already used to approve.
 */
export function retryLabel(retry: Refusal, purpose: KeyPurpose | null): string {
  switch (retry.refusal) {
    case 'key_repeated':
      return purpose === 'validate_key' ? 'Même clé que la clé 1' : 'Clé déjà approuvée'
    case 'key_not_enrolled':
      return 'Clé absente du coffre'
    case 'signer_revoked':
      return 'Clé marquée perdue ou révoquée'
    case 'key_not_validated':
      return 'Autre clé attendue'
    case 'key_declined':
      return 'Clé sans réponse'
    case 'foreground_unavailable':
      return 'Fenêtre Windows indisponible'
    case 'terms_refused':
      return 'Durées hors limites'
    default:
      return refusalSentence(retry)
  }
}

/** Why it stopped. Typed, so the words are ours. */
export function refusalSentence(
  refusal: Refusal,
  /** The rotation journal, when the screen knows it: dates and recourse come from it. */
  journal: RotationJournalView | null = null,
  /** The ceremony the refusal ends: a rotation words some refusals its own way. */
  operation: OperationKind | null = null,
  /** A campaign exists at the authority; `true` when the screen does not say. */
  opened = true,
): string {
  const rotation = operation === 'rotate_anchor' || operation === 'rotate_client_tls_ca'
  if (rotation) {
    const worded = rotationRefusal(refusal, journal, opened)
    if (worded !== null) return worded
  }
  switch (refusal.refusal) {
    case 'vault_unavailable':
      return 'Coffre d’autorité absent, illisible, ou étranger à ce domaine.'
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
      return 'La fenêtre de l’opération s’est refermée. En rouvrir une.'
    case 'authority_refused':
      return `L’autorité a décliné${refusal.status ? ` (${refusal.status})` : ''}.`
    case 'gateway_unavailable':
      return (
        'La gateway n’est pas connectée ou n’a pas pu être lue. Les feuilles sont émises : ' +
        'admettre le pair avec la ligne de admission.txt, puis reprendre depuis la liste des ' +
        'invitations.'
      )
    case 'gateway_leaf_unavailable':
      return (
        'Aucune feuille PQ de la gateway n’a pu être lue : la gateway ne répond pas. ' +
        'Fournir le fichier de la feuille PQ de la gateway, ou rétablir la gateway, puis ' +
        'refaire l’invitation.'
      )
    case 'document_not_signed':
      return (
        'Le pair est admis, mais son document n’a pas pu être signé. Ne pas l’admettre ' +
        'de nouveau : reprendre cette invitation depuis la liste des invitations pour ' +
        'signer le document.'
      )
    case 'invitation_unknown':
      return 'Cette invitation est inconnue de ce poste : la demande n’a rien consommé.'
    case 'invitation_consumed':
      return 'Cette invitation est déjà consommée : la reprendre depuis la liste des invitations.'
    case 'invitation_expired':
      return 'Cette invitation a expiré ou n’est plus ouverte : en émettre une nouvelle.'
    case 'ca_tls_missing':
      return (
        'Le relais de domaine ne porte aucun CA-TLS : l’émission de CA-TLS doit précéder ' +
        'l’acceptation des demandes.'
      )
    case 'gateway_forbidden':
      return (
        'La gateway refuse cette machine : le pair de ce poste doit porter le drapeau `admin`. ' +
        'Les feuilles sont émises : admettre le pair avec la ligne de admission.txt.'
      )
    case 'gateway_refused':
      return (
        `La gateway a refusé l’admission (HTTP ${refusal.status}). Les feuilles sont émises : ` +
        'admettre le pair avec la ligne de admission.txt.'
      )
    case 'acceptance_not_kept':
      return (
        'Les feuilles sont émises et remises, mais n’ont pas pu être conservées : cette ' +
        'acceptation ne pourra pas être reprise. Admettre le pair avec la ligne de ' +
        'admission.txt.'
      )
    case 'accepted_elsewhere':
      return "Cette invitation a été acceptée hors d'Orion : ses feuilles ne sont pas ici."
    case 'vault_exists':
      return 'Un coffre existe déjà à cet emplacement : ajouter une clé plutôt que créer un second domaine.'
    case 'location_unavailable':
      return 'L’emplacement du coffre est introuvable : rebrancher son support ou choisir un autre emplacement.'
    case 'vault_full':
      return 'Le coffre porte déjà huit clés : en retirer une avant d’en ajouter.'
    case 'minimum_keys':
      return 'Le coffre doit garder au moins deux clés : en ajouter une avant d’en retirer.'
    case 'key_being_removed':
      return 'La clé qui a ouvert le coffre est celle à retirer : recommencer avec une autre clé.'
    case 'gateway_identity_missing':
      return (
        'Le relais ne nomme pas encore la gateway, ou le document de credentials en place ne se ' +
        'vérifie pas : reprendre la gateway connectée, ou restaurer le document de credentials ' +
        'depuis une sauvegarde.'
      )
    case 'domain_complete':
      return 'Le domaine est déjà finalisé : CA-TLS et document de credentials sont en place.'
    case 'handoff_mismatch':
      return 'La proposition ne correspond pas à ce que ce coffre épingle.'
    case 'bootstrap_request_invalid':
      return (
        'Ce fichier n’est pas une demande d’amorçage de gateway valide, ou sa signature ne se ' +
        'vérifie pas. Rien n’a été signé.'
      )
    case 'delegation_request_invalid':
      return 'Ce fichier n’est pas une demande de délégation lisible. Rien n’a été signé.'
    case 'delegation_request_mismatch':
      return (
        'La campagne ne nomme pas cette demande, ou elle vise un autre domaine : époque ou clé ' +
        'substituée. Rien n’a été signé.'
      )
    case 'ca_tls_unusable':
      return (
        'La CA-TLS du domaine expire avant la fin de cette délégation, ou n’est pas une ' +
        'autorité : la renouveler d’abord. Rien n’a été signé.'
      )
    case 'other_gateway':
      return (
        'Le domaine nomme déjà une autre gateway : en changer est une transition de gateway. ' +
        'Rien n’a été écrit.'
      )
    case 'domain_changed':
      return (
        'Le domaine a changé depuis l’affichage de ce qui allait être signé : recommencer le ' +
        'geste. Rien n’a été signé.'
      )
    case 'signer_revoked':
      return 'Le document de credentials révoque cette clé : en présenter une autre.'
    case 'manifest_mismatch':
      return 'La réponse ne décrit pas la demande envoyée.'
    case 'protocol_violation':
      return 'Le canal local a été rompu.'
    case 'cancelled':
      return 'Abandonné.'
    case 'rotation_expired':
      return 'Rotation expirée. Recommencer.'
    case 'domain_conflict':
      return stopSentence('domain_conflict', journal)
    case 'install_deadline_passed':
      return stopSentence('install_deadline_passed', journal)
    case 'gateway_names_no_anchor':
      return stopSentence('gateway_names_no_anchor', journal)
    case 'rotation_in_flight':
      return 'Rotation en cours. La mener à son terme d’abord.'
    case 'campaign_closing':
      // Astra's silence on a campaign that has only just closed is not yet its last word.
      return `Campagne à peine close. Rotation conservée : reprendre après ${formatTime(refusal.until)}.`
    case 'key_not_validated':
      return 'Autre clé attendue.'
    case 'terms_refused':
      return 'Durées hors limites. Rien n’a été envoyé.'
    case 'nothing_to_finish':
      return 'Aucune rotation à terminer.'
    case 'overlap_running':
      // On this machine's clock, which the row's gateway clock may be ahead of.
      return `Recouvrement jusqu’au ${formatDateTime(refusal.until)}. Rien n’a été modifié.`
    case 'peer_name_mismatch':
      return 'Ce nom ne désigne pas ce poste sur la gateway. Rien n’a été coupé.'
    case 'self_revocation':
      return 'Ce poste ne peut pas se révoquer lui-même : utiliser `helios peer revoke <nom>` sur la gateway.'
    case 'revocation_awaits_deposit':
      return 'Une révocation attend son dépôt : la reprendre d’abord.'
    case 'revocation_not_before':
      // Signing is refused until the margin: the cut has already happened.
      return `Révocation possible après le ${formatDateTime(refusal.until)}. Le poste est coupé ; la révocation reste à signer.`
    case 'revocation_anchor_unknown':
      return 'Astra vérifie sous une ancre que ce coffre ne détient pas. Le poste est coupé ; la révocation reste à signer.'
    case 'credentials_unverified':
      return 'Le document de credentials ne se vérifie pas sous l’ancre à signer. Le poste est coupé ; la révocation reste à signer.'
    case 'campaign_mismatch':
      return 'La campagne d’Astra ne nomme pas ce poste. Le poste est coupé ; la révocation reste à signer.'
    case 'peer_already_revoked':
      return 'Poste déjà révoqué.'
    case 'outgoing_ca_pq_kept':
      return `L’ancienne CA-PQ est gardée jusqu’au ${formatDateTime(refusal.until)} : « Terminer » attendra. Rien n’a été modifié.`
    case 'authority_unreachable':
      return 'Astra injoignable. Le poste est coupé ; la révocation reste à signer.'
    case 'internal':
      return 'Le processus opérateur s’est arrêté sans conclure.'
  }
}

/** The purpose of the key being asked, when one is. */
export function purposeOf(gesture: GestureState): KeyPurpose | null {
  return typeof gesture === 'object' && 'awaiting_key' in gesture
    ? gesture.awaiting_key.purpose
    : null
}

export function Row({ label, value }: { label: string; value: string }) {
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
  journal = null,
}: {
  status: OperatorStatus
  onStatus: (next: OperatorStatus) => void
  onDismiss?: () => void
  journal?: RotationJournalView | null
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
          {rowsOf(status.manifest).map(([label, value]) => (
            <Row key={label} label={label} value={value} />
          ))}
        </Box>
      )}

      <Box sx={{ mt: 1.25, pt: 1.25, borderTop: `1px solid ${RULE}` }}>
        <Typography sx={{ fontSize: 11.5, lineHeight: 1.55 }}>
          {gestureSentence(status.gesture, status.operation, status.remote !== 'local')}
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

      {status.key_retry && !stopped && !done && (
        <Alert severity="warning" variant="outlined" sx={{ mt: 1, fontSize: 11.5 }}>
          {retryLabel(status.key_retry, purposeOf(status.gesture))}
        </Alert>
      )}
      {status.refusal && !done && (
        <Alert
          severity={status.refusal.refusal === 'cancelled' ? 'info' : 'error'}
          variant="outlined"
          sx={{ mt: 1, fontSize: 11.5 }}
        >
          {refusalSentence(status.refusal, journal, status.operation)}
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
