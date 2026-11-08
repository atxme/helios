import { describe, expect, it } from 'vitest'
import { gestureSentence, refusalSentence, retryLabel } from './OperatorCeremony'

describe('refusalSentence for the acceptance', () => {
  it('names the consumed invitation and where to resume it', () => {
    expect(refusalSentence({ refusal: 'invitation_consumed' })).toBe(
      'Cette invitation est déjà consommée : la reprendre depuis la liste des invitations.',
    )
  })

  it('says each cause and its next step', () => {
    expect(refusalSentence({ refusal: 'invitation_unknown' })).toMatch(/inconnue/)
    expect(refusalSentence({ refusal: 'invitation_expired' })).toMatch(/expiré/)
    expect(refusalSentence({ refusal: 'ca_tls_missing' })).toMatch(/émission de CA-TLS/)
    expect(refusalSentence({ refusal: 'gateway_forbidden' })).toMatch(/drapeau `admin`/)
    expect(refusalSentence({ refusal: 'gateway_forbidden' })).toMatch(/admission\.txt/)
    expect(refusalSentence({ refusal: 'gateway_refused', status: 409 })).toMatch(/409/)
    expect(refusalSentence({ refusal: 'gateway_refused', status: 409 })).toMatch(/admission\.txt/)
    expect(refusalSentence({ refusal: 'gateway_unavailable' })).toMatch(/admission\.txt/)
    expect(refusalSentence({ refusal: 'acceptance_not_kept' })).toMatch(/reprise/)
  })

  it('names_an_acceptance_made_outside_orion', () => {
    expect(refusalSentence({ refusal: 'accepted_elsewhere' })).toBe(
      "Cette invitation a été acceptée hors d'Orion : ses feuilles ne sont pas ici.",
    )
  })

  it('names_a_gateway_leaf_that_cannot_be_read_without_pointing_to_admission_txt', () => {
    const sentence = refusalSentence({ refusal: 'gateway_leaf_unavailable' })
    expect(sentence).toMatch(/feuille PQ de la gateway/)
    expect(sentence).not.toMatch(/admission\.txt/)
  })

  it('names_an_admitted_peer_whose_document_was_not_signed', () => {
    const sentence = refusalSentence({ refusal: 'document_not_signed' })
    expect(sentence).toMatch(/admis/)
    expect(sentence).toMatch(/reprendre/)
    expect(sentence).not.toMatch(/admission\.txt/)
  })
})

describe('refusalSentence for the issuer delegation', () => {
  it('the_delegation_refusals_have_their_sentences', () => {
    expect(refusalSentence({ refusal: 'delegation_request_invalid' })).toBe(
      'Ce fichier n’est pas une demande de délégation lisible. Rien n’a été signé.',
    )
    expect(refusalSentence({ refusal: 'delegation_request_mismatch' })).toBe(
      'La campagne ne nomme pas cette demande, ou elle vise un autre domaine : époque ou clé substituée. Rien n’a été signé.',
    )
    expect(refusalSentence({ refusal: 'ca_tls_unusable' })).toBe(
      'La CA-TLS du domaine expire avant la fin de cette délégation, ou n’est pas une autorité : la renouveler d’abord. Rien n’a été signé.',
    )
  })

  it('the_rotation_refusals_have_their_labels', () => {
    expect(refusalSentence({ refusal: 'rotation_expired' })).toBe('Rotation expirée. Recommencer.')
    expect(refusalSentence({ refusal: 'domain_conflict' })).toBe(
      'Domaine en désaccord. Intervention manuelle requise.',
    )
    expect(refusalSentence({ refusal: 'install_deadline_passed' })).toBe(
      'Délai dépassé. Intervention manuelle requise.',
    )
    expect(refusalSentence({ refusal: 'rotation_in_flight' })).toBe(
      'Rotation en cours. La mener à son terme d’abord.',
    )
    expect(refusalSentence({ refusal: 'key_not_validated' })).toBe('Autre clé attendue.')
    expect(refusalSentence({ refusal: 'terms_refused' })).toBe(
      'Durées hors limites. Rien n’a été envoyé.',
    )
    expect(refusalSentence({ refusal: 'nothing_to_finish' })).toBe('Aucune rotation à terminer.')
  })

  it('the_stops_use_the_journal_when_the_screen_has_one', () => {
    const journal = {
      kind: 'ca_pq' as const,
      stage: 'applied' as const,
      activationAt: 1_800_000_000,
      notAfter: 1_802_000_000,
      nextFingerprint: 'aa',
      offline: true,
    }
    expect(refusalSentence({ refusal: 'domain_conflict' }, journal)).toMatch(
      /astra-signer rotate-ca-pq/,
    )
    expect(refusalSentence({ refusal: 'domain_conflict' }, { ...journal, offline: false })).not.toMatch(
      /astra-signer/,
    )
    expect(refusalSentence({ refusal: 'gateway_names_no_anchor' }, journal)).toMatch(/CA-PQ/)
    expect(refusalSentence({ refusal: 'install_deadline_passed' }, journal)).toMatch(
      /^Délai dépassé le .*Intervention manuelle requise/,
    )
  })

  it('a_gateway_naming_no_anchor_does_not_give_an_update_as_its_only_cause', () => {
    const sentence = refusalSentence({ refusal: 'gateway_names_no_anchor' })
    expect(sentence).toMatch(/sans CA TLS/)
    expect(sentence).toMatch(/mise à jour/)
    expect(sentence).toMatch(/conservée/)
  })

  it('a_key_marked_lost_is_said_at_its_validation_and_at_approval', () => {
    expect(retryLabel({ refusal: 'signer_revoked' }, 'validate_key')).toBe(
      'Clé marquée perdue ou révoquée',
    )
    expect(refusalSentence({ refusal: 'signer_revoked' }, null, 'rotate_anchor')).toBe(
      'Clé validée marquée perdue ou révoquée. Recommencer avec une clé active.',
    )
  })

  it('a_validation_says_what_the_key_is_asked', () => {
    const asked = { awaiting_key: { index: 1, of: 2, purpose: 'validate_key' as const } }
    expect(gestureSentence(asked, 'rotate_anchor')).toBe(
      'Brancher la clé autorisée (1 sur 2), pour la valider.',
    )
  })
})

describe('the words of a rotation', () => {
  const journal = {
    kind: 'ca_pq' as const,
    stage: 'signed' as const,
    activationAt: 1_800_000_000,
    notAfter: 1_802_000_000,
    nextFingerprint: 'aa',
    offline: false,
  }

  it('a_gateway_that_cannot_be_reached_is_worded_for_a_rotation', () => {
    for (const refusal of [
      { refusal: 'gateway_unavailable' as const },
      { refusal: 'gateway_refused' as const, status: 409 },
    ]) {
      const kept = refusalSentence(refusal, journal, 'rotate_anchor')
      expect(kept).toMatch(/^Gateway (injoignable|refuse)/)
      expect(kept).toMatch(/Rotation conservée/)
      expect(kept).not.toMatch(/admission\.txt/)
      const unknown = refusalSentence(refusal, null, 'rotate_client_tls_ca')
      expect(unknown).not.toMatch(/admission\.txt/)
      expect(unknown).not.toMatch(/conservée/)
    }
    expect(refusalSentence({ refusal: 'gateway_refused', status: 409 }, journal, 'rotate_anchor')).toMatch(
      /409/,
    )
  })

  it('an_enrollment_keeps_its_admission_wording', () => {
    expect(refusalSentence({ refusal: 'gateway_unavailable' }, null, 'accept_enrollment')).toMatch(
      /admission\.txt/,
    )
  })

  it('the_door_and_the_campaign_have_their_labels_in_a_rotation', () => {
    expect(refusalSentence({ refusal: 'window_expired' }, null, 'rotate_anchor', true)).toBe(
      'Campagne expirée',
    )
    // Before the opening there is no campaign to call expired.
    expect(refusalSentence({ refusal: 'window_expired' }, null, 'rotate_anchor', false)).toBe(
      'Délai écoulé. Clés oubliées. Recommencer',
    )
    expect(
      refusalSentence({ refusal: 'authority_refused', status: 429 }, null, 'rotate_anchor'),
    ).toBe('Trop d’opérations en attente')
    expect(
      refusalSentence({ refusal: 'authority_refused', status: 403 }, null, 'rotate_anchor'),
    ).toBe('Opération déjà ouverte, ou poste non administrateur')
    expect(
      refusalSentence({ refusal: 'authority_refused', status: 500 }, null, 'rotate_anchor'),
    ).toBe('L’autorité a décliné (500).')
    // Other ceremonies keep their sentences.
    expect(refusalSentence({ refusal: 'window_expired' }, null, 'approve_campaign')).toMatch(
      /refermée/,
    )
  })

  it('a_cancel_after_the_opening_does_not_say_nothing_left_this_machine', () => {
    expect(gestureSentence('cancelled', 'rotate_anchor')).toBe(
      'Abandonné. Rien n’a quitté cette machine.',
    )
    const opened = gestureSentence('cancelled', 'rotate_anchor', true)
    expect(opened).toBe('Abandonné. Campagne encore ouverte, 5 min au plus.')
    expect(opened).not.toMatch(/Rien n’a quitté/)
  })

  it('the_reason_a_key_is_asked_again_is_a_label', () => {
    const validating = 'validate_key' as const
    expect(retryLabel({ refusal: 'key_repeated' }, validating)).toBe('Même clé que la clé 1')
    expect(retryLabel({ refusal: 'key_repeated' }, 'approve_campaign')).toBe('Clé déjà approuvée')
    expect(retryLabel({ refusal: 'key_not_enrolled' }, validating)).toBe('Clé absente du coffre')
    expect(retryLabel({ refusal: 'key_not_validated' }, 'approve_campaign')).toBe(
      'Autre clé attendue',
    )
    expect(retryLabel({ refusal: 'key_declined' }, validating)).toBe('Clé sans réponse')
    expect(retryLabel({ refusal: 'terms_refused' }, null)).toBe('Durées hors limites')
    expect(retryLabel({ refusal: 'foreground_unavailable' }, validating)).toMatch(/Windows/)
  })
})
