import { describe, expect, it } from 'vitest'
import { gestureSentence, refusalSentence } from './OperatorCeremony'

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
    expect(refusalSentence({ refusal: 'key_not_validated' })).toBe('Clé non validée.')
  })

  it('a_gateway_naming_no_anchor_does_not_give_an_update_as_its_only_cause', () => {
    const sentence = refusalSentence({ refusal: 'gateway_names_no_anchor' })
    expect(sentence).toMatch(/sans CA TLS/)
    expect(sentence).toMatch(/mise à jour/)
    expect(sentence).toMatch(/conservée/)
  })

  it('a_validation_says_what_the_key_is_asked', () => {
    const asked = { awaiting_key: { index: 1, of: 2, purpose: 'validate_key' as const } }
    expect(gestureSentence(asked, 'rotate_anchor')).toBe(
      'Brancher la clé autorisée (1 sur 2), pour la valider.',
    )
  })
})
