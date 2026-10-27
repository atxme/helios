import { describe, expect, it } from 'vitest'
import { refusalSentence } from './OperatorCeremony'

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
})
