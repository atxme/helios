import { describe, expect, it } from 'vitest'
import { refusalSentence, rowsOf, gestureSentence } from './OperatorCeremony'
import type { DomainFinalizationManifest, Refusal } from '../types'

describe('the vault gestures in the ceremony window', () => {
  it('every_new_refusal_has_its_sentence', () => {
    const cases: [Refusal['refusal'], string][] = [
      [
        'vault_exists',
        'Un coffre existe déjà à cet emplacement : ajouter une clé plutôt que créer un second domaine.',
      ],
      [
        'location_unavailable',
        'L’emplacement du coffre est introuvable : rebrancher son support ou choisir un autre emplacement.',
      ],
      ['vault_full', 'Le coffre porte déjà huit clés : en retirer une avant d’en ajouter.'],
      [
        'minimum_keys',
        'Le coffre doit garder au moins deux clés : en ajouter une avant d’en retirer.',
      ],
      [
        'key_being_removed',
        'La clé qui a ouvert le coffre est celle à retirer : recommencer avec une autre clé.',
      ],
      [
        'gateway_identity_missing',
        'Le relais ne nomme pas encore la gateway, ou le document de credentials en place ne se vérifie pas : reprendre la gateway connectée, ou restaurer le document de credentials depuis une sauvegarde.',
      ],
      [
        'domain_complete',
        'Le domaine est déjà finalisé : CA-TLS et document de credentials sont en place.',
      ],
    ]
    for (const [refusal, sentence] of cases) {
      expect(refusalSentence({ refusal } as Refusal)).toBe(sentence)
    }
  })

  it('a_new_key_is_asked_for_by_name', () => {
    const second = gestureSentence(
      { awaiting_key: { index: 2, of: 2, purpose: 'register_key' } },
      'create_domain',
    )
    expect(second).toContain('Débrancher la clé précédente')
    expect(second).toContain('nouvelle clé (2 sur 2)')
    const first = gestureSentence(
      { awaiting_key: { index: 1, of: 1, purpose: 'register_key' } },
      'add_key',
    )
    expect(first).not.toContain('Débrancher')
    expect(first).toBe('Brancher la nouvelle clé, pour l’enregistrer dans le coffre.')
  })

  it('the_finalization_manifest_says_what_it_issues', () => {
    const manifest: DomainFinalizationManifest = {
      operation: 'domain_finalization',
      vault_fingerprint: 'a'.repeat(64),
      server_name: 'gw.example.net',
      gateway_wg_public_key: 'k'.repeat(44),
      issues_ca_tls: true,
      ca_tls_days: 3650,
      issues_credentials: true,
    }
    const issued = rowsOf(manifest)
    expect(issued).toContainEqual(['CA-TLS', 'émise, 3650 jours'])
    expect(issued).toContainEqual(['credentials', 'émis'])
    const kept = rowsOf({ ...manifest, issues_ca_tls: false, issues_credentials: false })
    expect(kept).toContainEqual(['CA-TLS', 'déjà en place'])
    expect(kept).toContainEqual(['credentials', 'à jour'])
  })
})
