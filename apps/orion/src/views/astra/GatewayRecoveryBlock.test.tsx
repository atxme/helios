// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({
  gatewayRecoveryPrepare: vi.fn(),
  gatewayRecoveryAssemble: vi.fn(),
}))
vi.mock('../../api', () => api)

const artifacts = vi.hoisted(() => ({ saveArtifact: vi.fn() }))
vi.mock('./ArtifactDownloads', () => ({ saveArtifact: artifacts.saveArtifact }))

import type { RecoveryPrepared, RecoveryRefusalCode } from '../../types'
import { GatewayRecoveryBlock } from './GatewayRecoveryBlock'

const SENTENCES: Record<RecoveryRefusalCode, string> = {
  escrow_unreadable: 'Séquestre illisible avec cette clé.',
  legacy_escrow:
    "Séquestre d'un ancien format : redémarrez la gateway pour qu'elle l'écrive au nouveau format, puis recommencez.",
  escrow_inconsistent: "Le séquestre ne correspond pas à la clé qu'il contient.",
  counter_unknown: 'Valeur du compteur inconnue : lisez-la sur la gateway et saisissez-la.',
  authorization_invalid: "Autorisation non valide : signature manquante ou d'un autre éditeur.",
  foreign_gateway: 'Cette autorisation vise une autre gateway.',
  request_mismatch:
    'Cette autorisation ne correspond pas à la requête préparée (autre valeur de compteur ou autre gateway).',
  frame_malformed: 'Fichier de récupération mal formé.',
}

const ORIGIN_AFTER_TICKET =
  "Valeur déduite du séquestre, en supposant qu'un billet a été consommé. Vérifiez anti-rollback.json sur la gateway."
const DEPOSIT_REMINDER =
  "À déposer dans /var/lib/helios/wg-key.recovery par l'accès hors bande, puis redémarrer heliosd. Ce fichier contient la clé privée en clair : supprimez-le après usage."

const prepared: RecoveryPrepared = {
  gateway_public_key: 'PUBLIC-KEY-B64',
  counter: 6,
  counter_source: 'escrow_after_ticket',
  request: { file_name: 'wg-recovery-request.json', contents: '{"counter":6}', encoding: 'text' },
}

const block = () => within(screen.getByRole('region', { name: "Récupérer l'identité de la gateway" }))
const prepareStep = () => within(screen.getByRole('region', { name: 'Préparation de la requête' }))
const assembleStep = () => within(screen.getByRole('region', { name: 'Autorisation signée' }))

/** The escrow bytes 1, 2, 3 are "AQID" in base64. */
const escrow = () => new File([new Uint8Array([1, 2, 3])], 'wg-key.escrow')

const pickFile = (input: HTMLElement, file: File) =>
  fireEvent.change(input, { target: { files: [file] } })

const fillPrepare = (key = 'OPERATOR-KEY') => {
  pickFile(prepareStep().getByLabelText('Séquestre (wg-key.escrow)'), escrow())
  fireEvent.change(prepareStep().getByLabelText('Clé de séquestre'), { target: { value: key } })
}

/** Fills step 2 and waits until its files are read and the assemble button is enabled. */
const fillAssemble = async (authorization = '{"signed":true}') => {
  pickFile(assembleStep().getByLabelText('Séquestre (wg-key.escrow)'), escrow())
  fireEvent.change(assembleStep().getByLabelText('Clé de séquestre'), {
    target: { value: 'OPERATOR-KEY' },
  })
  pickFile(
    assembleStep().getByLabelText('Requête préparée (wg-recovery-request.json)'),
    new File(['{"counter":6}'], 'wg-recovery-request.json'),
  )
  pickFile(
    assembleStep().getByLabelText('Autorisation signée (wg-recovery-authorization.json)'),
    new File([authorization], 'wg-recovery-authorization.json'),
  )
  await waitFor(() =>
    expect(
      (assembleStep().getByRole('button', { name: 'Assembler le fichier' }) as HTMLButtonElement)
        .disabled,
    ).toBe(false),
  )
}

beforeEach(() => {
  vi.clearAllMocks()
})

afterEach(() => {
  cleanup()
})

describe('GatewayRecoveryBlock', () => {
  it('prepares then offers the request with its counter origin', async () => {
    api.gatewayRecoveryPrepare.mockResolvedValue(prepared)
    render(<GatewayRecoveryBlock />)

    fillPrepare()
    fireEvent.click(prepareStep().getByRole('button', { name: 'Préparer la requête' }))

    await waitFor(() => expect(block().getByText('PUBLIC-KEY-B64')).toBeTruthy())
    expect(api.gatewayRecoveryPrepare).toHaveBeenCalledWith('AQID', 'OPERATOR-KEY', null)
    expect(block().getByText(ORIGIN_AFTER_TICKET)).toBeTruthy()

    fireEvent.click(block().getByRole('button', { name: 'Enregistrer wg-recovery-request.json' }))
    expect(artifacts.saveArtifact).toHaveBeenCalledWith(prepared.request)
  })

  it('assembles and reminds where to deposit the file', async () => {
    api.gatewayRecoveryPrepare.mockResolvedValue(prepared)
    api.gatewayRecoveryAssemble.mockResolvedValue({
      file_name: 'wg-key.recovery',
      contents: 'RkFLRQ==',
      encoding: 'base64',
    })
    render(<GatewayRecoveryBlock />)

    fillPrepare()
    fireEvent.click(prepareStep().getByRole('button', { name: 'Préparer la requête' }))
    await waitFor(() => expect(block().getByText('PUBLIC-KEY-B64')).toBeTruthy())

    await fillAssemble('{"signed":true}')
    fireEvent.click(assembleStep().getByRole('button', { name: 'Assembler le fichier' }))

    await waitFor(() => expect(artifacts.saveArtifact).toHaveBeenCalled())
    expect(api.gatewayRecoveryAssemble).toHaveBeenCalledWith(
      'AQID',
      'OPERATOR-KEY',
      '{"counter":6}',
      '{"signed":true}',
    )
    expect(artifacts.saveArtifact).toHaveBeenCalledWith({
      file_name: 'wg-key.recovery',
      contents: 'RkFLRQ==',
      encoding: 'base64',
    })
    expect(block().getByText(DEPOSIT_REMINDER)).toBeTruthy()
  })

  it('shows the French sentence for each refusal code', async () => {
    const codes = Object.keys(SENTENCES) as RecoveryRefusalCode[]
    for (const code of codes) {
      api.gatewayRecoveryAssemble.mockRejectedValueOnce({ refusal: code })
      const { unmount } = render(<GatewayRecoveryBlock />)

      await fillAssemble()
      fireEvent.click(assembleStep().getByRole('button', { name: 'Assembler le fichier' }))

      await waitFor(() => expect(block().getByText(SENTENCES[code])).toBeTruthy())
      expect(artifacts.saveArtifact).not.toHaveBeenCalled()
      unmount()
    }
    expect(codes).toHaveLength(8)
  })
})
