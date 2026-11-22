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
    "Séquestre d'un ancien format, qui ne porte pas le compteur : il faut le séquestre réécrit par la gateway après son passage à F5 (voir MAINTENANCE, « Passage au compteur NV »).",
  escrow_inconsistent: "Le séquestre ne correspond pas à la clé qu'il contient.",
  counter_unknown: 'Valeur du compteur inconnue : lisez-la sur la gateway et saisissez-la.',
  authorization_invalid: "Autorisation non valide : signature manquante ou d'un autre éditeur.",
  foreign_gateway: 'Cette autorisation vise une autre gateway.',
  request_mismatch:
    'Cette autorisation ne correspond pas à la requête préparée (autre valeur de compteur ou autre gateway).',
  frame_malformed: 'Fichier de récupération mal formé.',
  request_malformed: 'Requête préparée illisible ou mal formée.',
  platform_unsupported: "Cette cérémonie n'existe que sous Windows.",
}

const ORIGIN_AFTER_TICKET =
  "Valeur déduite du séquestre, en supposant qu'un billet a été consommé. Vérifiez anti-rollback.json sur la gateway."
const depositReminder = (fileName: string) =>
  `Fichier enregistré : ${fileName}. À déposer dans /var/lib/helios/wg-key.recovery par l'accès hors bande, puis redémarrer heliosd. Ce fichier contient la clé privée en clair : supprimez-le après usage.`

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

const fillPrepare = () => {
  pickFile(prepareStep().getByLabelText('Séquestre (wg-key.escrow)'), escrow())
}

/** Fills step 2 and waits until its files are read and the assemble button is enabled. */
const fillAssemble = async (authorization = '{"signed":true}') => {
  pickFile(assembleStep().getByLabelText('Séquestre (wg-key.escrow)'), escrow())
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
    expect(api.gatewayRecoveryPrepare).toHaveBeenCalledWith('AQID', null)
    expect(block().getByText(ORIGIN_AFTER_TICKET)).toBeTruthy()

    fireEvent.click(block().getByRole('button', { name: 'Enregistrer wg-recovery-request.json' }))
    expect(artifacts.saveArtifact).toHaveBeenCalledWith(prepared.request)
  })

  it('shows no key input: the key is chosen in a native dialog', () => {
    render(<GatewayRecoveryBlock />)

    expect(block().queryByLabelText('Clé de séquestre')).toBeNull()
    expect(block().queryByDisplayValue('OPERATOR-KEY')).toBeNull()
    expect(prepareStep().getByText(/elle ne passe jamais par cette page/)).toBeTruthy()
  })

  it('assembles through the dialogs and names only the written file', async () => {
    api.gatewayRecoveryPrepare.mockResolvedValue(prepared)
    api.gatewayRecoveryAssemble.mockResolvedValue({ file_name: 'wg-key.recovery' })
    render(<GatewayRecoveryBlock />)

    fillPrepare()
    fireEvent.click(prepareStep().getByRole('button', { name: 'Préparer la requête' }))
    await waitFor(() => expect(block().getByText('PUBLIC-KEY-B64')).toBeTruthy())

    await fillAssemble('{"signed":true}')
    fireEvent.click(assembleStep().getByRole('button', { name: 'Assembler le fichier' }))

    await waitFor(() =>
      expect(block().getByText(depositReminder('wg-key.recovery'))).toBeTruthy(),
    )
    expect(api.gatewayRecoveryAssemble).toHaveBeenCalledWith(
      'AQID',
      '{"counter":6}',
      '{"signed":true}',
    )
    // No key and no frame reach the page: the frame is written by Orion, never saved here.
    expect(artifacts.saveArtifact).not.toHaveBeenCalled()
  })

  it('shows a fixed sentence, never the text of an unexpected failure', async () => {
    api.gatewayRecoveryAssemble.mockRejectedValueOnce(new Error('C:\\secret\\path'))
    render(<GatewayRecoveryBlock />)

    await fillAssemble()
    fireEvent.click(assembleStep().getByRole('button', { name: 'Assembler le fichier' }))

    await waitFor(() => expect(block().getByText('Erreur inattendue.')).toBeTruthy())
    expect(block().queryByText(/secret/)).toBeNull()
  })

  it('shows no error when the operator cancels a dialog', async () => {
    api.gatewayRecoveryPrepare.mockResolvedValue(null)
    api.gatewayRecoveryAssemble.mockResolvedValue(null)
    render(<GatewayRecoveryBlock />)

    fillPrepare()
    fireEvent.click(prepareStep().getByRole('button', { name: 'Préparer la requête' }))
    await waitFor(() => expect(api.gatewayRecoveryPrepare).toHaveBeenCalled())
    expect(block().queryByRole('alert')).toBeNull()
    expect(block().queryByText(/Clé publique de la gateway/)).toBeNull()

    await fillAssemble()
    fireEvent.click(assembleStep().getByRole('button', { name: 'Assembler le fichier' }))
    await waitFor(() => expect(api.gatewayRecoveryAssemble).toHaveBeenCalled())
    expect(block().queryByRole('alert')).toBeNull()
    expect(block().queryByText(/Fichier enregistré/)).toBeNull()
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
    expect(codes).toHaveLength(10)
  })
})
