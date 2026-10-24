// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { InvitationPreview, PendingEnrollment } from '../types'

const api = vi.hoisted(() => ({
  previewEnrollmentInvitation: vi.fn(),
  beginEnrollment: vi.fn(),
  listPendingEnrollments: vi.fn(),
  discardPendingEnrollment: vi.fn(),
  exportPendingRequest: vi.fn(),
}))
const documents = vi.hoisted(() => ({ readProfileDocument: vi.fn() }))

vi.mock('../api', () => api)
vi.mock('../profileDocument', () => ({ readProfileDocument: documents.readProfileDocument }))

import { EnrollmentPanel } from './EnrollmentPanel'

const preview: InvitationPreview = {
  server_name: 'vpn.example.net',
  ca_fingerprint: 'abcd 0123 4567 89ef',
  expires_at_unix: 1_800_000_000,
  invitation_token: 'invitation-text',
}

const pending: PendingEnrollment = {
  invitation_id: '01'.repeat(16),
  request_id: '02'.repeat(16),
  requested_name: 'poste-windows',
  server_name: 'vpn.example.net',
  created_at_unix: 1_799_999_000,
  invitation_expires_at_unix: 1_800_000_000,
}

const chooseInvitation = () => {
  const input = document.querySelector('input[type="file"]') as HTMLInputElement
  Object.defineProperty(input, 'files', {
    value: [new File(['invitation-text'], 'poste.helios-invite')],
  })
  fireEvent.change(input)
}

describe('EnrollmentPanel', () => {
  beforeEach(() => {
    documents.readProfileDocument.mockResolvedValue('invitation-text')
    api.listPendingEnrollments.mockResolvedValue([])
    api.previewEnrollmentInvitation.mockResolvedValue(preview)
    api.beginEnrollment.mockResolvedValue('request-text')
    api.discardPendingEnrollment.mockResolvedValue(undefined)
    api.exportPendingRequest.mockResolvedValue('request-text')
  })

  afterEach(() => {
    cleanup()
    vi.clearAllMocks()
  })

  it('the_request_button_stays_disabled_until_the_fingerprint_matches', async () => {
    render(<EnrollmentPanel />)
    chooseInvitation()

    await waitFor(() => expect(screen.getByText('vpn.example.net')).toBeTruthy())
    expect(screen.getByText('abcd 0123 4567 89ef')).toBeTruthy()
    const create = screen.getByRole('button', { name: 'Créer la demande' }) as HTMLButtonElement
    fireEvent.change(screen.getByLabelText('Nom du poste'), { target: { value: 'poste-windows' } })
    expect(create.disabled).toBe(true)

    const typed = screen.getByLabelText('Empreinte lue par l’opérateur')
    fireEvent.change(typed, { target: { value: 'abcd 0123 4567 89e0' } })
    expect(create.disabled).toBe(true)

    // Spacing and case are how a fingerprint is read aloud, not what it is.
    fireEvent.change(typed, { target: { value: 'ABCD01234567 89EF' } })
    expect(create.disabled).toBe(false)

    fireEvent.click(create)
    await waitFor(() =>
      expect(api.beginEnrollment).toHaveBeenCalledWith(
        'invitation-text',
        'ABCD01234567 89EF',
        'poste-windows',
      ),
    )
    await waitFor(() =>
      expect(screen.getByRole('button', { name: 'Enregistrer la demande' })).toBeTruthy(),
    )
  })

  it('a_pending_enrollment_is_listed_and_can_be_discarded', async () => {
    api.listPendingEnrollments.mockResolvedValueOnce([pending]).mockResolvedValue([])
    render(<EnrollmentPanel />)

    await waitFor(() => expect(screen.getByText('poste-windows')).toBeTruthy())
    expect(screen.getByText(/vpn\.example\.net/)).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: 'Abandonner' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Abandonner la demande' }))

    await waitFor(() =>
      expect(api.discardPendingEnrollment).toHaveBeenCalledWith(pending.request_id),
    )
    await waitFor(() => expect(screen.queryByText('poste-windows')).toBeNull())
  })

  it('a_pending_request_can_be_saved_again_from_the_list', async () => {
    api.listPendingEnrollments.mockResolvedValue([pending])
    const createObjectURL = vi.fn(() => 'blob:request')
    Object.assign(URL, { createObjectURL, revokeObjectURL: vi.fn() })
    render(<EnrollmentPanel />)

    fireEvent.click(await screen.findByRole('button', { name: 'Enregistrer' }))

    await waitFor(() =>
      expect(api.exportPendingRequest).toHaveBeenCalledWith(pending.request_id),
    )
    await waitFor(() => expect(createObjectURL).toHaveBeenCalled())
  })

  it('an_invitation_preview_error_is_shown_in_place', async () => {
    api.previewEnrollmentInvitation.mockRejectedValue(
      'cette invitation a expiré : en demander une nouvelle à l’opérateur',
    )
    render(<EnrollmentPanel />)
    chooseInvitation()

    await waitFor(() => expect(screen.getByText(/cette invitation a expiré/)).toBeTruthy())
    expect(screen.queryByRole('button', { name: 'Créer la demande' })).toBeNull()
    expect(api.beginEnrollment).not.toHaveBeenCalled()
  })
})
