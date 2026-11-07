// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const api = vi.hoisted(() => ({
  operatorRotationsOverview: vi.fn(),
  operatorSendVaultCopy: vi.fn(),
  operatorOpenCampaign: vi.fn(),
  beginOperatorCeremony: vi.fn(),
  beginIssuerCeremony: vi.fn(),
  beginRotationCeremony: vi.fn(),
}))
vi.mock('../../api', () => api)

import type { OperatorPendingOperation, RotationsOverview } from '../../types'
import { RotationsPanel } from './RotationsPanel'
import { RotationSteps } from './RotationSteps'
import { NOW, authorityRead, overview } from './rotationFixtures'

const operation = (scope: OperatorPendingOperation['scope']): OperatorPendingOperation => ({
  operation_id: 'c'.repeat(32),
  scope,
  reason: 'motif',
  requested_by: 'christophe',
  target_count: 2,
  required_credentials: 1,
  campaign_fingerprint: 'a'.repeat(64),
  created_at: NOW,
  expires_at: NOW + 300,
})

const ceremony = { session_id: 's', revision: 1, operation: 'approve_campaign' }

const region = (name: string) => screen.getByRole('region', { name })
const prerequisitesOf = () => within(screen.getByRole('region', { name: 'Prérequis' }))

const show = async (o: RotationsOverview = overview()) => {
  api.operatorRotationsOverview.mockResolvedValue(o)
  const onCeremony = vi.fn()
  const onOverview = vi.fn()
  render(
    <RotationsPanel
      onCeremony={onCeremony}
      onOverview={onOverview}
    />,
  )
  await screen.findByRole('region', { name: 'Renouveler les postes' })
  return { onCeremony, onOverview }
}

const choose = (title: string) =>
  fireEvent.click(within(region(title)).getByRole('button'))

beforeEach(() => {
  vi.clearAllMocks()
  vi.useRealTimers()
})
afterEach(cleanup)

describe('the rows', () => {
  it('shows_each_row_with_its_state_and_reports_the_read', async () => {
    const { onOverview } = await show()
    expect(within(region('Renouveler les postes')).getByText(/2 postes/)).toBeTruthy()
    expect(within(region('Remplacer la CA-PQ')).getByText('2 clés')).toBeTruthy()
    expect(onOverview).toHaveBeenCalledWith(expect.objectContaining({ tunnel: true }))
  })

  it('a_row_to_do_comes_first_and_a_disabled_row_says_why', async () => {
    await show(overview({ caPqOverlap: true, caTlsCloseAt: NOW - 1 }))
    const titles = screen.getAllByRole('region').map((r) => r.getAttribute('aria-label'))
    expect(titles[0]).toBe('Terminer la rotation CA TLS')
    const replace = region('Remplacer la CA-PQ')
    expect(within(replace).getByText('Recouvrement CA-PQ en cours')).toBeTruthy()
    expect(within(replace).getByRole('button').hasAttribute('disabled')).toBe(true)
  })

  it('an_unreachable_and_a_refusing_gateway_read_differently', async () => {
    await show(overview({ domain: { state: 'unreachable' } }))
    expect(screen.getByText(/Domaine : Gateway injoignable/)).toBeTruthy()
    expect(screen.queryByText(/ancienne ou refus/)).toBeNull()
    cleanup()
    await show(overview({ domain: { state: 'refused', value: 404 } }))
    expect(screen.getAllByText(/Gateway ancienne ou refus \(404\)/).length).toBeGreaterThan(0)
    expect(screen.queryByText(/injoignable/)).toBeNull()
  })

  it('a_resumable_rotation_shows_a_resume_row_without_a_journal', async () => {
    await show(overview({ resumable: true }))
    expect(within(region('Reprendre une rotation')).getByText('À reprendre')).toBeTruthy()
  })
})

describe('the prerequisites', () => {
  it('a_red_prerequisite_disables_the_next_step_and_never_calls_open', async () => {
    await show(overview({ tunnel: false }))
    choose('Renouveler les postes')
    const lines = prerequisitesOf()
    expect(lines.getByText('Tunnel connecté')).toBeTruthy()
    expect(lines.getByText('Connecter')).toBeTruthy()
    const next = lines.getByRole('button', { name: 'Continuer' })
    expect(next.hasAttribute('disabled')).toBe(true)
    fireEvent.click(next)
    expect(api.operatorOpenCampaign).not.toHaveBeenCalled()
    expect(api.beginOperatorCeremony).not.toHaveBeenCalled()
  })

  it('green_prerequisites_open_the_campaign_then_the_ceremony', async () => {
    api.operatorOpenCampaign.mockResolvedValue({ operation_id: 'd'.repeat(32) })
    api.beginOperatorCeremony.mockResolvedValue(ceremony)
    const { onCeremony } = await show()
    choose('Renouveler les postes')
    fireEvent.click(prerequisitesOf().getByRole('button', { name: 'Continuer' }))
    await waitFor(() => expect(onCeremony).toHaveBeenCalledWith(ceremony))
    expect(api.operatorOpenCampaign).toHaveBeenCalledWith(
      { action: 'fleet_leafs' },
      'Renouvellement des postes',
      'Clé 1',
    )
    expect(api.beginOperatorCeremony).toHaveBeenCalledWith({
      kind: 'approve_campaign',
      operation_id: 'd'.repeat(32),
    })
  })

  it('a_live_operation_is_resumed_and_not_opened_again', async () => {
    api.beginOperatorCeremony.mockResolvedValue(ceremony)
    const { onCeremony } = await show(
      overview({ pending: { state: 'ok', value: [operation('fleet_leafs')] } }),
    )
    expect(within(region('Renouveler les postes')).getByRole('button').textContent).toBe('Reprendre')
    choose('Renouveler les postes')
    fireEvent.click(prerequisitesOf().getByRole('button', { name: 'Reprendre l’opération ouverte' }))
    await waitFor(() => expect(onCeremony).toHaveBeenCalled())
    expect(api.operatorOpenCampaign).not.toHaveBeenCalled()
    expect(api.beginOperatorCeremony).toHaveBeenCalledWith({
      kind: 'approve_campaign',
      operation_id: 'c'.repeat(32),
    })
  })

  it('after_a_403_the_pending_operations_are_read_and_the_operation_is_offered', async () => {
    api.operatorOpenCampaign.mockRejectedValue('refusé (403) : ...')
    await show()
    choose('Renouveler les postes')
    // Nothing is pending at the read before the opening; the campaign appears in between.
    api.operatorRotationsOverview.mockResolvedValueOnce(overview())
    api.operatorRotationsOverview.mockResolvedValue(
      overview({ pending: { state: 'ok', value: [operation('fleet_leafs')] } }),
    )
    fireEvent.click(prerequisitesOf().getByRole('button', { name: 'Continuer' }))
    expect(await screen.findByText('Opération déjà ouverte')).toBeTruthy()
    expect(screen.queryByText(/403/)).toBeNull()
    await waitFor(() =>
      expect(within(region('Renouveler les postes')).getByRole('button').textContent).toBe(
        'Reprendre',
      ),
    )
  })

  it('pending_is_read_again_before_the_fleet_opens_so_an_open_campaign_is_not_opened_twice', async () => {
    api.beginOperatorCeremony.mockResolvedValue(ceremony)
    const { onCeremony } = await show()
    choose('Renouveler les postes')
    api.operatorRotationsOverview.mockResolvedValue(
      overview({ pending: { state: 'ok', value: [operation('fleet_leafs')] } }),
    )
    fireEvent.click(prerequisitesOf().getByRole('button', { name: 'Continuer' }))
    await waitFor(() => expect(onCeremony).toHaveBeenCalledWith(ceremony))
    expect(api.operatorOpenCampaign).not.toHaveBeenCalled()
    expect(api.beginOperatorCeremony).toHaveBeenCalledWith({
      kind: 'approve_campaign',
      operation_id: 'c'.repeat(32),
    })
  })

  it('a_refusal_with_nothing_pending_is_an_error', async () => {
    api.operatorOpenCampaign.mockRejectedValue('refusé (403) : ...')
    await show()
    choose('Renouveler les postes')
    fireEvent.click(prerequisitesOf().getByRole('button', { name: 'Continuer' }))
    expect(await screen.findByText(/403/)).toBeTruthy()
  })

  it('the_delegation_opens_with_its_request_and_hands_it_to_the_ceremony', async () => {
    api.operatorOpenCampaign.mockResolvedValue({
      operation_id: 'd'.repeat(32),
      delegation_request: '{"request":1}',
    })
    api.beginIssuerCeremony.mockResolvedValue(ceremony)
    const { onCeremony } = await show()
    choose('Renouveler la délégation')
    fireEvent.click(prerequisitesOf().getByRole('button', { name: 'Continuer' }))
    await waitFor(() => expect(onCeremony).toHaveBeenCalled())
    expect(api.beginIssuerCeremony).toHaveBeenCalledWith({
      gesture: 'authorize_issuer',
      operation_id: 'd'.repeat(32),
      request: '{"request":1}',
    })
  })

  it('a_live_delegation_is_shown_open_with_no_resume_and_no_new_opening', async () => {
    await show(
      overview({
        pending: {
          state: 'ok',
          value: [{ ...operation('issuer_delegation'), expires_at: NOW + 200 }],
        },
      }),
    )
    const row = within(region('Renouveler la délégation'))
    expect(row.getByText(/Opération ouverte jusqu’au/)).toBeTruthy()
    expect(row.queryByText('Reprendre')).toBeNull()
    expect(row.getByRole('button').hasAttribute('disabled')).toBe(true)
    expect(api.operatorOpenCampaign).not.toHaveBeenCalled()
  })

  it('a_live_CA_campaign_shows_its_reason_on_both_replace_rows', async () => {
    await show(
      overview({
        pending: { state: 'ok', value: [{ ...operation('trust_authorities'), reason: 'ancres 2027' }] },
      }),
    )
    for (const title of ['Remplacer la CA-PQ', 'Remplacer la CA TLS']) {
      const row = within(region(title))
      expect(row.getByText(/ancres 2027/)).toBeTruthy()
      expect(row.getByRole('button').textContent).toBe('Reprendre')
    }
  })
})

describe('a row that becomes impossible after it was chosen', () => {
  it('keeps_the_next_step_from_starting', async () => {
    api.beginOperatorCeremony.mockResolvedValue(ceremony)
    await show()
    choose('Renouveler les postes')
    const next = prerequisitesOf().getByRole('button', { name: 'Continuer' })
    expect(next.hasAttribute('disabled')).toBe(false)
    api.operatorRotationsOverview.mockResolvedValue(overview({ caPqOverlap: true }))
    fireEvent.click(prerequisitesOf().getByRole('button', { name: 'Vérifier' }))
    await waitFor(() =>
      expect(
        prerequisitesOf().getByRole('button', { name: 'Continuer' }).hasAttribute('disabled'),
      ).toBe(true),
    )
    fireEvent.click(prerequisitesOf().getByRole('button', { name: 'Continuer' }))
    expect(api.operatorOpenCampaign).not.toHaveBeenCalled()
    expect(api.beginOperatorCeremony).not.toHaveBeenCalled()
  })

  it('unmounts_a_CA_step_that_has_not_started_when_its_row_is_disabled', async () => {
    const renderStep = vi.fn(() => <p>étape</p>)
    api.operatorRotationsOverview.mockResolvedValue(overview())
    render(<RotationsPanel onCeremony={vi.fn()} renderStep={renderStep} />)
    await screen.findByRole('region', { name: 'Remplacer la CA TLS' })
    choose('Remplacer la CA TLS')
    expect(await screen.findByText('étape')).toBeTruthy()
    api.operatorRotationsOverview.mockResolvedValue(overview({ resumable: true }))
    fireEvent.click(prerequisitesOf().getByRole('button', { name: 'Vérifier' }))
    await waitFor(() => expect(screen.queryByText('étape')).toBeNull())
  })
})

describe('a step that has started', () => {
  it('hands_over_even_when_the_row_turns_disabled_during_the_start', async () => {
    let release: (value: unknown) => void = () => {}
    api.beginRotationCeremony.mockImplementation(
      () => new Promise((resolve) => (release = resolve)),
    )
    const onCeremony = vi.fn()
    api.operatorRotationsOverview.mockResolvedValue(overview())
    render(
      <RotationsPanel
        onCeremony={onCeremony}
        renderStep={(context) => <RotationSteps {...context} />}
      />,
    )
    await screen.findByRole('region', { name: 'Remplacer la CA TLS' })
    choose('Remplacer la CA TLS')
    fireEvent.click(await screen.findByRole('button', { name: 'Continuer' }))
    await waitFor(() => expect(api.beginRotationCeremony).toHaveBeenCalled())

    // A poll flips the row: the step is gone, but the start it made is not lost.
    api.operatorRotationsOverview.mockResolvedValue(overview({ resumable: true }))
    fireEvent.click(prerequisitesOf().getByRole('button', { name: 'Vérifier' }))
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Continuer' })).toBeNull())
    release(ceremony)
    await waitFor(() => expect(onCeremony).toHaveBeenCalledWith(ceremony, null))
  })

  it('shows_the_stop_of_an_automatic_resumption_in_its_row', async () => {
    api.operatorRotationsOverview.mockResolvedValue(overview({ resumable: true }))
    render(
      <RotationsPanel
        onCeremony={vi.fn()}
        resumeStop="Délai dépassé le 15 janv. 2027. Intervention manuelle requise."
      />,
    )
    const row = await screen.findByRole('region', { name: 'Reprendre une rotation' })
    expect(within(row).getByText(/Intervention manuelle requise/)).toBeTruthy()
  })
})

describe('the vault copy', () => {
  const absent = () =>
    overview({
      authority: { state: 'ok', value: authorityRead({ vault_copy_fingerprint: null }) },
    })

  it('the_vault_copy_is_sent_from_the_prerequisite', async () => {
    api.operatorSendVaultCopy.mockResolvedValue({
      state: 'copied',
      fingerprint: 'ef'.repeat(32),
      credential_registry_epoch: 5,
    })
    await show(absent())
    choose('Remplacer la CA TLS')
    expect(prerequisitesOf().getByText('Absente')).toBeTruthy()
    api.operatorRotationsOverview.mockResolvedValue(overview())
    const reads = api.operatorRotationsOverview.mock.calls.length
    fireEvent.click(prerequisitesOf().getByRole('button', { name: 'Envoyer' }))
    await waitFor(() => expect(prerequisitesOf().queryByText('Absente')).toBeNull())
    expect(api.operatorSendVaultCopy).toHaveBeenCalledTimes(1)
    expect(api.operatorRotationsOverview.mock.calls.length).toBeGreaterThan(reads)
  })

  it('an_old_copy_reads_old', async () => {
    await show(
      overview({
        authority: { state: 'ok', value: authorityRead({ vault_copy_fingerprint: '99'.repeat(32) }) },
      }),
    )
    choose('Remplacer la CA-PQ')
    expect(prerequisitesOf().getByText('Ancienne')).toBeTruthy()
  })

  it('a_held_back_copy_shows_as_waiting_and_not_as_an_error', async () => {
    api.operatorSendVaultCopy.mockResolvedValue({ state: 'held_back' })
    await show(absent())
    choose('Remplacer la CA TLS')
    fireEvent.click(prerequisitesOf().getByRole('button', { name: 'Envoyer' }))
    expect(await screen.findByText('En attente : copie retenue')).toBeTruthy()
    expect(screen.queryByText(/refus/i)).toBeNull()
  })

  it('a_failed_send_is_an_error', async () => {
    api.operatorSendVaultCopy.mockRejectedValue('la gateway ne répond pas')
    await show(absent())
    choose('Remplacer la CA TLS')
    fireEvent.click(prerequisitesOf().getByRole('button', { name: 'Envoyer' }))
    expect(await screen.findByText('la gateway ne répond pas')).toBeTruthy()
  })
})

describe('the CA steps', () => {
  it('are_mounted_only_when_every_prerequisite_is_green', async () => {
    api.operatorRotationsOverview.mockResolvedValue(
      overview({ pending: { state: 'not_admin' } }),
    )
    const renderStep = vi.fn(() => <p>étape</p>)
    render(<RotationsPanel onCeremony={vi.fn()} renderStep={renderStep} />)
    await screen.findByRole('region', { name: 'Remplacer la CA TLS' })
    choose('Remplacer la CA TLS')
    expect(renderStep).not.toHaveBeenCalled()
    cleanup()

    api.operatorRotationsOverview.mockResolvedValue(
      overview({ pending: { state: 'ok', value: [operation('trust_authorities')] } }),
    )
    render(<RotationsPanel onCeremony={vi.fn()} renderStep={renderStep} />)
    await screen.findByRole('region', { name: 'Remplacer la CA TLS' })
    choose('Remplacer la CA TLS')
    expect(await screen.findByText('étape')).toBeTruthy()
    expect(renderStep).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'replace_ca_tls',
        existingOperation: expect.objectContaining({ operation_id: 'c'.repeat(32) }),
      }),
    )
  })
})

describe('the poll', () => {
  it('reads_only_the_overview_and_never_two_reads_at_once', async () => {
    vi.useFakeTimers()
    let release: (value: RotationsOverview) => void = () => {}
    api.operatorRotationsOverview.mockImplementationOnce(
      () => new Promise<RotationsOverview>((resolve) => (release = resolve)),
    )
    render(<RotationsPanel onCeremony={vi.fn()} />)
    // A long wait with the first read still pending starts no second one.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(60_000)
    })
    expect(api.operatorRotationsOverview).toHaveBeenCalledTimes(1)
    api.operatorRotationsOverview.mockResolvedValue(overview())
    await act(async () => {
      release(overview())
      await vi.advanceTimersByTimeAsync(0)
    })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(15_000)
    })
    expect(api.operatorRotationsOverview).toHaveBeenCalledTimes(2)
    cleanup()
    await act(async () => {
      await vi.advanceTimersByTimeAsync(60_000)
    })
    expect(api.operatorRotationsOverview).toHaveBeenCalledTimes(2)
  })

  it('a_failed_read_is_kept_on_screen', async () => {
    api.operatorRotationsOverview.mockRejectedValue('échec de lecture')
    render(<RotationsPanel onCeremony={vi.fn()} />)
    expect(await screen.findByText('échec de lecture')).toBeTruthy()
  })
})

describe('under StrictMode', () => {
  it('runs_one_chain_of_reads_only', async () => {
    vi.useFakeTimers()
    api.operatorRotationsOverview.mockResolvedValue(overview())
    const { StrictMode } = await import('react')
    render(
      <StrictMode>
        <RotationsPanel onCeremony={vi.fn()} />
      </StrictMode>,
    )
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    const first = api.operatorRotationsOverview.mock.calls.length
    await act(async () => {
      await vi.advanceTimersByTimeAsync(15_000)
    })
    expect(api.operatorRotationsOverview.mock.calls.length - first).toBe(1)
  })
})

describe('the wording', () => {
  it('the_screen_has_no_second_person_text', async () => {
    await show(overview({ resumable: true, caTlsCloseAt: NOW - 1, tunnel: false }))
    choose('Remplacer la CA-PQ')
    const text = document.body.textContent ?? ''
    expect(text).not.toMatch(/\b(tu|te|ton|ta|tes|toi)\b/i)
  })
})
