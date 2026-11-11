// @vitest-environment jsdom

import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { OperatorStatus } from '../types'
import { OperatorCeremonyPanel } from './OperatorCeremony'

const SENTENCE =
  'Demande déjà préparée par la gateway pour cette époque : elle est reprise, sans nouvelle clé.'

const status = (extra: Partial<OperatorStatus> = {}): OperatorStatus => ({
  session_id: 's',
  revision: 1,
  operation: 'gateway_identity',
  remote: 'awaiting_operator',
  gesture: { awaiting_key: { index: 1, of: 1, purpose: 'approve_campaign' } },
  allowed: ['continue', 'cancel'],
  ...extra,
})

afterEach(cleanup)

describe('the reused request in the ceremony', () => {
  it('says_the_reused_request', () => {
    render(<OperatorCeremonyPanel status={status({ request_reused: true })} onStatus={vi.fn()} />)
    expect(screen.getByText(SENTENCE)).toBeTruthy()
  })

  it('does_not_say_the_reused_request_without_the_field', () => {
    render(<OperatorCeremonyPanel status={status()} onStatus={vi.fn()} />)
    expect(screen.queryByText(SENTENCE)).toBeNull()
  })
})
