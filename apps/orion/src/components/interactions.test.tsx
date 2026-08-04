// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  copyText: vi.fn(),
  exportLogs: vi.fn(),
}))

vi.mock('../clipboard', () => ({ copyText: mocks.copyText }))
vi.mock('../api', () => ({ exportLogs: mocks.exportLogs }))

import { CopyButton } from './CopyButton'
import { EventLog } from './EventLog'

const logs = [
  { ts: '12:00:00', level: 'info', message: 'connected' },
  { ts: '12:00:01', level: 'error', message: 'link lost' },
]

beforeEach(() => {
  vi.clearAllMocks()
  mocks.copyText.mockResolvedValue(undefined)
  mocks.exportLogs.mockResolvedValue('/tmp/orion-journal.txt')
})

afterEach(() => {
  cleanup()
  vi.useRealTimers()
})

describe('interactive controls', () => {
  it('confirms a clipboard write and clears the confirmation later', async () => {
    vi.useFakeTimers()
    render(<CopyButton value="gateway-public" label="la clé publique" />)
    const button = screen.getByRole('button', { name: 'Copier la clé publique' })

    await act(async () => fireEvent.click(button))
    expect(mocks.copyText).toHaveBeenCalledWith('gateway-public')
    expect(button.innerHTML).toContain('lucide-check')

    act(() => vi.advanceTimersByTime(1600))
    expect(button.innerHTML).toContain('lucide-clipboard-copy')
  })

  it('copies the complete log and reports the result', async () => {
    render(<EventLog logs={logs} />)

    fireEvent.click(screen.getByRole('button', { name: 'Copier tout le journal' }))
    await waitFor(() => expect(screen.getByRole('status').textContent).toContain('Journal copié'))
    expect(mocks.copyText).toHaveBeenCalledWith(
      '12:00:01  ERROR  link lost\n12:00:00  INFO   connected',
    )
  })

  it('reports both successful and failed exports', async () => {
    const { unmount } = render(<EventLog logs={logs} />)
    fireEvent.click(screen.getByRole('button', { name: 'Exporter le journal dans un fichier' }))
    await waitFor(() =>
      expect(screen.getByRole('status').textContent).toContain('/tmp/orion-journal.txt'),
    )
    expect(mocks.exportLogs).toHaveBeenCalledWith(
      expect.stringMatching(/^orion-journal-\d{8}-\d{6}$/),
      expect.stringContaining('link lost'),
    )
    unmount()

    mocks.exportLogs.mockRejectedValueOnce(new Error('read-only directory'))
    render(<EventLog logs={logs} />)
    fireEvent.click(screen.getByRole('button', { name: 'Exporter le journal dans un fichier' }))
    await waitFor(() =>
      expect(screen.getByRole('status').textContent).toContain('read-only directory'),
    )
  })
})
