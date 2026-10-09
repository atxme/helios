// @vitest-environment jsdom

import { ThemeProvider } from '@mui/material/styles'
import { act, cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { heliosTheme } from '../theme'
import type { Health } from '../types'

/**
 * Polling of `/api/health`.
 *
 * Two failures this guards against: an error banner that stays up after the
 * daemon answers again, and requests piling up when one answer takes longer
 * than the polling period.
 */

const fetchHealth = vi.fn<() => Promise<Health>>()

vi.mock('../api', () => ({ fetchHealth: () => fetchHealth() }))

const { HealthPanel } = await import('./HealthPanel')

const HEALTH: Health = {
  uptime_seconds: 3_600,
  load: [0.1, 0.2, 0.3],
  cpu_count: 4,
  memory_total_bytes: 1_000,
  memory_available_bytes: 500,
  temperature_celsius: null,
  tpm: null,
}

const ERROR_TITLE = 'Santé de la machine illisible'

function renderPanel() {
  return render(
    <ThemeProvider theme={heliosTheme}>
      <HealthPanel />
    </ThemeProvider>,
  )
}

describe('HealthPanel polling', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    fetchHealth.mockReset()
  })

  afterEach(() => {
    cleanup()
    vi.useRealTimers()
  })

  it('clears the error once the daemon answers again', async () => {
    fetchHealth.mockRejectedValueOnce(new Error('HTTP 503')).mockResolvedValue(HEALTH)
    renderPanel()

    await act(() => vi.advanceTimersByTimeAsync(0))
    expect(screen.getByText(ERROR_TITLE)).toBeTruthy()

    await act(() => vi.advanceTimersByTimeAsync(5_000))
    expect(screen.queryByText(ERROR_TITLE)).toBeNull()
    expect(screen.getByText('Machine')).toBeTruthy()
  })

  it('does not send a second request while the first is still pending', async () => {
    let answer: (health: Health) => void = () => {}
    fetchHealth.mockImplementationOnce(() => new Promise(resolve => { answer = resolve }))
    fetchHealth.mockResolvedValue(HEALTH)
    renderPanel()

    await act(() => vi.advanceTimersByTimeAsync(20_000))
    expect(fetchHealth).toHaveBeenCalledTimes(1)

    await act(async () => answer(HEALTH))
    await act(() => vi.advanceTimersByTimeAsync(5_000))
    expect(fetchHealth).toHaveBeenCalledTimes(2)
  })

  it('stops polling once unmounted', async () => {
    fetchHealth.mockResolvedValue(HEALTH)
    const { unmount } = renderPanel()
    await act(() => vi.advanceTimersByTimeAsync(0))
    unmount()

    await vi.advanceTimersByTimeAsync(60_000)
    expect(fetchHealth).toHaveBeenCalledTimes(1)
  })
})
