// @vitest-environment jsdom

import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { ClientProfile, SpeedTestProgress, SpeedTestResult } from '../types'

const api = vi.hoisted(() => ({
  runSpeedTest: vi.fn(),
  // Typed sink: one test drives the view by replaying the engine's own
  // progress frames, and it has to hand back a real callback to do so.
  onSpeedTestProgress: vi.fn((_cb: (update: SpeedTestProgress) => void) =>
    Promise.resolve(() => {}),
  ),
}))
vi.mock('../api', () => api)

import { SpeedTestView } from './SpeedTestView'

const profile: ClientProfile = {
  name: 'portable',
  endpoint: '203.0.113.10:51820',
  peer_public_key: 'gateway',
  public_key: 'client',
  has_private_key: true,
  has_static_psk: false,
  address: '100.64.1.2/32',
  allowed_ips: '0.0.0.0/0',
  persistent_keepalive: 25,
  // The speedtest target is fixed inside the WireGuard network; a profile
  // URL is neither required nor consulted.
  heliosd_url: null,
  ssh_target: null,
  key_negotiation: null,
}

const result: SpeedTestResult = {
  latency_ms: 12.4,
  jitter_ms: 1.2,
  latency_p95_ms: 18.7,
  mode: 'udp',
  tcp_download_mbps: null,
  tcp_upload_mbps: null,
  udp_download_mbps: 123.4,
  udp_upload_mbps: 45.6,
  udp_loss_pct: 0.4,
  udp_jitter_ms: 0.9,
  tcp_streams: 4,
  test_duration_secs: 20,
  download_mbps: 123.4,
  upload_mbps: 45.6,
  download_variation_pct: 2.1,
  upload_variation_pct: 3.2,
  duration_ms: 812,
  download_bytes: 8 * 1024 * 1024,
  upload_bytes: 8 * 1024 * 1024,
  parallel_streams: 4,
  measurement_rounds: 3,
}

beforeEach(() => {
  vi.clearAllMocks()
})

afterEach(cleanup)

describe('SpeedTestView', () => {
  it('requires an active tunnel before offering the measurement', () => {
    render(<SpeedTestView state="down" profile={profile} />)

    expect(screen.getByText(/Connectez le profil/)).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Lancer le speedtest' })).toHaveProperty('disabled', true)
    expect(api.runSpeedTest).not.toHaveBeenCalled()
  })

  it('runs the Rust measurement and renders both directions', async () => {
    api.runSpeedTest.mockResolvedValue(result)
    render(<SpeedTestView state="up" profile={profile} />)

    fireEvent.click(screen.getByRole('button', { name: 'Lancer le speedtest' }))

    await waitFor(() => expect(screen.getByText('123,4 Mb/s')).toBeTruthy())
    expect(screen.getByText('45,6 Mb/s')).toBeTruthy()
    expect(screen.getByText('12 ms')).toBeTruthy()
    expect(screen.getByText('0,4 %')).toBeTruthy()
  })

  /**
   * WireGuard carries UDP only, so the screen no longer asks. The mode is not
   * merely a default here: there is no control left that could change it, and
   * a run that went out as `tcp` or `full` would double its own duration.
   */
  it('measures UDP without offering a transport choice', async () => {
    api.runSpeedTest.mockResolvedValue(result)
    render(<SpeedTestView state="up" profile={profile} />)

    expect(screen.queryByRole('group', { name: /speedtest/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /TCP/i })).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: 'Lancer le speedtest' }))

    await waitFor(() => expect(api.runSpeedTest).toHaveBeenCalledWith('udp'))
  })

  /**
   * The engine reports its progress per phase and names the transport while
   * doing it. The screen reads the phase and says the direction: reception
   * has to stay legible once emission takes over, and «TCP montant» must
   * never reach the user.
   */
  it('keeps both directions on screen and names them by direction', async () => {
    const sinks: ((update: SpeedTestProgress) => void)[] = []
    api.onSpeedTestProgress.mockImplementation((cb) => {
      sinks.push(cb)
      return Promise.resolve(() => {})
    })
    // Never settles: the run stays in progress for the whole test.
    api.runSpeedTest.mockReturnValue(new Promise(() => {}))
    render(<SpeedTestView state="up" profile={profile} />)

    fireEvent.click(screen.getByRole('button', { name: 'Lancer le speedtest' }))

    const emit = (update: SpeedTestProgress) =>
      act(() => {
        sinks.forEach((sink) => sink(update))
      })

    await waitFor(() => expect(sinks.length).toBe(1))

    emit({
      phase: 'udp_download',
      fraction: 0.5,
      current_mbps: 90.5,
      bytes: 1024,
      elapsed_ms: 10_000,
      message: 'UDP descendant · perte et jitter',
    })
    expect(screen.getByText('90,5 Mb/s')).toBeTruthy()

    emit({
      phase: 'udp_upload',
      fraction: 0.25,
      current_mbps: 30.25,
      bytes: 2048,
      elapsed_ms: 25_000,
      message: 'UDP montant · perte et jitter',
    })

    // Reception keeps the figure it reached; emission shows its own.
    expect(screen.getByText('30,3 Mb/s')).toBeTruthy()
    expect(screen.getByText('90,5 Mb/s')).toBeTruthy()
    expect(screen.queryByText(/UDP montant/)).toBeNull()
    // Twice: the dial names the phase it is metering, the row names its own.
    expect(screen.getAllByText('Émission')).toHaveLength(2)
  })

  it('surfaces a gateway refusal without leaving the button stuck', async () => {
    api.runSpeedTest.mockRejectedValue('gateway indisponible')
    render(<SpeedTestView state="up" profile={profile} />)

    fireEvent.click(screen.getByRole('button', { name: 'Lancer le speedtest' }))

    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('gateway indisponible'))
    expect(screen.getByRole('button', { name: 'Lancer le speedtest' })).toHaveProperty('disabled', false)
  })
})
