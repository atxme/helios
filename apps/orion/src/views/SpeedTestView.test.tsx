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

import * as store from '../speedtest-store'
import { SpeedTestView } from './SpeedTestView'

const profile: ClientProfile = {
  name: 'portable',
  endpoint: '203.0.113.10:51820',
  peer_public_key: 'gateway',
  profile_type: 'classic',
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
  mode: 'full',
  tcp_download_mbps: 123.4,
  tcp_upload_mbps: 45.6,
  // The quality legs run just under the TCP figures: they report loss, not
  // capacity, and the screen must never show them as the line rate.
  udp_download_mbps: 104.9,
  udp_upload_mbps: 38.8,
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
  // The run now lives above the component, at module scope, so it survives an
  // unmount — which is the point, and which means one test's measurement would
  // otherwise be the next one's starting state.
  store.resetForTests()
})

afterEach(cleanup)

describe('SpeedTestView', () => {
  it('requires an active tunnel before offering the measurement', () => {
    render(<SpeedTestView state="down" profile={profile} />)

    expect(screen.getByText(/Connectez le profil/)).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Lancer le test' })).toHaveProperty('disabled', true)
    expect(api.runSpeedTest).not.toHaveBeenCalled()
  })

  it('runs the Rust measurement and renders both directions', async () => {
    api.runSpeedTest.mockResolvedValue(result)
    render(<SpeedTestView state="up" profile={profile} />)

    fireEvent.click(screen.getByRole('button', { name: 'Lancer le test' }))

    // Value and unit are separate: the finished screen prints the figure at
    // headline size and its unit under it.
    await waitFor(() => expect(screen.getByText('123,4')).toBeTruthy())
    expect(screen.getByText('45,6')).toBeTruthy()
    expect(screen.getByText('Test terminé')).toBeTruthy()
    // Ping, gigue, perte — the three cards below the two directions.
    expect(screen.getByText('12')).toBeTruthy()
    expect(screen.getByText('1,2')).toBeTruthy()
    expect(screen.getByText('0,4')).toBeTruthy()
  })

  /**
   * The transport question is gone from the screen, but the measurement still
   * needs TCP: only congestion control finds a line's capacity. A run sent as
   * `udp` reports the sender's own syscall loop and ~80 % loss.
   */
  it('measures both transports without offering a choice', async () => {
    api.runSpeedTest.mockResolvedValue(result)
    render(<SpeedTestView state="up" profile={profile} />)

    expect(screen.queryByRole('group', { name: /speedtest/i })).toBeNull()
    expect(screen.queryByRole('button', { name: /TCP/i })).toBeNull()

    fireEvent.click(screen.getByRole('button', { name: 'Lancer le test' }))

    await waitFor(() => expect(api.runSpeedTest).toHaveBeenCalledWith('full'))
  })

  /**
   * The engine reports its progress per phase and names the transport while
   * doing it. The screen reads the phase and says the direction: reception
   * has to stay legible once emission takes over, and «TCP montant» must
   * never reach the user.
   */
  it('holds the throughput figures through the quality legs', async () => {
    const sinks: ((update: SpeedTestProgress) => void)[] = []
    api.onSpeedTestProgress.mockImplementation((cb) => {
      sinks.push(cb)
      return Promise.resolve(() => {})
    })
    // Never settles: the run stays in progress for the whole test.
    api.runSpeedTest.mockReturnValue(new Promise(() => {}))
    render(<SpeedTestView state="up" profile={profile} />)

    fireEvent.click(screen.getByRole('button', { name: 'Lancer le test' }))

    const emit = (update: SpeedTestProgress) =>
      act(() => {
        sinks.forEach((sink) => sink(update))
      })

    await waitFor(() => expect(sinks.length).toBe(1))

    emit({
      phase: 'tcp_download',
      fraction: 0.5,
      current_mbps: 90.5,
      bytes: 1024,
      elapsed_ms: 5_000,
      message: 'TCP descendant · flux continus',
    })
    // Twice: the headline meters the leg, the «Réception» card holds it.
    await waitFor(() => expect(screen.getAllByText('90,5')).toHaveLength(2))
    expect(screen.getByText('Test de réception')).toBeTruthy()
    expect(screen.getByText('Étape 1/3')).toBeTruthy()

    emit({
      phase: 'tcp_upload',
      fraction: 0.25,
      current_mbps: 30.25,
      bytes: 2048,
      elapsed_ms: 12_000,
      message: 'TCP montant · flux continus',
    })

    // Reception keeps the figure it reached; emission shows its own. The
    // headline walks to its new value over a few frames rather than snapping
    // to it — see `useSmoothed` — so it is awaited, not read.
    await waitFor(() => expect(screen.getAllByText('30,3')).toHaveLength(2))
    expect(screen.getByText('90,5')).toBeTruthy()
    expect(screen.queryByText(/TCP montant/)).toBeNull()
    expect(screen.getByText("Test d'émission")).toBeTruthy()
    expect(screen.getByText('Étape 2/3')).toBeTruthy()

    // The quality leg runs *below* the rate TCP just found. Letting its
    // progress reach the rows would walk the reading down and then snap it
    // back when the result lands.
    emit({
      phase: 'udp_upload',
      fraction: 0.5,
      current_mbps: 25.7,
      bytes: 4096,
      elapsed_ms: 24_000,
      message: 'UDP montant · perte et jitter',
    })
    expect(screen.queryByText('25,7')).toBeNull()
    // The headline goes back to holding the reception figure, and the
    // «Émission» card keeps the rate its own leg found.
    // Twice again once the headline has walked back up to it: the reception
    // card never stopped showing it.
    await waitFor(() => expect(screen.getAllByText('90,5')).toHaveLength(2))
    expect(screen.getByText('30,3')).toBeTruthy()
    expect(screen.getByText('Mesure de la qualité')).toBeTruthy()
    expect(screen.getByText('Étape 3/3')).toBeTruthy()
  })

  it('surfaces a gateway refusal without leaving the button stuck', async () => {
    api.runSpeedTest.mockRejectedValue('gateway indisponible')
    render(<SpeedTestView state="up" profile={profile} />)

    fireEvent.click(screen.getByRole('button', { name: 'Lancer le test' }))

    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('gateway indisponible'))
    expect(screen.getByText('Impossible de réaliser le test')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Réessayer' })).toHaveProperty('disabled', false)
  })

  /**
   * The defect this store exists for.
   *
   * A run takes about forty seconds, and the speedtest screen is the one a
   * user has every reason to leave while it works. With the state inside the
   * component, that navigation unmounted it: the measurement kept running in
   * Rust, its progress landed on a listener that no longer existed, and coming
   * back showed « Prêt ». Forty seconds lost, silently.
   */
  it('keeps a run alive across leaving the screen and coming back', async () => {
    let settle: (value: SpeedTestResult) => void = () => {}
    api.runSpeedTest.mockReturnValue(
      new Promise<SpeedTestResult>((resolve) => {
        settle = resolve
      }),
    )
    const first = render(<SpeedTestView state="up" profile={profile} />)
    fireEvent.click(screen.getByRole('button', { name: 'Lancer le test' }))
    // While the run works the screen *is* the run: the step and its curve,
    // with no button to press.
    await waitFor(() => expect(screen.getByText('Test en cours…')).toBeTruthy())

    // The user goes to another screen. The router unmounts this one.
    first.unmount()
    await act(async () => {
      settle(result)
    })

    // …and comes back to the finished measurement, not to an empty screen.
    render(<SpeedTestView state="up" profile={profile} />)
    expect(screen.getByText('123,4')).toBeTruthy()
    expect(screen.getByText('45,6')).toBeTruthy()
    expect(api.runSpeedTest).toHaveBeenCalledTimes(1)
  })

  /**
   * The previous runs are what turn a number into an answer: « 123 Mb/s » says
   * nothing on its own, « 123 après 450 » says the line changed.
   */
  it('keeps the five previous runs beside the current one', async () => {
    for (let index = 0; index < 7; index += 1) {
      api.runSpeedTest.mockResolvedValue({ ...result, tcp_download_mbps: 100 + index })
      await act(async () => {
        await store.start('full')
      })
    }
    render(<SpeedTestView state="up" profile={profile} />)

    // The newest is the pair of cards; the five kept rows are the ones before
    // it, and the seventh run has pushed the first two out.
    expect(screen.getByText('106,0')).toBeTruthy()
    expect(screen.getAllByText(/Mb\/s/).length).toBeGreaterThan(5)
    expect(screen.getByText('Historique récent')).toBeTruthy()
    expect(screen.getByText('105,0 / 45,6 Mb/s')).toBeTruthy()
    expect(screen.getByText('101,0 / 45,6 Mb/s')).toBeTruthy()
    expect(screen.queryByText('100,0 / 45,6 Mb/s')).toBeNull()
  })

  /**
   * Two runs at once would share the dial, the progress stream and the history
   * slot, and report each other's rates.
   */
  it('refuses to start a second run while one is under way', async () => {
    // Deliberately never settled: the first run has to still be under way when
    // the second is asked for. Neither call is awaited — the first one never
    // returns, which is the whole point of the fixture.
    api.runSpeedTest.mockReturnValue(new Promise<SpeedTestResult>(() => {}))
    await act(async () => {
      void store.start('full')
      void store.start('full')
    })
    expect(store.getSnapshot().running).toBe(true)
    expect(api.runSpeedTest).toHaveBeenCalledTimes(1)
  })
})
