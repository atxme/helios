// @vitest-environment jsdom

import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { ClientProfile, SpeedTestResult } from '../types'

const api = vi.hoisted(() => ({
  runSpeedTest: vi.fn(),
  onSpeedTestProgress: vi.fn(async () => () => {}),
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
  mode: 'tcp',
  tcp_download_mbps: 123.4,
  tcp_upload_mbps: 45.6,
  udp_download_mbps: null,
  udp_upload_mbps: null,
  udp_loss_pct: null,
  udp_jitter_ms: null,
  tcp_streams: 4,
  test_duration_secs: 8,
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
    expect(api.runSpeedTest).toHaveBeenCalledWith('tcp', 8)
  })

  it('surfaces a gateway refusal without leaving the button stuck', async () => {
    api.runSpeedTest.mockRejectedValue('gateway indisponible')
    render(<SpeedTestView state="up" profile={profile} />)

    fireEvent.click(screen.getByRole('button', { name: 'Lancer le speedtest' }))

    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('gateway indisponible'))
    expect(screen.getByRole('button', { name: 'Lancer le speedtest' })).toHaveProperty('disabled', false)
  })
})
