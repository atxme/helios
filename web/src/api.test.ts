import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  createWebSocket,
  fetchStatus,
  fetchTrust,
  fetchUpdateStatus,
  releaseCaptivePortal,
  setSplitTunnel,
  tunnelStart,
  tunnelStop,
  stageUpdate,
} from './api'

describe('Helios REST client', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('returns the JSON status when the API responds successfully', async () => {
    const status = { state: 'up', version: '0.1.0' }
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(status), { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(fetchStatus()).resolves.toEqual(status)
    expect(fetchMock).toHaveBeenCalledWith('/api/status', undefined)
  })

  it('reports an API error response instead of presenting a stale status', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 503 })))

    await expect(fetchStatus()).rejects.toThrow('HTTP 503')
  })

  it('sends tunnel commands with the expected methods and payloads', async () => {
    const fetchMock = vi.fn().mockImplementation(() =>
      Promise.resolve(new Response(JSON.stringify({ ok: true }), { status: 200 })),
    )
    vi.stubGlobal('fetch', fetchMock)

    await tunnelStart()
    await tunnelStop()
    await releaseCaptivePortal()
    await setSplitTunnel(['10.0.0.0/8'])

    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/tunnel/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    })
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/tunnel/stop', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    })
    expect(fetchMock).toHaveBeenNthCalledWith(3, '/api/captive-portal/release', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    })
    expect(fetchMock).toHaveBeenNthCalledWith(4, '/api/split-tunnel', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cidrs: ['10.0.0.0/8'] }),
    })
  })

  it('surfaces a command\'s business rejection', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ ok: false, error: 'orchestrateur injoignable' }),
      { status: 200 },
    )))

    await expect(tunnelStart()).rejects.toThrow('orchestrateur injoignable')
  })

  it('reads the compiled trust anchor', async () => {
    const trust = { required_algs: ['ed25519', 'ml-dsa-65'], publisher_keys: [] }
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      new Response(JSON.stringify(trust), { status: 200 }),
    ))

    await expect(fetchTrust()).resolves.toEqual(trust)
  })

  it('stages a signed manifest only as JSON', async () => {
    const release = { release_sequence: 7, version: '1.2.0', sha256: 'ab'.repeat(32) }
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ release }), { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    const manifest = { payload: { product: 'heliosd' }, signatures: [] }

    await expect(stageUpdate(manifest)).resolves.toEqual(release)
    expect(fetchMock).toHaveBeenCalledWith('/api/update/stage', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ manifest }),
    })
  })

  it('reads the update channel and sequence', async () => {
    const status = { channel: 'testing', highest_confirmed_sequence: 4 }
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(status), { status: 200 })))
    await expect(fetchUpdateStatus()).resolves.toEqual(status)
  })

  it('chooses an encrypted WebSocket when the page is served over HTTPS', () => {
    const WebSocketMock = vi.fn()
    vi.stubGlobal('WebSocket', WebSocketMock)
    vi.stubGlobal('window', { location: { protocol: 'https:', host: 'helios.test' } })

    createWebSocket()

    expect(WebSocketMock).toHaveBeenCalledWith('wss://helios.test/ws')
  })
})
