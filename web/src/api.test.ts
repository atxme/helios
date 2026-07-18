import { afterEach, describe, expect, it, vi } from 'vitest'

import { fetchStatus, setSplitTunnel, tunnelStart, tunnelStop } from './api'

describe('client REST Helios', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('retourne le statut JSON lorsque l’API répond avec succès', async () => {
    const status = { state: 'up', version: '0.1.0' }
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(status), { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(fetchStatus()).resolves.toEqual(status)
    expect(fetchMock).toHaveBeenCalledWith('/api/status', undefined)
  })

  it('signale une réponse API en erreur au lieu de présenter un statut périmé', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 503 })))

    await expect(fetchStatus()).rejects.toThrow('HTTP 503')
  })

  it('envoie les commandes de tunnel avec les méthodes et charges attendues', async () => {
    const fetchMock = vi.fn().mockImplementation(() =>
      Promise.resolve(new Response(JSON.stringify({ ok: true }), { status: 200 })),
    )
    vi.stubGlobal('fetch', fetchMock)

    await tunnelStart()
    await tunnelStop()
    await setSplitTunnel(['10.0.0.0/8'])

    expect(fetchMock).toHaveBeenNthCalledWith(1, '/api/tunnel/start', {
      method: 'POST',
    })
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/api/tunnel/stop', { method: 'POST' })
    expect(fetchMock).toHaveBeenNthCalledWith(3, '/api/split-tunnel', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ cidrs: ['10.0.0.0/8'] }),
    })
  })

  it('remonte le refus métier d’une commande', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      JSON.stringify({ ok: false, error: 'orchestrateur injoignable' }),
      { status: 200 },
    )))

    await expect(tunnelStart()).rejects.toThrow('orchestrateur injoignable')
  })
})
