// @vitest-environment jsdom

import { act, cleanup, renderHook } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

/**
 * Reconnection lifecycle of the event WebSocket.
 *
 * The hook reconnects with backoff when the socket drops, but unmounting it
 * must stop that loop for good: a close event delivered after unmount, or by a
 * socket that has since been replaced, must not open a new connection.
 */

class FakeWebSocket {
  static readonly CONNECTING = 0
  static readonly OPEN = 1
  static readonly CLOSING = 2
  static readonly CLOSED = 3

  readyState = FakeWebSocket.CONNECTING
  onopen: (() => void) | null = null
  onmessage: ((message: MessageEvent) => void) | null = null
  onclose: (() => void) | null = null
  onerror: (() => void) | null = null
  close = vi.fn(() => {
    this.readyState = FakeWebSocket.CLOSING
  })

  open() {
    this.readyState = FakeWebSocket.OPEN
    this.onopen?.()
  }

  // The browser delivers the close event asynchronously, after close().
  deliverClose() {
    this.readyState = FakeWebSocket.CLOSED
    this.onclose?.()
  }
}

const sockets: FakeWebSocket[] = []

vi.mock('../api', () => ({
  createWebSocket: vi.fn(() => {
    const socket = new FakeWebSocket()
    sockets.push(socket)
    return socket
  }),
  fetchStatus: vi.fn(() => Promise.resolve({ state: 'down' })),
  releaseCaptivePortal: vi.fn(),
  setSplitTunnel: vi.fn(),
  tunnelStart: vi.fn(),
  tunnelStop: vi.fn(),
}))

const { useHelios } = await import('./useHelios')

describe('useHelios WebSocket reconnection', () => {
  beforeEach(() => {
    sockets.length = 0
    vi.useFakeTimers()
    vi.stubGlobal('WebSocket', FakeWebSocket)
  })

  afterEach(() => {
    cleanup()
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('reconnects with backoff after the socket drops while mounted', async () => {
    const { result } = renderHook(() => useHelios())
    expect(sockets).toHaveLength(1)

    act(() => sockets[0].open())
    expect(result.current.wsStatus).toBe('connected')

    act(() => sockets[0].deliverClose())
    expect(result.current.wsStatus).toBe('disconnected')
    expect(sockets).toHaveLength(1)

    await act(() => vi.advanceTimersByTimeAsync(1000))
    expect(sockets).toHaveLength(2)
  })

  it('does not reconnect when the socket closes after unmount', async () => {
    const { unmount } = renderHook(() => useHelios())
    act(() => sockets[0].open())

    unmount()
    expect(sockets[0].close).toHaveBeenCalled()
    sockets[0].deliverClose()

    await vi.advanceTimersByTimeAsync(60_000)
    expect(sockets).toHaveLength(1)
  })

  it('aborts a connection still in progress on unmount without reconnecting', async () => {
    const { unmount } = renderHook(() => useHelios())
    expect(sockets[0].readyState).toBe(FakeWebSocket.CONNECTING)

    unmount()
    expect(sockets[0].close).toHaveBeenCalled()
    sockets[0].deliverClose()

    await vi.advanceTimersByTimeAsync(60_000)
    expect(sockets).toHaveLength(1)
  })

  it('cancels a pending reconnection on unmount', async () => {
    const { unmount } = renderHook(() => useHelios())
    act(() => sockets[0].deliverClose())

    unmount()

    await vi.advanceTimersByTimeAsync(60_000)
    expect(sockets).toHaveLength(1)
  })

  it('ignores the close event of a socket replaced by a remount', async () => {
    const first = renderHook(() => useHelios())
    first.unmount()
    const second = renderHook(() => useHelios())
    expect(sockets).toHaveLength(2)
    act(() => sockets[1].open())

    act(() => sockets[0].deliverClose())

    await act(() => vi.advanceTimersByTimeAsync(60_000))
    expect(sockets).toHaveLength(2)
    expect(second.result.current.wsStatus).toBe('connected')
  })
})
