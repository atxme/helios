import { afterEach, describe, expect, it, vi } from 'vitest'

import { copyText } from './clipboard'

afterEach(() => vi.unstubAllGlobals())

describe('clipboard fallback', () => {
  it('uses the native clipboard when WebView grants it', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal('navigator', { clipboard: { writeText } })

    await copyText('public key')

    expect(writeText).toHaveBeenCalledWith('public key')
  })

  it('uses a temporary readonly textarea and always removes it', async () => {
    const area = {
      value: '',
      style: { position: '', opacity: '' },
      setAttribute: vi.fn(),
      select: vi.fn(),
    }
    const appendChild = vi.fn()
    const removeChild = vi.fn()
    const execCommand = vi.fn(() => true)
    vi.stubGlobal('navigator', { clipboard: { writeText: vi.fn().mockRejectedValue('denied') } })
    vi.stubGlobal('document', {
      createElement: vi.fn(() => area),
      body: { appendChild, removeChild },
      execCommand,
    })

    await copyText('fingerprint')

    expect(area.value).toBe('fingerprint')
    expect(area.setAttribute).toHaveBeenCalledWith('readonly', '')
    expect(area.select).toHaveBeenCalledOnce()
    expect(execCommand).toHaveBeenCalledWith('copy')
    expect(appendChild).toHaveBeenCalledWith(area)
    expect(removeChild).toHaveBeenCalledWith(area)
  })

  it('removes the temporary textarea even if the legacy copy throws', async () => {
    const area = {
      value: '',
      style: { position: '', opacity: '' },
      setAttribute: vi.fn(),
      select: vi.fn(),
    }
    const removeChild = vi.fn()
    vi.stubGlobal('navigator', { clipboard: { writeText: vi.fn().mockRejectedValue('denied') } })
    vi.stubGlobal('document', {
      createElement: vi.fn(() => area),
      body: { appendChild: vi.fn(), removeChild },
      execCommand: vi.fn(() => {
        throw new Error('copy failed')
      }),
    })

    await expect(copyText('secret')).rejects.toThrow('copy failed')
    expect(removeChild).toHaveBeenCalledWith(area)
  })
})
