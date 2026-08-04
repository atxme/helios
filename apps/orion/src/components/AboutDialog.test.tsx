// @vitest-environment jsdom

import { cleanup, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  aboutOrion: vi.fn(),
  copyText: vi.fn(),
}))

vi.mock('../api', () => ({ aboutOrion: mocks.aboutOrion }))
vi.mock('../clipboard', () => ({ copyText: mocks.copyText }))

import { AboutDialog } from './AboutDialog'

const about = (overrides = {}) => ({
  version: '0.1.0',
  backend: 'wireguard',
  profile_extension: 'orion',
  log_path: 'C:\\Users\\op\\AppData\\Roaming\\Orion\\orion.log',
  ...overrides,
})

beforeEach(() => {
  vi.clearAllMocks()
  mocks.aboutOrion.mockResolvedValue(about())
})

afterEach(cleanup)

describe('AboutDialog', () => {
  it('reads nothing while closed', () => {
    render(<AboutDialog open={false} onClose={vi.fn()} />)
    expect(mocks.aboutOrion).not.toHaveBeenCalled()
  })

  // The log file is the only trace a release build leaves — it has no
  // console — so the path is stated, and stated in full.
  it('states the version, the backend and the log path', async () => {
    render(<AboutDialog open onClose={vi.fn()} />)

    await waitFor(() => expect(screen.getByText('0.1.0')).toBeTruthy())
    expect(screen.getByText('wireguard')).toBeTruthy()
    expect(screen.getByText('.orion')).toBeTruthy()
    expect(
      screen.getByText('C:\\Users\\op\\AppData\\Roaming\\Orion\\orion.log'),
    ).toBeTruthy()
  })

  // A dry-run build displays a profile, a mode and a state while encrypting
  // nothing. Naming the backend is not enough — the consequence is spelled
  // out.
  it('says outright that a simulated backend mounts no tunnel', async () => {
    mocks.aboutOrion.mockResolvedValue(about({ backend: 'dry-run' }))
    render(<AboutDialog open onClose={vi.fn()} />)

    await waitFor(() => expect(screen.getByText(/aucun tunnel n’est monté/)).toBeTruthy())
  })

  it('reports a missing log file rather than an empty row', async () => {
    mocks.aboutOrion.mockResolvedValue(about({ log_path: null }))
    render(<AboutDialog open onClose={vi.fn()} />)

    await waitFor(() => expect(screen.getByText(/sortie standard uniquement/)).toBeTruthy())
  })

  it('survives a shell that cannot answer', async () => {
    mocks.aboutOrion.mockRejectedValue(new Error('IPC indisponible'))
    render(<AboutDialog open onClose={vi.fn()} />)

    await waitFor(() => expect(screen.getByText(/IPC indisponible/)).toBeTruthy())
  })
})
