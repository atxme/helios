// @vitest-environment jsdom

import { beforeEach, expect, it, vi } from 'vitest'

const mocks = vi.hoisted(() => ({
  createRoot: vi.fn(),
  render: vi.fn(),
}))

vi.mock('react-dom/client', () => ({
  default: { createRoot: mocks.createRoot },
  createRoot: mocks.createRoot,
}))
vi.mock('./App', () => ({ default: () => <div>orion-app</div> }))

beforeEach(() => {
  vi.resetModules()
  vi.clearAllMocks()
  document.body.innerHTML = '<div id="root"></div>'
  mocks.createRoot.mockReturnValue({ render: mocks.render })
})

it('mounts the application into the declared root', async () => {
  await import('./main')

  expect(mocks.createRoot).toHaveBeenCalledWith(document.getElementById('root'))
  expect(mocks.render).toHaveBeenCalledOnce()
})
