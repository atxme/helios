import { describe, expect, it } from 'vitest'

import { decodeProfileDocument, readProfileDocument } from './profileDocument'

const DOCUMENT = '{"format":"orion-profile","version":1}'

/** Same document, dressed the way a given tool would have written it. */
function encoded(kind: 'utf-8' | 'utf-8-bom' | 'utf-16le' | 'utf-16be'): ArrayBuffer {
  const utf8 = new TextEncoder().encode(DOCUMENT)
  if (kind === 'utf-8') return utf8.buffer as ArrayBuffer
  if (kind === 'utf-8-bom') return Uint8Array.from([0xef, 0xbb, 0xbf, ...utf8]).buffer

  const units = [...DOCUMENT].map((character) => character.charCodeAt(0))
  const little = kind === 'utf-16le'
  const bytes = [little ? 0xff : 0xfe, little ? 0xfe : 0xff]
  for (const unit of units) {
    bytes.push(little ? unit & 0xff : unit >> 8, little ? unit >> 8 : unit & 0xff)
  }
  return Uint8Array.from(bytes).buffer
}

describe('decodeProfileDocument', () => {
  /** The trip from the gateway to the machine re-encodes the file; the
   *  document itself is intact and must stay importable. */
  it('reads a document whatever byte-order mark it carries', () => {
    for (const kind of ['utf-8', 'utf-8-bom', 'utf-16le', 'utf-16be'] as const) {
      expect(decodeProfileDocument(encoded(kind)), kind).toBe(DOCUMENT)
    }
  })

  /** The decisive property: the first character must be the JSON brace.
   *  A leading U+FEFF left in place is what made the import report an
   *  unknown format about a valid document. */
  it('leaves no byte-order mark at the head', () => {
    for (const kind of ['utf-8-bom', 'utf-16le', 'utf-16be'] as const) {
      expect(decodeProfileDocument(encoded(kind)).startsWith('{'), kind).toBe(true)
    }
  })

  it('decodes plain UTF-8 unchanged, accents included', () => {
    const accented = '{"name":"poste-éà"}'
    const bytes = new TextEncoder().encode(accented)
    expect(decodeProfileDocument(bytes.buffer as ArrayBuffer)).toBe(accented)
  })

  it('reads the bytes from a selected file before decoding them', async () => {
    const buffer = encoded('utf-16le')
    const file = { arrayBuffer: async () => buffer } as File

    await expect(readProfileDocument(file)).resolves.toBe(DOCUMENT)
  })
})
