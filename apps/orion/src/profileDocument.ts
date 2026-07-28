/**
 * Reading a profile file chosen through the picker.
 *
 * `File.text()` would be enough if every document arrived as it was written.
 * It doesn't: a profile is carried by hand from the gateway to the machine,
 * and that trip re-encodes it — Windows PowerShell's `Out-File` writes
 * UTF-16LE by default, Notepad long prefixed UTF-8 with a byte-order mark.
 * `text()` decodes as UTF-8 unconditionally, so a UTF-16 document comes back
 * as a string of replacement characters: the import then reports an unknown
 * format about a document that is perfectly valid, and the user has no way
 * to guess that only its clothing changed.
 *
 * Reading the bytes and looking at the mark is the whole fix. It mirrors
 * `orion_core::profile_import::decode_document`, which does the same for the
 * double-click path — the two must accept the same files, because an import
 * that works one way and fails the other is impossible to explain to the
 * person doing it.
 */

/** Text decoders, by the mark that announces them. */
const MARKS: { bytes: number[]; encoding: string }[] = [
  { bytes: [0xff, 0xfe], encoding: 'utf-16le' },
  { bytes: [0xfe, 0xff], encoding: 'utf-16be' },
  // UTF-8: the mark is consumed by the decoder itself, hence no slicing.
  { bytes: [0xef, 0xbb, 0xbf], encoding: 'utf-8' },
]

/** Decodes a document's bytes according to its byte-order mark, if any. */
export function decodeProfileDocument(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer)
  const mark = MARKS.find(({ bytes: prefix }) =>
    prefix.every((byte, index) => bytes[index] === byte),
  )
  if (!mark) return new TextDecoder('utf-8').decode(bytes)
  // `utf-16le` and `utf-16be` do not skip their own mark: slicing it off here
  // avoids a leading U+FEFF that the JSON parser would refuse.
  return new TextDecoder(mark.encoding).decode(
    mark.encoding === 'utf-8' ? bytes : bytes.subarray(mark.bytes.length),
  )
}

/** Reads a chosen file, whatever byte-order mark it carries. */
export async function readProfileDocument(file: File): Promise<string> {
  return decodeProfileDocument(await file.arrayBuffer())
}
