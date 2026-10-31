/** Same bound as the other pasted documents: a request or a leaf is a few kilobytes. */
export const MAX_FILE_BYTES = 256 * 1024

/** Reads a chosen file in the WebView; the content is what travels, never a path. */
export async function readFileText(file: File): Promise<string> {
  if (file.size > MAX_FILE_BYTES) throw new Error('Fichier trop volumineux (maximum 256 Kio).')
  if (typeof file.text === 'function') return file.text()
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => resolve(String(reader.result))
    reader.onerror = () => reject(new Error('Lecture du fichier impossible.'))
    reader.readAsText(file)
  })
}
