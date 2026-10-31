import { useEffect, useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { Download } from 'lucide-react'

import * as api from '../../api'
import type { GestureState, OperatorArtifact } from '../../types'

/**
 * The bytes a file is saved as: UTF-8 for a text artifact, the decoded bytes
 * for a base64 one, so a DER leaf lands on disk raw and not as its base64 text.
 */
export function artifactBytes(artifact: OperatorArtifact): Uint8Array {
  if (artifact.encoding === 'text') return new TextEncoder().encode(artifact.contents)
  const binary = atob(artifact.contents.trim())
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index)
  return bytes
}

/** Offers one artifact as a download link, the way EnrollmentPanel offers a request. */
function saveArtifact(artifact: OperatorArtifact) {
  const blob = new Blob([artifactBytes(artifact) as BlobPart], {
    type: artifact.encoding === 'text' ? 'text/plain' : 'application/octet-stream',
  })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = artifact.file_name
  link.click()
  URL.revokeObjectURL(url)
}

const ENDED: GestureState[] = ['done', 'failed']

/**
 * The files a ceremony produced, each saved by its own button, with its
 * fingerprint under it when the file carries one.
 *
 * Fetched once the ceremony has ended, including when it stopped short: an
 * acceptance that could not admit the peer still hands over its leaves, and a
 * bootstrap whose finalization failed still hands over its leaf, which
 * `failedNote` then explains. The files are public material held for this
 * session only, hence the reminder; the gateway's bootstrap leaf alone is also
 * written beside the vault.
 */
export function ArtifactDownloads({
  gesture,
  failedNote,
}: {
  gesture: GestureState
  failedNote?: string
}) {
  const [artifacts, setArtifacts] = useState<OperatorArtifact[]>([])
  const [error, setError] = useState<string | null>(null)
  const ended = typeof gesture === 'string' && ENDED.includes(gesture)

  useEffect(() => {
    if (!ended) return
    let cancelled = false
    void api
      .operatorArtifacts()
      .then((found) => {
        if (!cancelled) setArtifacts(found)
      })
      .catch((cause) => {
        if (!cancelled) setError(`Fichiers illisibles : ${String(cause)}`)
      })
    return () => {
      cancelled = true
    }
  }, [ended])

  const save = (artifact: OperatorArtifact) => {
    setError(null)
    try {
      saveArtifact(artifact)
    } catch (cause) {
      setError(`Enregistrement impossible : ${String(cause)}`)
    }
  }

  if (!ended || (artifacts.length === 0 && !error)) return null
  return (
    <Paper variant="outlined" sx={{ mt: 1.25, p: 1.75 }}>
      <Typography component="h3" sx={{ fontSize: 12.5, fontWeight: 700, mb: 0.5 }}>
        Fichiers produits
      </Typography>
      <Typography color="text.secondary" sx={{ fontSize: 11, mb: 1 }}>
        Enregistrez-les avant de quitter cet écran, qui ne les garde pas (seule la feuille
        d’amorçage de la gateway est aussi écrite à côté du coffre).
      </Typography>
      <Stack spacing={0.75} sx={{ alignItems: 'flex-start' }}>
        {artifacts.map((artifact) => (
          <Box key={artifact.file_name} sx={{ minWidth: 0, maxWidth: '100%' }}>
            <Button
              size="small"
              variant="outlined"
              color="inherit"
              startIcon={<Download size={14} aria-hidden />}
              onClick={() => save(artifact)}
              sx={{ minHeight: 30, fontSize: 11.5, textTransform: 'none' }}
            >
              {`Enregistrer ${artifact.file_name}`}
            </Button>
            {artifact.fingerprint && (
              <Typography
                color="text.secondary"
                sx={{ mt: 0.5, fontSize: 10.5, fontFamily: 'monospace', overflowWrap: 'anywhere' }}
              >
                {`empreinte : ${artifact.fingerprint}`}
              </Typography>
            )}
          </Box>
        ))}
      </Stack>
      {gesture === 'failed' && failedNote && artifacts.length > 0 && (
        <Typography color="text.secondary" sx={{ mt: 1, fontSize: 11.5 }}>
          {failedNote}
        </Typography>
      )}
      {error && (
        <Alert severity="error" variant="outlined" sx={{ mt: 1, fontSize: 11.5 }}>
          {error}
        </Alert>
      )}
    </Paper>
  )
}
