import { useEffect, useState } from 'react'
import IconButton from '@mui/material/IconButton'
import Tooltip from '@mui/material/Tooltip'
import { Check, ClipboardCopy } from 'lucide-react'
import { copyText } from '../clipboard'
import { PINE } from '../theme'

/**
 * Copies a value that is meant to be compared elsewhere.
 *
 * Every value it serves — public key, PQ fingerprint, virtual address — exists
 * to be carried out of Orion: read against what `heliosd init-key-negotiation`
 * printed, pasted into an admission request, given to an operator. Selecting
 * truncated monospace text with the mouse is exactly where that goes wrong.
 *
 * The check mark is not decoration: a clipboard write is invisible, and a
 * button that answers nothing gets pressed twice.
 */

/** How long the confirmation stays, in milliseconds. */
const CONFIRM_MS = 1600

export function CopyButton({ value, label }: { value: string; label: string }) {
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    if (!copied) return
    const id = setTimeout(() => setCopied(false), CONFIRM_MS)
    return () => clearTimeout(id)
  }, [copied])

  return (
    <Tooltip title={copied ? 'Copié' : `Copier ${label}`}>
      <IconButton
        size="small"
        aria-label={`Copier ${label}`}
        onClick={() => {
          void copyText(value).then(() => setCopied(true))
        }}
        sx={{ flexShrink: 0, p: 0.4 }}
      >
        {copied ? (
          <Check size={13} aria-hidden style={{ color: PINE }} />
        ) : (
          <ClipboardCopy size={13} aria-hidden />
        )}
      </IconButton>
    </Tooltip>
  )
}
