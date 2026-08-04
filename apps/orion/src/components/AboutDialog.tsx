import { useEffect, useState } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import Typography from '@mui/material/Typography'
import * as api from '../api'
import type { About } from '../types'
import { CopyButton } from './CopyButton'
import { OrionMark } from './OrionMark'
import { GRAPHITE, GUTTER, PINE, RULE } from '../theme'

/**
 * What Orion is, and where its traces are.
 *
 * # Why it holds four rows and not a credits screen
 *
 * Each one answers a question a support exchange has actually had to ask, and
 * none of them can be answered from the outside: which version is installed
 * (the title bar says «Orion» and nothing else), whether this build drives a
 * real adapter or the dry-run backend, what a profile file looks like on disk,
 * and where the log written by a start that failed lives. The last one matters
 * most: a release build has no console, so the file is the only trace left —
 * and a path nobody can find is a file nobody reads.
 *
 * The path is copiable for the same reason it is stated: it exists to be
 * pasted into an explorer window or a message.
 */

/** Word shown for a backend that mounts nothing. */
const DRY_RUN = 'dry-run'

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <Box
      sx={{
        display: 'grid',
        gridTemplateColumns: '112px 1fr',
        alignItems: 'baseline',
        gap: 1,
        py: 0.75,
        borderTop: `1px solid ${RULE}`,
      }}
    >
      <Typography sx={{ fontSize: 12, color: GRAPHITE }}>{label}</Typography>
      <Box sx={{ minWidth: 0 }}>{children}</Box>
    </Box>
  )
}

export function AboutDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [about, setAbout] = useState<About | null>(null)
  const [failure, setFailure] = useState<string | null>(null)

  // Read on each opening rather than once: a rebuild of the shell under a
  // running window would otherwise keep showing the version it started with.
  useEffect(() => {
    if (!open) return
    let cancelled = false
    api
      .aboutOrion()
      .then((found) => {
        if (!cancelled) {
          setAbout(found)
          setFailure(null)
        }
      })
      .catch((cause) => {
        if (!cancelled) setFailure(String(cause))
      })
    return () => {
      cancelled = true
    }
  }, [open])

  const simulated = about?.backend === DRY_RUN

  return (
    <Dialog open={open} onClose={onClose} maxWidth="xs" fullWidth aria-labelledby="about-orion">
      <DialogContent sx={{ px: GUTTER, pt: GUTTER }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.25, pb: 1.5 }}>
          <OrionMark style={{ width: 32, height: 32, flexShrink: 0, color: PINE }} title="Orion" />
          <Box sx={{ minWidth: 0 }}>
            <Typography
              id="about-orion"
              component="h2"
              sx={{ fontSize: 16, fontWeight: 700, letterSpacing: '-0.01em' }}
            >
              Orion
            </Typography>
            <Typography sx={{ fontSize: 12, color: GRAPHITE }}>
              Client VPN de la gateway Helios
            </Typography>
          </Box>
        </Box>

        {failure ? (
          <Typography sx={{ fontSize: 12.5, color: GRAPHITE }}>
            Informations indisponibles : {failure}
          </Typography>
        ) : (
          <Box>
            <Row label="Version">
              <Typography sx={{ fontSize: 12.5, fontFamily: 'monospace' }}>
                {about?.version ?? '—'}
              </Typography>
            </Row>
            <Row label="Backend">
              <Typography sx={{ fontSize: 12.5, fontFamily: 'monospace' }}>
                {about?.backend ?? '—'}
              </Typography>
              {/* A dry-run build displays a profile, a negotiated mode and a
                  state while encrypting nothing. It is legitimate in
                  development and nowhere else, so it is said here in full. */}
              {simulated && (
                <Typography sx={{ fontSize: 11.5, color: GRAPHITE, mt: 0.25 }}>
                  Backend simulé : aucun tunnel n’est monté.
                </Typography>
              )}
            </Row>
            <Row label="Profils">
              <Typography sx={{ fontSize: 12.5 }}>
                Fichiers{' '}
                <Box component="span" sx={{ fontFamily: 'monospace' }}>
                  .{about?.profile_extension ?? 'orion'}
                </Box>
              </Typography>
            </Row>
            <Row label="Journal">
              {about?.log_path ? (
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, minWidth: 0 }}>
                  <Typography
                    noWrap
                    title={about.log_path}
                    sx={{ fontSize: 12, fontFamily: 'monospace', minWidth: 0 }}
                  >
                    {about.log_path}
                  </Typography>
                  <CopyButton value={about.log_path} label="Copier le chemin du journal" />
                </Box>
              ) : (
                <Typography sx={{ fontSize: 12.5, color: GRAPHITE }}>
                  Aucun fichier — sortie standard uniquement.
                </Typography>
              )}
            </Row>
          </Box>
        )}
      </DialogContent>
      <DialogActions sx={{ px: GUTTER, pb: 1.5 }}>
        <Button size="small" onClick={onClose}>
          Fermer
        </Button>
      </DialogActions>
    </Dialog>
  )
}
