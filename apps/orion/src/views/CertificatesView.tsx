import { useCallback, useEffect, useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import CircularProgress from '@mui/material/CircularProgress'
import Paper from '@mui/material/Paper'
import Typography from '@mui/material/Typography'
import { RefreshCw } from 'lucide-react'

import * as api from '../api'
import { CertificatePanel, PhasePill, isAlarming, worstPhase } from '../components/CertificatePanel'
import { GUTTER } from '../theme'
import type { CertificateAction, CertificatePhase, ProfileCertificates } from '../types'

/**
 * Certificates — its own destination, between Profiles and the log.
 *
 * # Why it is not a block inside Profiles
 *
 * It answers a different question, for a different reason, at a different
 * moment. Profiles is where one *edits* a profile: a name, an endpoint, a
 * mode. This is where one finds out **why a profile that used to work does
 * not** — and the answer is almost always a date. Folding the two put a
 * four-row expiry table under an edit form nobody opens unless they already
 * intend to change something.
 *
 * It also has to be per **device**, not per profile. Spec §12.2 asks for
 * «Renouveler tous les profils Helios de cet appareil», and an action over
 * every profile cannot live on a screen that shows one at a time.
 *
 * # One command, not two per profile
 *
 * Reading a profile's certificates unseals its protected identity. A screen
 * listing six profiles asking two questions each would make twelve DPAPI
 * round trips to draw one view; `certificate_overview` answers once.
 *
 * # One card per profile, worst first
 *
 * Profiles used to run together as headings separated by rules, and the only
 * way to learn a profile was in trouble was to read its four rows. Each one
 * now sits in its own card carrying the state of its worst certificate beside
 * its name, and the cards in trouble are on top — a user who opens this screen
 * because something stopped connecting sees the cause before scrolling.
 *
 * The reload is «Actualiser», with the circular arrow. «Relire» with an undo
 * arrow read as *revenir en arrière*, which is exactly what the four actions
 * below it can be asked to do.
 */
export function CertificatesView() {
  const [profiles, setProfiles] = useState<ProfileCertificates[] | null>(null)
  const [failed, setFailed] = useState(false)
  const [busy, setBusy] = useState(false)
  const [reloading, setReloading] = useState(false)

  const refresh = useCallback(async () => {
    setReloading(true)
    try {
      setProfiles(await api.certificateOverview())
      setFailed(false)
    } catch {
      // An unanswered read is not an empty device. Reporting the two the same
      // way told a user with six profiles that they had none.
      setProfiles([])
      setFailed(true)
    } finally {
      setReloading(false)
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const run = async (name: string, action: CertificateAction) => {
    setBusy(true)
    try {
      await api.runCertificateAction(name, action)
    } catch {
      // The refusal is recorded on the Rust side and comes back with the
      // refreshed overview: showing it from the rejection as well would print
      // it twice, and the two could disagree after a concurrent change.
    } finally {
      setBusy(false)
      await refresh()
    }
  }

  const helios = (profiles?.filter((profile) => profile.negotiates) ?? [])
    .map((profile) => ({ profile, phase: worstPhase(profile.inventory) }))
    // Worst first, and stable inside a rank: a list that reorders itself on
    // every refresh cannot be pointed at over a phone call.
    .sort((a, b) => rank(b.phase) - rank(a.phase))
  const classic = profiles?.filter((profile) => !profile.negotiates) ?? []

  return (
    <Box sx={{ height: '100%', overflowY: 'auto', px: GUTTER, py: 1.5 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1.5 }}>
        <Typography component="h2" sx={{ fontSize: 13, fontWeight: 700 }}>
          Certificats
        </Typography>
        <Button
          size="small"
          variant="text"
          color="inherit"
          disabled={reloading}
          startIcon={
            reloading ? (
              <CircularProgress size={13} color="inherit" />
            ) : (
              <RefreshCw size={14} aria-hidden />
            )
          }
          onClick={() => void refresh()}
          sx={{ ml: 'auto', minHeight: 30, color: 'text.secondary', fontSize: 11.5 }}
        >
          Actualiser
        </Button>
      </Box>

      {profiles === null && (
        <Typography color="text.disabled" sx={{ fontSize: 11.5 }}>
          lecture…
        </Typography>
      )}

      {failed && (
        <Alert severity="error" variant="outlined" sx={{ fontSize: 11.5 }}>
          Les certificats de ce poste n’ont pas pu être lus.
        </Alert>
      )}

      {profiles !== null && !failed && helios.length === 0 && (
        <Typography color="text.secondary" sx={{ fontSize: 11.5, lineHeight: 1.55 }}>
          Aucun profil de ce poste ne négocie de clé : un profil WireGuard ordinaire n’épingle
          aucun certificat.
        </Typography>
      )}

      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.25 }}>
        {helios.map(({ profile, phase }) => (
          <Paper key={profile.name} variant="outlined" sx={{ px: 1.75, py: 1.5 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, minWidth: 0 }}>
              <Typography
                component="h3"
                noWrap
                sx={{ minWidth: 0, fontSize: 13, fontWeight: 650 }}
              >
                {profile.name}
              </Typography>
              {phase && (
                <Box sx={{ ml: 'auto' }}>
                  <PhasePill phase={phase} dense />
                </Box>
              )}
            </Box>
            <CertificatePanel
              inventory={profile.inventory}
              identityName={profile.identity}
              actions={profile.actions}
              lastError={profile.last_error}
              onRun={busy ? undefined : (action) => void run(profile.name, action)}
            />
          </Paper>
        ))}
      </Box>

      {/* Named, not hidden: a user looking for a profile that is not here has
          to learn it pins nothing, rather than conclude the screen is broken. */}
      {classic.length > 0 && (
        <Typography color="text.disabled" sx={{ mt: 1.5, fontSize: 11 }}>
          sans négociation : {classic.map((profile) => profile.name).join(', ')}
        </Typography>
      )}
    </Box>
  )
}

/** Cards in trouble first; among equals, the order the shell returned. */
function rank(phase: CertificatePhase | null): number {
  return phase && isAlarming(phase) ? 1 : 0
}
