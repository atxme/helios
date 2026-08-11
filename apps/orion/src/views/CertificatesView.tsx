import { useCallback, useEffect, useState } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Divider from '@mui/material/Divider'
import Typography from '@mui/material/Typography'
import { RotateCcw } from 'lucide-react'

import * as api from '../api'
import { CertificatePanel } from '../components/CertificatePanel'
import { GUTTER } from '../theme'
import type { CertificateAction, ProfileCertificates } from '../types'

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
 */
export function CertificatesView() {
  const [profiles, setProfiles] = useState<ProfileCertificates[] | null>(null)
  const [busy, setBusy] = useState(false)

  const refresh = useCallback(async () => {
    try {
      setProfiles(await api.certificateOverview())
    } catch {
      setProfiles([])
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

  const helios = profiles?.filter((profile) => profile.negotiates) ?? []
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
          startIcon={<RotateCcw size={14} aria-hidden />}
          onClick={() => void refresh()}
          sx={{ ml: 'auto', color: 'text.secondary', fontSize: 11 }}
        >
          Relire
        </Button>
      </Box>

      {profiles === null && (
        <Typography color="text.disabled" sx={{ fontFamily: 'monospace', fontSize: 11 }}>
          lecture…
        </Typography>
      )}

      {profiles !== null && helios.length === 0 && (
        <Typography color="text.secondary" sx={{ fontSize: 11.5, lineHeight: 1.55 }}>
          Aucun profil de ce poste ne négocie de clé : un profil WireGuard ordinaire n’épingle
          aucun certificat.
        </Typography>
      )}

      {helios.map((profile, index) => (
        <Box key={profile.name}>
          {index > 0 && <Divider sx={{ my: 1.75 }} />}
          <Typography component="h3" sx={{ fontSize: 12.5, fontWeight: 650 }}>
            {profile.name}
          </Typography>
          <CertificatePanel
            inventory={profile.inventory}
            identityName={profile.identity}
            actions={profile.actions}
            lastError={profile.last_error}
            onRun={busy ? undefined : (action) => void run(profile.name, action)}
          />
        </Box>
      ))}

      {/* Named, not hidden: a user looking for a profile that is not here has
          to learn it pins nothing, rather than conclude the screen is broken. */}
      {classic.length > 0 && (
        <>
          <Divider sx={{ my: 1.75 }} />
          <Typography color="text.disabled" sx={{ fontFamily: 'monospace', fontSize: 10.5 }}>
            sans négociation : {classic.map((profile) => profile.name).join(', ')}
          </Typography>
        </>
      )}
    </Box>
  )
}
