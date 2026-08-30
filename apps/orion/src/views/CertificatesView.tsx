import { useCallback, useEffect, useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import CircularProgress from '@mui/material/CircularProgress'
import Paper from '@mui/material/Paper'
import Typography from '@mui/material/Typography'
import { KeyRound, RefreshCw } from 'lucide-react'

import * as api from '../api'
import { CertificatePanel, PhasePill, isAlarming, worstPhase } from '../components/CertificatePanel'
import { CopyButton } from '../components/CopyButton'
import { GUTTER, RULE } from '../theme'
import type {
  CertificateAction,
  CertificatePhase,
  ProfileCertificates,
  RenewalProgress,
} from '../types'

type CompanionLaunch =
  | { state: 'launching' }
  | { state: 'launched' }
  | { state: 'failed'; reason: string }

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
  // Process launch is separate from the certificate action: the operation may
  // be validly waiting even when this machine cannot start its companion.
  const [companion, setCompanion] = useState<Record<string, CompanionLaunch>>({})
  // Where each profile's renewal stopped, from the press that opened it.
  // Not persisted and not refreshed: it describes one attempt made here, and a
  // step surviving a reload would outlive the operation it names.
  const [progress, setProgress] = useState<Record<string, RenewalProgress>>({})
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

  const launchCompanion = async (name: string) => {
    setCompanion((current) => ({ ...current, [name]: { state: 'launching' } }))
    try {
      await api.launchCertificateCompanion(name)
      setCompanion((current) => ({ ...current, [name]: { state: 'launched' } }))
    } catch (cause) {
      setCompanion((current) => ({
        ...current,
        [name]: { state: 'failed', reason: String(cause) },
      }))
    }
  }

  const run = async (name: string, action: CertificateAction) => {
    setBusy(true)
    try {
      // Merged, not assigned: `renew_every_profile` advances every profile by
      // one step, and each has its own place to wait for an approval.
      const outcome = await api.runCertificateAction(name, action)
      setProgress((current) => {
        const merged = { ...current, ...outcome.progress }
        // A profile that could not be advanced has no step any more. Leaving
        // the previous one beside its refusal would show a renewal as
        // progressing and refused at once.
        for (const refused of Object.keys(outcome.refused)) delete merged[refused]
        return merged
      })
      setCompanion((current) => {
        const next = { ...current }
        for (const [profile, step] of Object.entries(outcome.progress)) {
          if (step.step !== 'awaiting_operator') delete next[profile]
        }
        for (const refused of Object.keys(outcome.refused)) delete next[refused]
        return next
      })
      await Promise.all(
        Object.entries(outcome.progress)
          .filter(([, step]) => step.step === 'awaiting_operator')
          .map(([profile]) => launchCompanion(profile)),
      )
    } catch {
      // The refusal is recorded on the Rust side and comes back with the
      // refreshed overview: showing it from the rejection as well would print
      // it twice, and the two could disagree after a concurrent change.
      //
      // The previous step is dropped: it described an attempt that a later one
      // has now failed, and leaving it on screen beside the new error would
      // show a renewal as progressing and refused at once.
      setProgress((current) => {
        const { [name]: _dropped, ...rest } = current
        return rest
      })
      setCompanion((current) => {
        const { [name]: _dropped, ...rest } = current
        return rest
      })
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
            <RenewalStep
              step={progress[profile.name]}
              launch={companion[profile.name]}
              onLaunch={() => void launchCompanion(profile.name)}
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

/**
 * Where the renewal this press opened has stopped.
 *
 * Values only. `awaiting_operator` is not a warning to explain — it is where
 * every renewal legitimately waits — so what the row carries is the operation,
 * the launch result and the exact fallback command. The command remains
 * copyable even after a successful launch: policy may stop Orion from opening
 * a process on another machine, and the operation must stay recoverable.
 */
function RenewalStep({
  step,
  launch,
  onLaunch,
}: {
  step: RenewalProgress | undefined
  launch: CompanionLaunch | undefined
  onLaunch: () => void
}) {
  if (!step) return null
  return (
    <Box sx={{ mt: 1.25, pt: 1.25, borderTop: `1px solid ${RULE}` }}>
      {step?.step === 'committed' && (
        <Row label="génération suivante" value={String(step.generation)} />
      )}
      {step?.step === 'rolled_back' && (
        <>
          <Row label="identité servie" value={`génération ${step.generation}`} />
          <Row
            label="sélection jusqu’au"
            value={new Date(step.available_until * 1000).toLocaleString()}
          />
        </>
      )}
      {step && (step.step === 'awaiting_operator' || step.step === 'issuing') && (
        <Row label="opération" value={step.operation_id} copyable />
      )}
      {step?.step === 'awaiting_operator' && (
        <>
          <Row label="approbation" value={step.companion_command} copyable />
          <Button
            size="small"
            variant="outlined"
            color="inherit"
            disabled={launch?.state === 'launching'}
            startIcon={
              launch?.state === 'launching' ? (
                <CircularProgress size={13} color="inherit" />
              ) : (
                <KeyRound size={14} aria-hidden />
              )
            }
            onClick={onLaunch}
            sx={{ mt: 0.75, minHeight: 30, fontSize: 11.5 }}
          >
            {launch?.state === 'launching' ? 'Lancement…' : 'Relancer le compagnon'}
          </Button>
          {launch?.state === 'launched' && (
            <Alert severity="info" variant="outlined" sx={{ mt: 0.75, fontSize: 11.5 }}>
              Compagnon lancé. L’approbation et la clé matérielle restent dans sa fenêtre.
            </Alert>
          )}
          {launch?.state === 'failed' && (
            <Alert severity="error" variant="outlined" sx={{ mt: 0.75, fontSize: 11.5 }}>
              Lancement du compagnon impossible : {launch.reason}
            </Alert>
          )}
        </>
      )}
    </Box>
  )
}

function Row({
  label,
  value,
  copyable,
}: {
  label: string
  value: string
  copyable?: boolean
}) {
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, minWidth: 0, py: 0.3 }}>
      <Typography
        color="text.disabled"
        sx={{ fontSize: 10.5, width: 96, flexShrink: 0, textTransform: 'uppercase' }}
      >
        {label}
      </Typography>
      <Typography
        noWrap
        sx={{ minWidth: 0, flex: '1 1 0', fontFamily: 'monospace', fontSize: 11 }}
        title={value}
      >
        {value}
      </Typography>
      {copyable && <CopyButton value={value} label={label} />}
    </Box>
  )
}

/** Cards in trouble first; among equals, the order the shell returned. */
function rank(phase: CertificatePhase | null): number {
  return phase && isAlarming(phase) ? 1 : 0
}
