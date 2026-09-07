import { useCallback, useEffect, useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import CircularProgress from '@mui/material/CircularProgress'
import Paper from '@mui/material/Paper'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { Fingerprint, KeyRound, RefreshCw } from 'lucide-react'

import * as api from '../api'
import { CertificatePanel, PhasePill, isAlarming, worstPhase } from '../components/CertificatePanel'
import { CopyButton } from '../components/CopyButton'
import { GUTTER, RULE } from '../theme'
import type {
  ApprovalManifest,
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
              name={profile.name}
              step={progress[profile.name]}
              launch={companion[profile.name]}
              onLaunch={() => void launchCompanion(profile.name)}
              onApproved={(step) => {
                setProgress((current) => ({ ...current, [profile.name]: step }))
                void refresh()
              }}
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
 * what is about to be approved, and the way to approve it.
 *
 * # Two doors, and why the ceremony is the first
 *
 * A renewal parked here needs one touch on a security key. That key is very
 * often plugged into *this* machine, and Orion has held the whole ceremony
 * since §8.1.2 — read the request, verify it against what the profile pins,
 * run the assertion, post it. Sending the user to a separate companion for a
 * key already in front of them was making them leave the screen that told them
 * to act. So the ceremony is here, and the companion stays as what it is: the
 * way in when the key is on another machine, or when policy stops Orion from
 * talking to it.
 *
 * # The manifest is read before anything is signed
 *
 * `certificateApprovalManifest` returns fields taken from the **verified**
 * request, never from the envelope, and the shell refuses to run the ceremony
 * until it has been read: what is signed is what was shown. Which is why the
 * button that reads it and the button that touches the key are two buttons.
 */
function RenewalStep({
  name,
  step,
  launch,
  onLaunch,
  onApproved,
}: {
  name: string
  step: RenewalProgress | undefined
  launch: CompanionLaunch | undefined
  onLaunch: () => void
  onApproved: (step: RenewalProgress) => void
}) {
  const [manifest, setManifest] = useState<ApprovalManifest | null>(null)
  const [needsPin, setNeedsPin] = useState(false)
  const [pin, setPin] = useState('')
  const [ceremony, setCeremony] = useState<null | 'reading' | 'signing'>(null)
  const [refusal, setRefusal] = useState<string | null>(null)

  const readManifest = async () => {
    setCeremony('reading')
    setRefusal(null)
    try {
      setManifest(await api.certificateApprovalManifest(name))
      // Asked, never assumed: under Windows the platform dialog collects the
      // PIN and it never enters Orion, so a field here would be asking for a
      // secret nothing in this process can use.
      setNeedsPin(await api.certificateApprovalNeedsPin(name))
    } catch (cause) {
      setRefusal(String(cause))
    } finally {
      setCeremony(null)
    }
  }

  const approve = async () => {
    setCeremony('signing')
    setRefusal(null)
    try {
      const reached = await api.approveCertificateRenewal(name, needsPin ? pin : undefined)
      // The verified request is consumed by the ceremony: keeping the manifest
      // on screen would offer a second touch against a window the authority
      // has already closed.
      setManifest(null)
      setPin('')
      onApproved(reached)
    } catch (cause) {
      setRefusal(String(cause))
    } finally {
      setCeremony(null)
    }
  }

  if (!step) return null
  return (
    <Box sx={{ mt: 1.25, pt: 1.25, borderTop: `1px solid ${RULE}` }}>
      {step?.step === 'committed' && (
        <Row label="génération suivante" value={String(step.generation)} />
      )}
      {step?.step === 'recovered' && (
        <>
          <Row label="génération suivante" value={String(step.generation)} />
          <Typography color="text.disabled" sx={{ mt: 0.5, fontSize: 11, lineHeight: 1.5 }}>
            Identité récupérée : ce poste signe à nouveau.
          </Typography>
        </>
      )}
      {step?.step === 'rolled_back' && (
        <>
          <Row label="identité servie" value={`génération ${step.generation}`} />
          <Row
            label="sélection jusqu’au"
            value={new Date(step.available_until * 1000).toLocaleString('fr-FR', {
              timeZone: 'Europe/Paris',
            })}
          />
        </>
      )}
      {step &&
        (step.step === 'awaiting_operator' ||
          step.step === 'issuing' ||
          step.step === 'recovery_awaiting_operator') && (
          <Row label="opération" value={step.operation_id} copyable />
        )}

      {/* A §7.5 recovery has no door on this machine: the active leaf has
          expired, so there is no request this poste can offer to a key plugged
          in here. What the surface owes the user is therefore the whole of what
          remains to be done, in the form it has to be done in — the command,
          entire, rather than an identifier to reassemble by hand. */}
      {step?.step === 'recovery_awaiting_operator' && (
        <>
          <Typography color="text.secondary" sx={{ mt: 0.75, fontSize: 11.5, lineHeight: 1.55 }}>
            Demande déposée. Elle attend un opérateur muni de sa clé, sur son propre poste :
            l’identité de celui-ci a expiré et ne peut plus rien approuver.
          </Typography>
          <Row label="commande" value={step.operator_command} copyable />
          <Typography color="text.disabled" sx={{ mt: 0.75, fontSize: 11, lineHeight: 1.5 }}>
            Une fois la clé touchée là-bas, relancer « Récupérer le certificat expiré » ici
            pour installer la génération émise.
          </Typography>
        </>
      )}
      {step?.step === 'awaiting_operator' && (
        <>
          {manifest === null ? (
            <Button
              size="small"
              variant="contained"
              disabled={ceremony !== null}
              startIcon={
                ceremony === 'reading' ? (
                  <CircularProgress size={13} color="inherit" />
                ) : (
                  <Fingerprint size={14} aria-hidden />
                )
              }
              onClick={() => void readManifest()}
              sx={{ mt: 0.75, minHeight: 30, fontSize: 11.5 }}
            >
              {ceremony === 'reading' ? 'Lecture…' : 'Lire la demande d’approbation'}
            </Button>
          ) : (
            <Box sx={{ mt: 0.75 }}>
              <Typography color="text.disabled" sx={{ fontSize: 11, lineHeight: 1.5, mb: 0.5 }}>
                Vérifié contre ce que ce profil épingle. C’est cela qui sera signé.
              </Typography>
              <Row label="pair" value={manifest.client_wg_public_key} copyable />
              <Row
                label="génération"
                value={`${manifest.active_generation} → ${manifest.requested_generation}`}
              />
              <Row label="empreinte" value={manifest.request_fingerprint} copyable />
              <Row
                label="expire"
                value={new Date(manifest.expires_at * 1000).toLocaleString('fr-FR', {
                  timeZone: 'Europe/Paris',
                })}
              />
              <Row
                label="clés"
                value={
                  manifest.eligible_credentials === 1
                    ? '1 clé du domaine peut répondre'
                    : `${manifest.eligible_credentials} clés du domaine peuvent répondre`
                }
              />

              {manifest.eligible_credentials === 0 ? (
                <Alert severity="warning" variant="outlined" sx={{ mt: 0.75, fontSize: 11.5 }}>
                  Aucune clé du domaine n’est autorisée à répondre à cette demande. Rien à
                  toucher ici : c’est le registre de credentials qu’il faut reprendre côté
                  autorité.
                </Alert>
              ) : (
                <>
                  {needsPin && (
                    <TextField
                      size="small"
                      type="password"
                      label="PIN de la clé"
                      value={pin}
                      onChange={(event) => setPin(event.target.value)}
                      autoComplete="off"
                      sx={{ mt: 0.75, width: 200 }}
                      slotProps={{ htmlInput: { style: { fontSize: 12 } } }}
                    />
                  )}
                  <Box>
                    <Button
                      size="small"
                      variant="contained"
                      disabled={ceremony !== null || (needsPin && pin === '')}
                      startIcon={
                        ceremony === 'signing' ? (
                          <CircularProgress size={13} color="inherit" />
                        ) : (
                          <KeyRound size={14} aria-hidden />
                        )
                      }
                      onClick={() => void approve()}
                      sx={{ mt: 0.75, minHeight: 30, fontSize: 11.5 }}
                    >
                      {ceremony === 'signing' ? 'Touchez la clé…' : 'Approuver avec la clé'}
                    </Button>
                  </Box>
                </>
              )}
            </Box>
          )}

          {refusal && (
            <Alert
              severity="error"
              variant="outlined"
              sx={{ mt: 0.75, fontSize: 11.5 }}
              onClose={() => setRefusal(null)}
            >
              {refusal}
            </Alert>
          )}

          {/* The way in when the key is not on this machine. Kept whole —
              command included — because a failed launch must still leave the
              operation recoverable by hand. */}
          <Typography color="text.disabled" sx={{ mt: 1, fontSize: 11, lineHeight: 1.5 }}>
            Si la clé est sur un autre poste, l’approbation s’y fait par le compagnon.
          </Typography>
          <Row label="compagnon" value={step.companion_command} copyable />
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
