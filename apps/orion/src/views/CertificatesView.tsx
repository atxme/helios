import { useCallback, useEffect, useRef, useState } from 'react'
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
export function CertificatesView({
  onApprove,
  completedRecovery,
}: {
  /** Starts a §7.5 ceremony in the Astra tab, when the key is on this machine. */
  onApprove?: (operationId: string) => Promise<void>
  /** Result committed while this view was unmounted in the Astra tab. */
  completedRecovery?: Record<string, RenewalProgress> | null
} = {}) {
  const [profiles, setProfiles] = useState<ProfileCertificates[] | null>(null)
  const [failed, setFailed] = useState(false)
  const [busy, setBusy] = useState(false)
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

  useEffect(() => {
    if (!completedRecovery) return
    setProgress((current) => ({ ...current, ...completedRecovery }))
    const activation = Math.min(
      ...Object.values(completedRecovery)
        .filter((step) => step.step === 'recovered')
        .map((step) => step.activation_at),
    )
    if (!Number.isFinite(activation)) return
    const delay = Math.max(0, activation * 1000 - Date.now() + 250)
    const timer = window.setTimeout(() => void refresh(), Math.min(delay, 2_147_483_647))
    return () => window.clearTimeout(timer)
  }, [completedRecovery, refresh])

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
          Aucun profil de ce poste ne négocie de clé.
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
              onApprove={onApprove}
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
 * # One door: the key on this machine
 *
 * A renewal parked here needs one touch on a security key, and the whole
 * ceremony runs in this process. There is no companion to launch: an ordinary
 * renewal belongs to the peer that opened it, so only this workstation can
 * answer it.
 *
 * # The manifest is read before anything is signed
 *
 * The request is read on its own as soon as the step appears — once per
 * operation — and shown before the key is asked for anything. It carries fields
 * taken from the **verified** request, never from the envelope, and the shell
 * refuses to run the ceremony until it has been read: what is signed is what
 * was shown. A failed approval keeps the manifest and the button: the request
 * is consumed only at the deposit, so retrying is one click.
 */
function RenewalStep({
  name,
  step,
  onApproved,
  onApprove,
}: {
  name: string
  step: RenewalProgress | undefined
  onApproved: (step: RenewalProgress) => void
  /** Opens the §7.5 ceremony in the Astra tab, when the key is on this machine. */
  onApprove?: (operationId: string) => Promise<void>
}) {
  const [read, setRead] = useState<{ operation: string; manifest: ApprovalManifest } | null>(null)
  const [needsPin, setNeedsPin] = useState(false)
  const [pin, setPin] = useState('')
  const [reading, setReading] = useState(false)
  const [signing, setSigning] = useState(false)
  const [refusal, setRefusal] = useState<string | null>(null)
  const [approving, setApproving] = useState(false)
  // Folded: on the workstation that holds the key, the button is the gesture.
  const [manualPath, setManualPath] = useState(false)
  // The operation whose request was last read: one automatic read per
  // operation, whatever re-renders the step goes through.
  const readFor = useRef<string | null>(null)
  const operationId =
    step?.step === 'awaiting_operator' ? step.operation_id : null

  // Keyed by operation, so the render that brings a new operation_id already
  // shows no manifest: no frame carries the previous request.
  const manifest = read !== null && read.operation === operationId ? read.manifest : null

  const readManifest = useCallback(
    async (operation: string) => {
      readFor.current = operation
      // Nothing approvable survives a re-read: a failed one must not leave the
      // previous request beside its error.
      setRead(null)
      setPin('')
      setReading(true)
      setRefusal(null)
      try {
        const fetched = await api.certificateApprovalManifest(name)
        // Asked, never assumed: under Windows the platform dialog collects the
        // PIN and it never enters Orion, so a field here would be asking for a
        // secret nothing in this process can use.
        const pinWanted = await api.certificateApprovalNeedsPin(name)
        if (readFor.current !== operation) return
        setRead({ operation, manifest: fetched })
        setNeedsPin(pinWanted)
      } catch (cause) {
        if (readFor.current === operation) setRefusal(String(cause))
      } finally {
        if (readFor.current === operation) setReading(false)
      }
    },
    [name],
  )

  useEffect(() => {
    if (operationId === null) {
      readFor.current = null
      return
    }
    if (readFor.current === operationId) return
    void readManifest(operationId)
  }, [operationId, readManifest])

  const approve = async () => {
    setSigning(true)
    setRefusal(null)
    try {
      const reached = await api.approveCertificateRenewal(name, needsPin ? pin : undefined)
      setRead(null)
      setPin('')
      onApproved(reached)
    } catch (cause) {
      // The manifest stays: the request is consumed only at the deposit, so a
      // key that was absent, a wrong PIN or a cancelled dialog is retried with
      // one click. If the failure came after the deposit, « Relire la demande »
      // is the way to find out.
      setPin('')
      setRefusal(String(cause))
    } finally {
      setSigning(false)
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
            Identité récupérée et commitée. Elle sera utilisée à partir du{' '}
            {new Date(step.activation_at * 1000).toLocaleString('fr-FR', {
              timeZone: 'Europe/Paris',
            })}.
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

      {step?.step === 'recovery_awaiting_operator' && (
        <>
          <Typography color="text.secondary" sx={{ mt: 0.75, fontSize: 11.5, lineHeight: 1.55 }}>
            Demande déposée. Elle attend un opérateur muni de sa clé.
          </Typography>
          {onApprove && (
            <Button
              size="small"
              variant="contained"
              disabled={approving}
              startIcon={
                approving ? (
                  <CircularProgress size={13} color="inherit" />
                ) : (
                  <KeyRound size={14} aria-hidden />
                )
              }
              onClick={() => {
                setApproving(true)
                setRefusal(null)
                // A ceremony that never opens is the failure this screen is
                // most likely to meet — no local channel, no helper beside
                // Orion, a handshake that times out. Swallowing it left a
                // spinner, then nothing: the operator had no way to tell a
                // refusal from a button that does not work.
                void onApprove(step.operation_id)
                  .catch((cause) => setRefusal(String(cause)))
                  .finally(() => setApproving(false))
              }}
              sx={{ mt: 0.75, minHeight: 30, fontSize: 11.5 }}
            >
              Approuver ici avec la clé
            </Button>
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
          <Button
            size="small"
            variant="text"
            color="inherit"
            onClick={() => setManualPath(!manualPath)}
            sx={{ mt: 0.75, minHeight: 26, fontSize: 11, textTransform: 'none' }}
          >
            {manualPath ? 'Masquer le chemin manuel' : 'La clé est sur un autre poste ?'}
          </Button>
          {manualPath && (
            <Typography color="text.disabled" sx={{ mt: 0.5, fontSize: 11, lineHeight: 1.5 }}>
              Sur le poste de l’opérateur : Astra › Approbations › « Approuver une
              récupération », avec cet identifiant. Puis relancez « Récupérer le
              certificat expiré » ici.
            </Typography>
          )}
        </>
      )}
      {step?.step === 'awaiting_operator' && (
        <>
          {reading && (
            <Typography color="text.secondary" sx={{ mt: 0.75, fontSize: 11.5 }}>
              Lecture de la demande…
            </Typography>
          )}
          {manifest !== null && (
            <Box sx={{ mt: 0.75 }}>
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
                  Aucune clé du domaine n’est autorisée à répondre à cette demande.
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
                      disabled={signing || (needsPin && pin === '')}
                      startIcon={
                        signing ? (
                          <CircularProgress size={13} color="inherit" />
                        ) : (
                          <KeyRound size={14} aria-hidden />
                        )
                      }
                      onClick={() => void approve()}
                      sx={{ mt: 0.75, minHeight: 30, fontSize: 11.5 }}
                    >
                      {signing ? 'Touchez la clé…' : 'Approuver avec la clé'}
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

          {/* After a failed read, and after a failed approval: the second case
              covers a retry refused because the request was consumed. */}
          {refusal && !reading && !signing && operationId !== null && (
            <Button
              size="small"
              variant="outlined"
              color="inherit"
              startIcon={<Fingerprint size={14} aria-hidden />}
              onClick={() => void readManifest(operationId)}
              sx={{ mt: 0.75, minHeight: 30, fontSize: 11.5 }}
            >
              Relire la demande
            </Button>
          )}

          <Button
            size="small"
            variant="text"
            color="inherit"
            onClick={() => setManualPath(!manualPath)}
            sx={{ mt: 0.75, minHeight: 26, fontSize: 11, textTransform: 'none' }}
          >
            {manualPath ? 'Masquer le chemin manuel' : 'La clé est sur un autre poste ?'}
          </Button>
          {manualPath && (
            <Typography color="text.disabled" sx={{ mt: 0.5, fontSize: 11, lineHeight: 1.5 }}>
              Cette approbation se fait sur ce poste : la gateway n’accepte la réponse que
              du poste qui a demandé le renouvellement. Branchez ici la clé d’un opérateur.
            </Typography>
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
