import { useCallback, useEffect, useRef, useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import ButtonBase from '@mui/material/ButtonBase'
import Collapse from '@mui/material/Collapse'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogContentText from '@mui/material/DialogContentText'
import DialogTitle from '@mui/material/DialogTitle'
import Divider from '@mui/material/Divider'
import IconButton from '@mui/material/IconButton'
import InputAdornment from '@mui/material/InputAdornment'
import TextField from '@mui/material/TextField'
import ToggleButton from '@mui/material/ToggleButton'
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import {
  AlertTriangle,
  ChevronRight,
  FileCode2,
  Plus,
  RotateCcw,
  Save,
  ShieldPlus,
  Trash2,
  Upload,
} from 'lucide-react'
import * as api from '../api'
import { readProfileDocument } from '../profileDocument'
import { CopyButton } from '../components/CopyButton'
import { modeAllowed, modeLevel, modeMeta, PROTECTION_MODES } from '../components/state'
import { GUTTER } from '../theme'
import type {
  ClientConfig,
  ClientProfile,
  ImportOutcome,
  KeyNegotiationSettings,
  KeyNegotiationSupport,
  ProfileDraft,
  ProfileIssues,
  ProtectionMode,
} from '../types'

/**
 * Profiles view — master-detail.
 *
 * The stance comes from actual usage: **a profile is normally imported, not
 * typed**. The screen therefore favors choosing and importing, and keeps the
 * four settings almost never touched under "Advanced".
 *
 * "Normally" is not "only", and that is the difference with the first
 * version: everything a profile holds is editable here, key negotiation
 * included. A document that arrives with the wrong negotiation endpoint, or
 * a gateway whose certificate has been reissued, used to leave the user with
 * a read-only block and a command line to run elsewhere. The **one** thing
 * this screen still cannot do is lower the anti-downgrade floor — that is an
 * invariant, not an ergonomic choice.
 *
 * Warnings are **conditional** rather than permanent: a paragraph shown at
 * all times becomes invisible from being there. The one about `AllowedIPs`
 * only appears if the range has been restricted, the one about the PSK only
 * if a static value has been set — that is, at the precise moment the risk
 * exists.
 */

interface Props {
  config: ClientConfig
  pathImport: ClientProfile | null
  onPathImportHandled: () => void
  onImport: (contents: string, fileName: string) => Promise<ImportOutcome>
  onSave: (draft: ProfileDraft) => Promise<void>
  onDelete: (name: string) => Promise<void>
  onSelect: (name: string) => Promise<void>
}

function blankProfile(): ClientProfile {
  return {
    name: 'nouveau',
    endpoint: '',
    peer_public_key: '',
    // A brand-new profile has no key yet: Rust draws one when it is first
    // saved. Nothing here ever holds one (ADR-006 §5).
    public_key: null,
    has_private_key: false,
    has_static_psk: false,
    address: null,
    allowed_ips: '0.0.0.0/0',
    persistent_keepalive: 25,
    heliosd_url: null,
    // No negotiation by default: its material comes from the operator, and a
    // block full of empty certificates would report itself faulty from the
    // first render. Adding one is one click away in the block below.
    key_negotiation: null,
  }
}

/**
 * What the screen has to say about the last action it took.
 *
 * `transient` separates two kinds: an import notice states a *situation* the
 * user must act on and stays until the next edit clears it, whereas a save
 * confirmation states a *fact* already true — leaving it on screen would soon
 * describe a draft that has since moved on.
 */
type Notice = { tone: 'success' | 'error'; message: string; transient?: boolean }

/** How long a transient notice stays, in milliseconds. */
const NOTICE_MS = 3000

const MAX_IMPORT_BYTES = 64 * 1024

/** Range that captures all traffic — the one that holds up the fail-open invariant. */
const CAPTURE_ALL = '0.0.0.0/0'

/**
 * Delay before judging a field, in milliseconds.
 *
 * We wait for typing to stop: validating on every character would highlight
 * red on every intermediate state of an address being entered — "86",
 * "86.2", "86.22" are all invalid along the way.
 */
const VALIDATION_DELAY_MS = 500

/**
 * Depth of the undo history.
 *
 * One entry per field modification: enough to undo an entire entry without
 * letting the array grow indefinitely during a long session.
 */
const HISTORY_LIMIT = 50

/**
 * Negotiation settings for a block being created by hand.
 *
 * The floor starts at `classic` because nothing has been negotiated yet: it
 * is raised by the first committed negotiation, and by this screen, but it
 * would be a lie to start it at the mode merely *wished for*. The mode, on
 * the other hand, starts at the strongest — that is what one comes here for.
 */
function blankNegotiation(): KeyNegotiationSettings {
  return {
    mode: 'ml_kem',
    minimum_mode: 'classic',
    endpoint: '',
    server_name: '',
    gateway_ca_der: '',
    gateway_pq_certificate: '',
    identity: '',
  }
}

export function ProfilesView({
  config,
  pathImport,
  onPathImportHandled,
  onImport,
  onSave,
  onDelete,
  onSelect,
}: Props) {
  const initial =
    config.profiles.find((profile) => profile.name === config.selected) ??
    config.profiles[0] ??
    blankProfile()
  const [draft, setDraft] = useState<ClientProfile>(initial)
  /**
   * Floor this profile arrived with — the one the screen may not go under.
   *
   * It is captured whenever a profile is *loaded* rather than read from the
   * draft: the draft is exactly what the user is allowed to raise, so
   * comparing it to itself would authorize a slow slide back down, one save
   * at a time.
   */
  const [floorBaseline, setFloorBaseline] = useState<ProtectionMode | null>(
    initial.key_negotiation?.minimum_mode ?? null,
  )
  const [dirty, setDirty] = useState(false)
  const [importing, setImporting] = useState(false)
  const [notice, setNotice] = useState<Notice | null>(null)
  /**
   * Secret-touching **intents**, not values.
   *
   * The screen can ask Rust to draw a new key or to drop the static PSK; it
   * cannot supply either. Holding them as booleans beside the draft is what
   * keeps the form a description of public state.
   */
  const [rotateKey, setRotateKey] = useState(false)
  const [clearPsk, setClearPsk] = useState(false)
  const [issues, setIssues] = useState<Partial<ProfileIssues>>({})
  const [history, setHistory] = useState<ClientProfile[]>([])
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [advanced, setAdvanced] = useState(false)
  const [support, setSupport] = useState<KeyNegotiationSupport | null>(null)
  const [fingerprint, setFingerprint] = useState<string | null>(null)
  const [identitySealed, setIdentitySealed] = useState(false)
  const fileInput = useRef<HTMLInputElement>(null)

  useEffect(() => {
    if (!notice?.transient) return
    const id = setTimeout(() => setNotice(null), NOTICE_MS)
    return () => clearTimeout(id)
  }, [notice])

  // A build fact, not a profile one: asked once.
  useEffect(() => {
    let cancelled = false
    api
      .keyNegotiationSupport()
      .then((found) => {
        if (!cancelled) setSupport(found)
      })
      .catch(() => {
        if (!cancelled) setSupport(null)
      })
    return () => {
      cancelled = true
    }
  }, [])

  // Same rule as the public key: the fingerprint is derived on the Rust side.
  // The UI handles no crypto, and an unreadable certificate simply yields no
  // value — the fault is reported by the core, not disguised as a hash.
  useEffect(() => {
    let cancelled = false
    api
      .keyNegotiationFingerprint(draft.key_negotiation)
      .then((found) => {
        if (!cancelled) setFingerprint(found)
      })
      .catch(() => {
        if (!cancelled) setFingerprint(null)
      })
    return () => {
      cancelled = true
    }
  }, [draft])

  // Re-asked on every import notice: sealing happens during import, so the
  // answer changes at exactly that moment.
  useEffect(() => {
    let cancelled = false
    api
      .keyNegotiationIdentitySealed(draft.key_negotiation)
      .then((sealed) => {
        if (!cancelled) setIdentitySealed(sealed)
      })
      .catch(() => {
        if (!cancelled) setIdentitySealed(false)
      })
    return () => {
      cancelled = true
    }
  }, [draft, notice])

  /**
   * The draft in the shape the shell accepts: public fields plus intents.
   *
   * Built here, once, so the two callers that send it — validation and save —
   * cannot drift. Note what it does *not* contain, and cannot: neither secret
   * is reachable from this module.
   */
  const toDraft = useCallback(
    (profile: ClientProfile): ProfileDraft => ({
      name: profile.name,
      endpoint: profile.endpoint,
      peer_public_key: profile.peer_public_key,
      address: profile.address,
      allowed_ips: profile.allowed_ips,
      persistent_keepalive: profile.persistent_keepalive,
      heliosd_url: profile.heliosd_url,
      key_negotiation: profile.key_negotiation,
      generatePrivateKey: rotateKey,
      clearPresharedKey: clearPsk,
    }),
    [clearPsk, rotateKey],
  )

  // The public key is no longer derived on demand: it comes down with the
  // profile, because the private half it derives from never leaves Rust.
  const publicKey = draft.public_key

  // The rules live in `orion-core`: we query the core rather than duplicate
  // its validation grammar in the UI. The call is deferred until typing
  // finishes.
  useEffect(() => {
    let cancelled = false
    const timer = setTimeout(() => {
      api
        .validateProfile(toDraft(draft))
        .then((found) => {
          if (!cancelled) setIssues(found)
        })
        .catch(() => {
          if (!cancelled) setIssues({})
        })
    }, VALIDATION_DELAY_MS)
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [draft, toDraft])

  /**
   * Replaces the draft wholesale.
   *
   * Selecting, importing, reverting and starting fresh all go through here:
   * each of them also resets the undo history and re-arms the floor ratchet,
   * and doing that at four call sites is how one of them ends up forgetting.
   */
  const loadDraft = useCallback((profile: ClientProfile) => {
    setDraft(profile)
    setHistory([])
    setFloorBaseline(profile.key_negotiation?.minimum_mode ?? null)
    // Intents belong to the edit in progress, never to the profile: carrying a
    // pending rotation onto the next profile loaded would rotate a key the
    // user never asked about.
    setRotateKey(false)
    setClearPsk(false)
  }, [])

  useEffect(() => {
    if (dirty) return
    const selected =
      config.profiles.find((profile) => profile.name === config.selected) ?? config.profiles[0]
    if (selected) loadDraft(selected)
  }, [config, dirty, loadDraft])

  useEffect(() => {
    if (!pathImport) return
    const replaces = config.profiles.some((candidate) => candidate.name === pathImport.name)
    loadDraft(pathImport)
    setDirty(true)
    setNotice({
      tone: 'success',
      message: replaces
        ? `« ${pathImport.name} » chargé. Enregistrer remplacera le profil existant.`
        : `« ${pathImport.name} » chargé. Vérifiez-le puis enregistrez-le.`,
    })
    onPathImportHandled()
  }, [config.profiles, loadDraft, onPathImportHandled, pathImport])

  const set = <Key extends keyof ClientProfile>(key: Key, value: ClientProfile[Key]) => {
    setHistory((past) => [...past, draft].slice(-HISTORY_LIMIT))
    setDraft((profile) => ({ ...profile, [key]: value }))
    setDirty(true)
    setNotice(null)
  }

  /** Writes one field of the negotiation block. */
  const setNegotiation = <Key extends keyof KeyNegotiationSettings>(
    key: Key,
    value: KeyNegotiationSettings[Key],
  ) => {
    const settings = draft.key_negotiation
    if (!settings) return
    // A mode under the floor is refused here rather than silently written:
    // the core refuses it too, before any network access, and the screen must
    // not promise what the connection would reject.
    if (key === 'mode' && !modeAllowed(value as ProtectionMode, settings.minimum_mode)) return
    editNegotiation({ [key]: value } as Partial<KeyNegotiationSettings>)
  }

  /**
   * Raises the anti-downgrade floor.
   *
   * Only upward, and only above the value the profile was loaded with: the
   * gateway holds the same ratchet per peer, so a floor lowered here would
   * merely produce a negotiation refused at the other end. Raising it past
   * the selected mode pulls the mode along — leaving a mode below its own
   * floor would just make the profile invalid on the spot.
   */
  const raiseFloor = (floor: ProtectionMode) => {
    const settings = draft.key_negotiation
    if (!settings) return
    if (floorBaseline && !modeAllowed(floor, floorBaseline)) return
    editNegotiation({
      minimum_mode: floor,
      ...(modeAllowed(settings.mode, floor) ? {} : { mode: floor }),
    })
  }

  const editNegotiation = (patch: Partial<KeyNegotiationSettings>) => {
    setHistory((past) => [...past, draft].slice(-HISTORY_LIMIT))
    setDraft((profile) =>
      profile.key_negotiation
        ? { ...profile, key_negotiation: { ...profile.key_negotiation, ...patch } }
        : profile,
    )
    setDirty(true)
    setNotice(null)
  }

  /**
   * Adds a negotiation block to a profile that had none, or removes it.
   *
   * Removal is a downgrade — the tunnel then goes back to mounting before
   * anything is authenticated — so it is offered only while nothing has been
   * negotiated yet. Once a floor exists, that floor is what forbids it.
   */
  const toggleNegotiation = (enabled: boolean) => {
    if (!enabled && floorBaseline && modeLevel(floorBaseline) > 0) return
    setHistory((past) => [...past, draft].slice(-HISTORY_LIMIT))
    const settings = enabled ? blankNegotiation() : null
    setDraft((profile) => ({ ...profile, key_negotiation: settings }))
    setFloorBaseline(settings?.minimum_mode ?? null)
    setDirty(true)
    setNotice(null)
  }

  /** Undoes the last field modification. */
  const undo = useCallback(() => {
    if (history.length === 0) return
    setDraft(history[history.length - 1])
    setHistory((past) => past.slice(0, -1))
    setDirty(true)
    setNotice(null)
  }, [history])

  /** Reverts to the profile as saved, in one go. */
  const revert = () => {
    const saved =
      config.profiles.find((profile) => profile.name === draft.name) ??
      config.profiles.find((profile) => profile.name === config.selected) ??
      config.profiles[0]
    if (!saved) return
    loadDraft(saved)
    setDirty(false)
    setNotice(null)
  }

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const combo =
        (event.ctrlKey || event.metaKey) && !event.shiftKey && event.key.toLowerCase() === 'z'
      if (!combo) return
      // Fields are controlled by React: the browser's native undo is
      // inoperative there since the value is rewritten on every render. It's
      // therefore up to the view to hold the history, and to intercept the
      // shortcut.
      event.preventDefault()
      undo()
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [undo])

  const save = async () => {
    try {
      await onSave(toDraft(draft))
      setDirty(false)
      setRotateKey(false)
      setClearPsk(false)
      // Saving is the one action here with no visible consequence: the form
      // shows exactly what it showed a moment earlier. Without a word, one
      // presses the button again to be sure.
      setNotice({
        tone: 'success',
        message: `« ${draft.name} » enregistré.`,
        transient: true,
      })
    } catch {
      // The global error keeps the draft intact to allow a correction.
    }
  }

  const remove = async () => {
    try {
      await onDelete(draft.name)
      setDeleteOpen(false)
      setDirty(false)
    } catch {
      // The global error explains the failure and the dialog stays open.
    }
  }

  const importFile = async (file: File | undefined) => {
    if (!file) return
    setNotice(null)
    if (file.size > MAX_IMPORT_BYTES) {
      setNotice({ tone: 'error', message: 'Fichier trop volumineux (maximum 64 Kio).' })
      if (fileInput.current) fileInput.current.value = ''
      return
    }

    setImporting(true)
    try {
      const imported = await onImport(await readProfileDocument(file), file.name)
      const profile = imported.profile
      const existing = config.profiles.find((candidate) => candidate.name === profile.name)

      loadDraft(profile)
      setDirty(true)
      // A missing private key outranks the rest: the profile is on screen but
      // WireGuard has nothing to sign with, and the message says which key is
      // expected — that is what lets the user act.
      if (imported.private_key_missing) {
        setNotice({ tone: 'error', message: imported.private_key_missing })
      }
      // The identity failing to seal outranks the profile loading fine: the
      // profile is visible on screen, whereas an unsealed identity only
      // shows up much later, as a connection that fails before WireGuard.
      else if (imported.identity_error) {
        setNotice({
          tone: 'error',
          message: `« ${profile.name} » chargé, mais l’identité n’a pas pu être scellée : ${imported.identity_error}`,
        })
      } else {
        const sealed = imported.identity_sealed
          ? ' Identité scellée dans le stockage protégé : le fichier peut être détruit.'
          : ''
        setNotice({
          tone: 'success',
          message: existing
            ? `« ${profile.name} » chargé. Enregistrer remplacera le profil existant.${sealed}`
            : `« ${profile.name} » chargé. Vérifiez-le puis enregistrez-le.${sealed}`,
        })
      }
    } catch (cause) {
      setNotice({ tone: 'error', message: `Import impossible : ${String(cause)}` })
    } finally {
      setImporting(false)
      if (fileInput.current) fileInput.current.value = ''
    }
  }

  const exists = config.profiles.some((profile) => profile.name === draft.name)
  const narrowed = draft.allowed_ips.trim() !== CAPTURE_ALL
  const staticPsk = draft.has_static_psk && !clearPsk
  const invalid = Object.values(issues).some(Boolean)
  // The "Advanced" collapse must flag what it hides: otherwise a faulty
  // field would stay invisible until someone thinks to open it.
  const advancedFlagged =
    narrowed ||
    staticPsk ||
    Boolean(
      issues.allowed_ips || issues.persistent_keepalive || issues.preshared_key || issues.heliosd_url,
    )

  return (
    <Box sx={{ display: 'flex', height: '100%', flexDirection: 'column' }}>
      <Box sx={{ display: 'grid', gridTemplateColumns: '176px 1fr', minHeight: 0, flex: 1 }}>
        {/* ── Master: the list. Choosing is the primary action. ── */}
        <Box
          sx={{
            display: 'flex',
            flexDirection: 'column',
            borderRight: 1,
            borderColor: 'divider',
            pt: 1.5,
          }}
        >
          <Typography
            component="h2"
            variant="overline"
            color="text.disabled"
            sx={{ px: GUTTER, pb: 0.5 }}
          >
            Profils
          </Typography>

          <Box component="ul" sx={{ m: 0, p: 0, listStyle: 'none', overflow: 'hidden' }}>
            {config.profiles.map((profile) => {
              const active = profile.name === draft.name
              return (
                <Box component="li" key={profile.name}>
                  <ButtonBase
                    onClick={() => {
                      loadDraft(profile)
                      setDirty(false)
                      setNotice(null)
                      void onSelect(profile.name).catch(() => {})
                    }}
                    aria-current={active ? 'true' : undefined}
                    sx={{
                      position: 'relative',
                      display: 'block',
                      width: '100%',
                      px: GUTTER,
                      py: 1,
                      textAlign: 'left',
                      bgcolor: active ? 'action.selected' : 'transparent',
                      '&:hover': { bgcolor: 'action.hover' },
                    }}
                  >
                    {active && (
                      <Box
                        aria-hidden
                        sx={{
                          position: 'absolute',
                          top: 6,
                          bottom: 6,
                          left: 0,
                          width: 2,
                          borderRadius: 1,
                          bgcolor: 'primary.main',
                        }}
                      />
                    )}
                    <Typography
                      noWrap
                      sx={{
                        fontSize: 12.5,
                        fontWeight: active ? 650 : 500,
                        color: active ? 'primary.main' : 'text.primary',
                      }}
                    >
                      {profile.name}
                    </Typography>
                  </ButtonBase>
                </Box>
              )
            })}
          </Box>

          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5, mt: 'auto', p: 1 }}>
            <Box
              component="input"
              ref={fileInput}
              type="file"
              // `.orionprofile` d'abord : c'est l'extension que produit
              // `helios-ctl enroll` et celle qu'Orion associe au double-clic.
              // Son absence ici la grisait dans le sélecteur, ce qui donnait à
              // penser que le format n'était pas supporté — alors que le
              // parseur l'accepte depuis toujours (il reconnaît le JSON à son
              // premier caractère, pas au suffixe).
              accept=".orionprofile,.json,.conf,application/json,text/plain"
              onChange={(event: React.ChangeEvent<HTMLInputElement>) =>
                void importFile(event.target.files?.[0])
              }
              sx={{ display: 'none' }}
            />
            <Button
              size="small"
              variant="contained"
              startIcon={<Upload size={15} aria-hidden />}
              disabled={importing}
              onClick={() => fileInput.current?.click()}
            >
              {importing ? 'Chargement…' : 'Importer'}
            </Button>
            <Button
              size="small"
              variant="text"
              color="inherit"
              startIcon={<Plus size={15} aria-hidden />}
              onClick={() => {
                loadDraft(blankProfile())
                setDirty(true)
                setNotice(null)
              }}
              sx={{ color: 'text.secondary' }}
            >
              Nouveau
            </Button>
          </Box>
        </Box>

        {/* ── Detail: the essentials visible, the rare things collapsed. ──
            Vertical scrolling is allowed here, and only here: a clipped
            certificate warning would be worse than a scrollbar. */}
        <Box sx={{ minWidth: 0, overflowX: 'hidden', overflowY: 'auto', px: GUTTER, py: 1.5 }}>
          {notice && (
            <Alert
              severity={notice.tone}
              variant="outlined"
              role={notice.tone === 'error' ? 'alert' : 'status'}
              sx={{ mb: 1.5, py: 0, fontSize: 12 }}
            >
              {notice.message}
            </Alert>
          )}

          <Box
            sx={{
              display: 'grid',
              gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
              gap: 1.5,
              alignItems: 'start',
            }}
          >
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
              <Field label="Nom"
                error={issues.name} value={draft.name} onChange={(value) => set('name', value)} />
              <Field
                label="Endpoint"
                error={issues.endpoint}
                placeholder="203.0.113.10:51820"
                value={draft.endpoint}
                onChange={(value) => set('endpoint', value)}
              />
              {/* The private key is stated, never shown. It used to be a text
                  field with a reveal button, which put it in the WebView DOM
                  and in a JavaScript string nothing can wipe — see the note on
                  the shell's `ProfileView`. It arrives by enrolment or is drawn
                  in Rust; either way it does not come through here. */}
              <SecretState
                label="Clé privée"
                present={draft.has_private_key || rotateKey}
                error={issues.private_key}
                presentLabel={rotateKey ? 'nouvelle clé à l’enregistrement' : 'scellée dans le coffre'}
                absentLabel="aucune — importer un profil ou en générer une"
                action={{
                  label: draft.has_private_key ? 'Générer une nouvelle clé' : 'Générer une clé',
                  onClick: () => {
                    setRotateKey(true)
                    setDirty(true)
                    setNotice({
                      tone: 'success',
                      message:
                        'Nouvelle clé à l’enregistrement. Sa clé publique devra être réadmise par l’opérateur.',
                    })
                  },
                  disabled: rotateKey,
                }}
                hint="Elle ne quitte jamais le poste."
              />
              <Field
                label="Clé publique gateway"
                error={issues.peer_public_key}
                value={draft.peer_public_key}
                onChange={(value) => set('peer_public_key', value)}
              />
            </Box>

            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
              <Field
                label="Adresse virtuelle"
                error={issues.address}
                placeholder="assignée à l’enrôlement"
                value={draft.address ?? ''}
                onChange={(value) => set('address', value || null)}
              />
              <ReadOnlyField
                label="Votre clé publique"
                value={publicKey ?? '—'}
                hint="À transmettre à l’opérateur : l’admission est hors bande, elle doit être déclarée sur Helios avant le premier handshake."
              />

              <ButtonBase
                onClick={() => setAdvanced((open) => !open)}
                aria-expanded={advanced}
                sx={{
                  display: 'flex',
                  justifyContent: 'flex-start',
                  gap: 0.5,
                  py: 0.5,
                  color: 'text.secondary',
                  '&:hover': { color: 'text.primary' },
                }}
              >
                <ChevronRight
                  size={14}
                  aria-hidden
                  style={{
                    transform: advanced ? 'rotate(90deg)' : undefined,
                    transition: 'transform 140ms ease',
                  }}
                />
                <Typography sx={{ fontSize: 12, fontWeight: 600 }}>Avancé</Typography>
                {advancedFlagged && (
                  <AlertTriangle size={13} aria-hidden style={{ color: '#A16207' }} />
                )}
              </ButtonBase>

              <Collapse in={advanced} unmountOnExit>
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
                  <Field
                    label="Trafic capté"
                error={issues.allowed_ips}
                    value={draft.allowed_ips}
                    onChange={(value) => set('allowed_ips', value)}
                  />
                  {narrowed && (
                    <Caution>
                      Plage restreinte : ce qui en sort part <strong>en clair</strong>.{' '}
                      {CAPTURE_ALL} capte tout.
                    </Caution>
                  )}
                  <Field
                    label="Keepalive (s)"
                error={issues.persistent_keepalive}
                    type="number"
                    value={String(draft.persistent_keepalive)}
                    onChange={(value) => set('persistent_keepalive', Number(value) || 0)}
                  />
                  {/* Same rule as the private key, and one more: a static PSK
                      is an out-of-band value. It arrives through the enrolment
                      document, so the screen can drop it but never set it. */}
                  <SecretState
                    label="PSK statique"
                    present={staticPsk}
                    error={issues.preshared_key}
                    presentLabel="scellé dans le coffre"
                    absentLabel="aucun — ML-KEM à chaque connexion"
                    action={
                      staticPsk
                        ? {
                            label: 'Retirer le PSK statique',
                            onClick: () => {
                              setClearPsk(true)
                              setDirty(true)
                            },
                            disabled: clearPsk,
                          }
                        : undefined
                    }
                    hint="Se pose à l’enrôlement. Cet écran ne peut que le retirer."
                  />
                  {staticPsk && (
                    <Caution>
                      Un PSK statique <strong>désactive</strong> ML-KEM.
                    </Caution>
                  )}
                  <Field
                    label="URL Helios"
                error={issues.heliosd_url}
                    placeholder="http://100.64.0.1:8080"
                    value={draft.heliosd_url ?? ''}
                    onChange={(value) => set('heliosd_url', value || null)}
                  />
                </Box>
              </Collapse>
            </Box>
          </Box>

          <Divider sx={{ my: 1.75 }} />

          <KeyNegotiation
            settings={draft.key_negotiation}
            floorBaseline={floorBaseline}
            issue={issues.key_negotiation}
            support={support}
            fingerprint={fingerprint}
            identitySealed={identitySealed}
            onChange={setNegotiation}
            onRaiseFloor={raiseFloor}
            onToggle={toggleNegotiation}
          />
        </Box>
      </Box>

      <Divider />
      <Box sx={{ display: 'flex', flexShrink: 0, alignItems: 'center', gap: 1, px: GUTTER, py: 1.25 }}>
        <Typography
          role="status"
          color={invalid ? 'error.main' : dirty ? 'warning.main' : 'text.disabled'}
          sx={{ mr: 'auto', fontSize: 11.5 }}
        >
          {invalid
            ? 'Un champ est invalide'
            : dirty
              ? 'Modifications non enregistrées'
              : 'Profil à jour'}
        </Typography>
        <Tooltip title="Revenir au profil enregistré — Ctrl+Z annule pas à pas">
          <span>
            <Button
              variant="text"
              color="inherit"
              startIcon={<RotateCcw size={15} aria-hidden />}
              onClick={revert}
              disabled={!dirty}
              sx={{ color: 'text.secondary' }}
            >
              Annuler
            </Button>
          </span>
        </Tooltip>
        <Button
          variant="contained"
          startIcon={<Save size={16} aria-hidden />}
          onClick={() => void save()}
          disabled={!dirty || invalid}
        >
          Enregistrer
        </Button>
        {exists && (
          <Tooltip title="Supprimer le profil">
            <IconButton
              color="error"
              onClick={() => setDeleteOpen(true)}
              aria-label={`Supprimer le profil ${draft.name}`}
            >
              <Trash2 size={18} aria-hidden />
            </IconButton>
          </Tooltip>
        )}
      </Box>

      <Dialog open={deleteOpen} onClose={() => setDeleteOpen(false)} aria-labelledby="delete-profile-title">
        <DialogTitle id="delete-profile-title">Supprimer « {draft.name} » ?</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Le profil et ses secrets locaux seront supprimés d’Orion. Cette action ne révoque pas
            automatiquement le pair sur la gateway.
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button color="inherit" onClick={() => setDeleteOpen(false)}>
            Annuler
          </Button>
          <Button color="error" variant="contained" onClick={() => void remove()}>
            Supprimer
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  )
}

/**
 * Key negotiation — the only place where the user chooses a level of
 * protection rather than an address.
 *
 * The block is normally **received**: `helios-ctl enroll` fills it, and
 * nobody types a certificate by hand. But received is not immutable — a
 * negotiation endpoint moves, a gateway certificate gets reissued, a lab
 * differs from production — so every field is editable here, certificates
 * included. What guards against a bad edit is not a read-only attribute: it
 * is the core, which re-verifies the pinned certificate against the peer key
 * of this very profile and reports the block as faulty.
 *
 * One exception, and it is not ergonomic: the **floor only goes up**. It
 * rises by itself after each committed negotiation, on this side as on the
 * gateway's, and the gateway would refuse a weaker mode anyway. Modes below
 * it are shown disabled rather than hidden — seeing what one has left behind
 * is the whole point of a ratchet.
 */
function KeyNegotiation({
  settings,
  floorBaseline,
  issue,
  support,
  fingerprint,
  identitySealed,
  onChange,
  onRaiseFloor,
  onToggle,
}: {
  settings: KeyNegotiationSettings | null
  /** Floor the profile was loaded with: the screen never goes under it. */
  floorBaseline: ProtectionMode | null
  issue?: string | null
  support: KeyNegotiationSupport | null
  /** The identity this profile names is sealed on this machine. */
  identitySealed: boolean
  fingerprint: string | null
  onChange: <Key extends keyof KeyNegotiationSettings>(
    key: Key,
    value: KeyNegotiationSettings[Key],
  ) => void
  onRaiseFloor: (floor: ProtectionMode) => void
  onToggle: (enabled: boolean) => void
}) {
  const title = (
    <Typography component="h3" sx={{ fontSize: 12.5, fontWeight: 650 }}>
      Négociation de clé
    </Typography>
  )

  if (!settings) {
    return (
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
        {title}
        <Typography color="text.secondary" sx={{ fontSize: 11.5, lineHeight: 1.5 }}>
          Aucune : le tunnel monte d’abord, le PSK post-quantique n’arrive
          qu’ensuite par l’API. Le <strong>premier handshake</strong> n’est donc pas protégé.
        </Typography>
        <Button
          size="small"
          variant="outlined"
          startIcon={<ShieldPlus size={14} aria-hidden />}
          onClick={() => onToggle(true)}
          sx={{ ml: 'auto', flexShrink: 0 }}
        >
          Ajouter
        </Button>
      </Box>
    )
  }

  const selected = modeMeta(settings.mode)
  const unusable = support && !support.identity_store
  // Removing the block is a downgrade. It stays possible while nothing has
  // been negotiated — a block just added by hand, typically — and the floor
  // is what closes the door as soon as something has.
  const removable = !floorBaseline || modeLevel(floorBaseline) === 0

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
        {/* No floor chip here: the "Plancher" row below states it, and
            saying it twice is how a screen ends up unreadable. */}
        {title}
        {removable && (
          <Tooltip title="Retirer la négociation : le tunnel remonterait sans protection avant le premier handshake.">
            <Button
              size="small"
              variant="text"
              color="inherit"
              onClick={() => onToggle(false)}
              sx={{ ml: 'auto', color: 'text.secondary', fontSize: 11 }}
            >
              Retirer
            </Button>
          </Tooltip>
        )}
      </Box>

      <ModeChoice
        label="Mode"
        value={settings.mode}
        floor={settings.minimum_mode}
        onChange={(mode) => onChange('mode', mode)}
      />
      <Typography color="text.secondary" sx={{ fontSize: 11, lineHeight: 1.55 }}>
        {selected.detail}
      </Typography>

      <ModeChoice
        label="Plancher"
        value={settings.minimum_mode}
        floor={floorBaseline ?? 'classic'}
        hint="Mode sous lequel ce profil refuse de négocier, avant tout accès réseau. Il ne redescend pas : le relever engage les connexions suivantes."
        onChange={onRaiseFloor}
      />

      <Box
        sx={{
          display: 'grid',
          gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
          gap: 1.5,
          mt: 0.5,
        }}
      >
        <Field
          label="Endpoint de négociation"
          placeholder="gateway:51821"
          value={settings.endpoint}
          onChange={(value) => onChange('endpoint', value)}
        />
        <Field
          label="Nom du serveur"
          placeholder="nom porté par le certificat"
          value={settings.server_name}
          onChange={(value) => onChange('server_name', value)}
        />
        <Field
          label="Identité protégée"
          placeholder="orion-poste"
          value={settings.identity}
          onChange={(value) => onChange('identity', value)}
        />
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <Detail
            label="identité"
            value={identitySealed ? 'scellée' : 'absente de ce poste'}
            hint={
              identitySealed
                ? 'Certificat client scellé au compte Windows par DPAPI. Le fichier d’enrôlement n’est plus nécessaire.'
                : 'Aucune identité de ce nom sur ce poste : importer le fichier d’enrôlement produit par « helios-ctl enroll ».'
            }
          />
        </Box>
      </Box>

      {/* The fingerprint is what one reads; the base64 behind it is what one
          pastes, once, on the rare day a certificate is reissued. Only the
          first belongs in the flow. */}
      <Detail
        label="empreinte PQ"
        value={fingerprint ?? 'illisible'}
        copyable={Boolean(fingerprint)}
        hint="Empreinte SHA-256 du certificat ML-DSA-65 épinglé. Comparer avec ce qu’a affiché « heliosd init-key-negotiation » : c’est ce qui rattache le profil à la bonne gateway."
      />
      <EncodedData
        caDer={settings.gateway_ca_der}
        pqCertificate={settings.gateway_pq_certificate}
        onChange={onChange}
      />

      {/* The missing identity outranks everything else this block says: the
          mode, the floor and the fingerprint are all moot if the client has
          no certificate to present. */}
      {!identitySealed && settings.identity.trim() !== '' && (
        <Caution>
          Aucune identité protégée nommée <strong>{settings.identity}</strong> sur ce poste : la
          connexion échouera <strong>avant</strong> WireGuard. Importer le fichier d’enrôlement
          fourni par l’opérateur — il scelle le certificat client et peut être détruit ensuite.
        </Caution>
      )}

      {issue && (
        <Alert severity="error" variant="outlined" sx={{ py: 0, fontSize: 11 }}>
          {issue}
        </Alert>
      )}

      {unusable && (
        <Caution>
          Aucun stockage protégé d’identité sur ce poste : le certificat client ne peut pas
          être scellé ni relu, et la connexion échouera <strong>avant</strong> WireGuard. Le
          scellement passe par DPAPI, qui n’existe que sous Windows.
        </Caution>
      )}
    </Box>
  )
}

/**
 * Choice among the three modes, ordered and floored.
 *
 * What is under the floor is disabled rather than absent: a ratchet one
 * cannot see having climbed teaches nothing.
 */
function ModeChoice({
  label,
  value,
  floor,
  hint,
  onChange,
}: {
  label: string
  value: ProtectionMode
  /** Nothing below this is selectable. */
  floor: ProtectionMode
  hint?: string
  onChange: (mode: ProtectionMode) => void
}) {
  const group = (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
      <Typography
        color="text.disabled"
        sx={{
          width: 62,
          flexShrink: 0,
          fontFamily: 'monospace',
          fontSize: 9.5,
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
        }}
      >
        {label}
      </Typography>
      <ToggleButtonGroup
        exclusive
        size="small"
        value={value}
        onChange={(_event, next: ProtectionMode | null) => {
          if (next) onChange(next)
        }}
        aria-label={label}
        sx={{ '& .MuiToggleButton-root': { px: 1.25, py: 0.4, fontSize: 11.5, textTransform: 'none' } }}
      >
        {PROTECTION_MODES.map((mode) => {
          const meta = modeMeta(mode)
          const allowed = modeAllowed(mode, floor)
          return (
            <ToggleButton
              key={mode}
              value={mode}
              disabled={!allowed}
              aria-label={meta.label}
              title={allowed ? meta.detail : `Sous le plancher : ${modeMeta(floor).label}.`}
            >
              {meta.label}
            </ToggleButton>
          )
        })}
      </ToggleButtonGroup>
    </Box>
  )
  return hint ? <Tooltip title={hint}>{group}</Tooltip> : group
}

/**
 * The gateway's encoded material, behind a door.
 *
 * Neither blob is secret and both stay fully editable — a reissued
 * certificate has to be pasteable, and that is why they were in the flow to
 * begin with. But two kilobytes of base64 sitting permanently between the
 * fields one actually edits is what made this screen read as a dump rather
 * than as a form. Here the flow states what matters — present or absent, and
 * the fingerprint just above — and the data itself is one click away.
 */
function EncodedData({
  caDer,
  pqCertificate,
  onChange,
}: {
  caDer: string
  pqCertificate: string
  onChange: <Key extends keyof KeyNegotiationSettings>(
    key: Key,
    value: KeyNegotiationSettings[Key],
  ) => void
}) {
  const [open, setOpen] = useState(false)
  const summary = [
    caDer.trim() ? 'CA TLS présente' : 'CA TLS absente',
    pqCertificate.trim() ? 'certificat PQ présent' : 'certificat PQ absent',
  ].join(' · ')
  const missing = !caDer.trim() || !pqCertificate.trim()

  return (
    <>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, minWidth: 0 }}>
        <Typography
          noWrap
          color={missing ? 'warning.main' : 'text.secondary'}
          sx={{ minWidth: 0, fontFamily: 'monospace', fontSize: 10.5 }}
        >
          {summary}
        </Typography>
        <Button
          size="small"
          variant="text"
          color="inherit"
          startIcon={<FileCode2 size={14} aria-hidden />}
          onClick={() => setOpen(true)}
          sx={{ ml: 'auto', flexShrink: 0, color: 'text.secondary', fontSize: 11 }}
        >
          Afficher les données encodées
        </Button>
      </Box>

      <Dialog
        open={open}
        onClose={() => setOpen(false)}
        maxWidth="sm"
        fullWidth
        aria-labelledby="encoded-data-title"
      >
        <DialogTitle id="encoded-data-title" sx={{ fontSize: 15 }}>
          Données encodées de la gateway
        </DialogTitle>
        <DialogContent sx={{ display: 'flex', flexDirection: 'column', gap: 2, pt: 1 }}>
          <DialogContentText sx={{ fontSize: 11.5, lineHeight: 1.55 }}>
            Rien ici n’est secret : ce matériel est public et sert à épingler la gateway. Le
            remplacer n’a de sens qu’après une réémission de certificat — le cœur revérifie
            l’épinglage et signale le bloc comme fautif si la valeur ne correspond plus.
          </DialogContentText>
          <Blob
            label="CA TLS de la gateway (DER base64)"
            value={caDer}
            onChange={(value) => onChange('gateway_ca_der', value)}
          />
          <Blob
            label="Certificat PQ épinglé (base64)"
            value={pqCertificate}
            onChange={(value) => onChange('gateway_pq_certificate', value)}
          />
        </DialogContent>
        <DialogActions>
          <Button variant="contained" onClick={() => setOpen(false)}>
            Fermer
          </Button>
        </DialogActions>
      </Dialog>
    </>
  )
}

/**
 * Long public value — a certificate, an authority.
 *
 * Shown in full over two lines rather than masked: none of this is secret,
 * and what one does with it is compare it, or paste a new one.
 */
function Blob({
  label,
  value,
  onChange,
}: {
  label: string
  value: string
  onChange: (value: string) => void
}) {
  return (
    <Box>
      <TextField
        fullWidth
        multiline
        minRows={3}
        maxRows={7}
        size="small"
        label={label}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        slotProps={{ htmlInput: { spellCheck: false, autoCorrect: 'off', autoCapitalize: 'off' } }}
        sx={{
          '& textarea': { fontFamily: 'monospace', fontSize: 10, lineHeight: 1.45, wordBreak: 'break-all' },
        }}
      />
      {/* Below rather than inside: an adornment floating over base64 that
          wraps at every character is a click one aims at and misses. */}
      {value.trim() !== '' && (
        <Box sx={{ display: 'flex', justifyContent: 'flex-end', mt: 0.25 }}>
          <CopyButton value={value} label={label.toLowerCase()} />
        </Box>
      )}
    </Box>
  )
}

/**
 * Received value, read-only: it is meant to be compared, not edited.
 *
 * Compared *elsewhere*, which is why `copyable` exists. A fingerprint one
 * must hold against what `heliosd init-key-negotiation` printed, shown
 * truncated and selectable only by dragging across monospace text, is a
 * verification nobody performs.
 */
function Detail({
  label,
  value,
  hint,
  copyable,
}: {
  label: string
  value: string
  hint?: string
  /** The value carries out of Orion — offer the clipboard. */
  copyable?: boolean
}) {
  const row = (
    <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 0.75, minWidth: 0 }}>
      <Typography
        color="text.disabled"
        sx={{
          flexShrink: 0,
          fontFamily: 'monospace',
          fontSize: 9.5,
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
        }}
      >
        {label}
      </Typography>
      <Typography
        noWrap
        color="text.secondary"
        sx={{ fontFamily: 'monospace', fontSize: 10.5, minWidth: 0 }}
      >
        {value}
      </Typography>
      {copyable && <CopyButton value={value} label={label} />}
    </Box>
  )
  return hint ? <Tooltip title={hint}>{row}</Tooltip> : row
}

/**
 * Contextual warning — it only appears at the moment the risk exists. A
 * permanent warning eventually stops being read.
 */
function Caution({ children }: { children: React.ReactNode }) {
  return (
    <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 0.75, mt: -0.5 }}>
      <AlertTriangle
        size={13}
        aria-hidden
        style={{ color: '#A16207', flexShrink: 0, marginTop: 2 }}
      />
      <Typography color="warning.main" sx={{ fontSize: 11, lineHeight: 1.5 }}>
        {children}
      </Typography>
    </Box>
  )
}

function Field({
  label,
  value,
  onChange,
  type = 'text',
  placeholder,
  error,
}: {
  label: string
  value: string
  onChange: (value: string) => void
  type?: 'text' | 'number'
  placeholder?: string
  /** Message from the core, `null` if the field is acceptable. */
  error?: string | null
}) {
  return (
    <TextField
      fullWidth
      size="small"
      label={label}
      type={type}
      placeholder={placeholder}
      value={value}
      error={Boolean(error)}
      helperText={error ?? undefined}
      onChange={(event) => onChange(event.target.value)}
      sx={{
        '& input': { fontFamily: 'monospace', fontSize: 12 },
        '& .MuiFormHelperText-root': { fontSize: 10.5, lineHeight: 1.4 },
      }}
    />
  )
}

/**
 * Derived value, not editable: modifying it would make no sense.
 *
 * The explanation goes through a tooltip rather than permanent text — it's
 * only useful once, at enrollment time.
 */
function ReadOnlyField({ label, value, hint }: { label: string; value: string; hint?: string }) {
  const field = (
    <TextField
      fullWidth
      size="small"
      label={label}
      value={value}
      slotProps={{
        htmlInput: { readOnly: true },
        input: {
          endAdornment: (
            <InputAdornment position="end">
              <CopyButton value={value} label={label.toLowerCase()} />
            </InputAdornment>
          ),
        },
      }}
      sx={{ '& input': { fontFamily: 'monospace', fontSize: 12, opacity: 0.72 } }}
    />
  )
  return hint ? <Tooltip title={hint}>{field}</Tooltip> : field
}

/** Secret field: masked by default, revealable without forcing blind entry. */
/**
 * States that a secret exists, without being able to carry it.
 *
 * # What this replaces, and why
 *
 * A `TextField` holding the WireGuard private key, with a button to reveal it.
 * That single component was the widest hole in ADR-006: the value had to be
 * serialised across the Tauri IPC to be displayed, parsed into a JavaScript
 * string nothing can wipe, and kept in a DOM node's `value` for the life of
 * the screen — where a screenshot, an accessibility client, or anything with
 * access to the WebView could read it. Sealing a key on disk and then showing
 * it in a browser engine protects the quiet half of its life.
 *
 * There is deliberately **no `value` prop**. The component cannot display a
 * secret because it is never given one, which is a stronger guarantee than a
 * component that merely chooses not to. What the user acts on is an *intent* —
 * generate, clear — carried out in Rust.
 */
function SecretState({
  label,
  present,
  presentLabel,
  absentLabel,
  action,
  error,
  hint,
}: {
  label: string
  present: boolean
  /** What to say when the secret is there. Never the secret. */
  presentLabel: string
  absentLabel: string
  action?: { label: string; onClick: () => void; disabled?: boolean }
  /** Message from the core, `null` if the field is acceptable. */
  error?: string | null
  hint?: string
}) {
  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75, minWidth: 0 }}>
        <Typography
          color="text.disabled"
          sx={{
            width: 110,
            flexShrink: 0,
            fontFamily: 'monospace',
            fontSize: 9.5,
            letterSpacing: '0.08em',
            textTransform: 'uppercase',
          }}
        >
          {label}
        </Typography>
        <Typography
          sx={{
            minWidth: 0,
            color: error ? 'error.main' : present ? 'text.primary' : 'text.secondary',
            fontFamily: 'monospace',
            fontSize: 11.5,
            overflowWrap: 'anywhere',
          }}
        >
          {present ? presentLabel : absentLabel}
        </Typography>
      </Box>
      {action && (
        <Button
          size="small"
          variant="text"
          onClick={action.onClick}
          disabled={action.disabled}
          sx={{ ml: '118px', mt: 0.25, fontSize: 11, textTransform: 'none' }}
        >
          {action.label}
        </Button>
      )}
      {(error || hint) && (
        <Typography
          color={error ? 'error' : 'text.secondary'}
          sx={{ mt: 0.25, ml: '118px', fontSize: 10.5, lineHeight: 1.4 }}
        >
          {error ?? hint}
        </Typography>
      )}
    </Box>
  )
}
