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
  Check,
  ChevronRight,
  KeyRound,
  FileCode2,
  Plus,
  RotateCcw,
  Save,
  Trash2,
  Upload,
} from 'lucide-react'
import * as api from '../api'
import { readProfileDocument } from '../profileDocument'
import { CopyButton } from '../components/CopyButton'
import { modeAllowed, modeLevel, modeMeta, PROTECTION_MODES } from '../components/state'
import {
  matchPreset,
  presetPrefixes,
  SPLIT_TUNNEL_PRESETS,
  type SplitTunnelPreset,
} from '../splitTunnel'
import { GUTTER, PINE } from '../theme'
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
 * # Two blocks, and the line between them is the protocol's
 *
 * «Tunnel WireGuard» holds what a plain WireGuard peer needs and nothing
 * else: a profile with that block filled in connects to any WireGuard
 * gateway. «Protection du tunnel» holds the other question entirely — what
 * stands between this profile and an unprotected first handshake — as one
 * ladder of three rungs: none, a static PSK, the v5 negotiation.
 *
 * That line is not a presentation choice, and neither is the ladder. The rung
 * **is** the profile type: the first two are `classic` and differ only by
 * whether a preshared key exists, the third is the one that writes a
 * negotiation block. `classic` is refused as a negotiable mode by
 * `aether::key_negotiation` (`ClassicNotNegotiable`) — a negotiated `classic`
 * is a tunnel with no preshared key, which the lower rungs already express —
 * so it is not a mode inside the block, it is the absence of the block.
 *
 * The ladder is also the whole of the choice: the negotiation rung writes
 * `ml_kem` and offers no mode of its own. A preshared key is the rung below,
 * and a negotiation that installs one instead of deriving a fresh one would
 * be the same decision written twice with nothing on screen to say which one
 * wins. `static_psk` remains an explicit v5 mode — the transaction runs and
 * proves possession with a session-bound HMAC commitment before the gateway
 * installs the configured key — so a block that already carries it is
 * displayed as what it is, with the key it needs and one gesture back to
 * ML-KEM, rather than relabelled.
 *
 * # No captions
 *
 * Fields state values. What a mode does, what a range captures, why a floor
 * refuses something — none of that is printed under the field: it belongs to
 * a tooltip when it is worth a hover, and to the ADR otherwise. A screen that
 * explains itself in permanent paragraphs stops being read, and the paragraph
 * that matters goes down with the rest.
 */

interface Props {
  config: ClientConfig
  pathImport: ClientProfile | null
  /**
   * Counter bumped each time the notification-area menu asks for an import.
   *
   * A counter and not a boolean: «Importer un profil…» twice in a row must
   * open the picker twice, and a flag already set changes nothing. `0` — the
   * value the screen mounts with — opens nothing, so reaching the profile
   * screen by the navigation rail stays quiet.
   */
  importRequest?: number
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
    // A brand-new profile has no key yet. The identity block above is where
    // one is obtained — generated or imported — and only its public half ever
    // reaches this object (ADR-006 §5).
    public_key: null,
    has_private_key: false,
    has_static_psk: false,
    profile_type: 'classic',
    address: null,
    allowed_ips: '0.0.0.0/0',
    persistent_keepalive: 25,
    heliosd_url: null,
    ssh_target: null,
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

/** Action waiting for the user's informed bare-volume decision. */
type VolumeWarningAction = 'import' | 'save'

/** How long a transient notice stays, in milliseconds. */
const NOTICE_MS = 3000

const MAX_IMPORT_BYTES = 64 * 1024

/**
 * How each split-tunnel choice is named on screen, and what it does.
 *
 * Named by what goes through the tunnel, never by the prefixes it writes:
 * those are in the field just below, and a row that repeated them would only
 * help whoever already knew the answer. The second line is the exception the
 * rest of this screen does not make — four exclusive choices with nothing but
 * a noun each is a list one has to try to read.
 */
const SPLIT_TUNNEL_CHOICES: Record<SplitTunnelPreset, { label: string; detail: string }> = {
  full: { label: 'Tout', detail: 'Internet et réseaux privés' },
  private: { label: 'Réseaux privés', detail: 'Uniquement les réseaux Helios' },
  gateway: { label: 'Helios seul', detail: 'Uniquement la passerelle' },
  custom: { label: 'Personnalisé', detail: 'Choisir les réseaux manuellement' },
}

/** The segments, in order. `custom` closes the bar: it is the way out of it. */
const SPLIT_TUNNEL_CHOICES_ORDER: SplitTunnelPreset[] = [...SPLIT_TUNNEL_PRESETS, 'custom']

/**
 * One segment of a choice bar.
 *
 * The screen has three of them now — split tunnelling, tunnel protection, the
 * negotiated mode and its floor — and they are the same gesture: pick exactly
 * one. Short labels, because a bar has to fit the form's column; what each
 * segment means is the line underneath it.
 */
const SEGMENT_BUTTON = {
  px: 1.25,
  py: 0.4,
  fontSize: 11.5,
  textTransform: 'none',
} as const

/**
 * What protects this tunnel, as one ladder instead of three places.
 *
 * The three rungs were spread across the screen: `classic` was a read-only
 * word under «Type de profil», its static PSK was a row under «Avancé», and
 * the negotiated modes lived in a block reached by an «Ajouter» button. Those
 * are not three subjects. They are one — *what stands between this profile and
 * an unprotected first handshake* — and a PSK filed under "advanced settings"
 * is the clearest symptom: it is not a setting, it is the entire protection of
 * a classic profile.
 *
 * What this deliberately does **not** do is flatten the negotiated
 * `static_psk` into the same rung as a plain WireGuard PSK. Both end up in the
 * same WireGuard slot, but one is copied by hand once and never rotates while
 * the other is the outcome of an authenticated v5 transaction — so the
 * negotiated one stays inside the negotiation block, under the mode that owns
 * it.
 */
type TunnelProtection = 'none' | 'static_psk' | 'negotiation'

/** The rungs, weakest first. The order is the ratchet's. */
const TUNNEL_PROTECTIONS: TunnelProtection[] = ['none', 'static_psk', 'negotiation']

const TUNNEL_PROTECTION_LABELS: Record<TunnelProtection, string> = {
  none: 'Aucune',
  static_psk: 'PSK statique',
  negotiation: 'Négociation Helios',
}

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
  importRequest = 0,
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
   * Public key of the pair staged in Rust, once one has been drawn or pasted.
   *
   * `null` means "no new key this session" — the profile keeps whatever it
   * already had. Holding the **public** half here is what lets the screen show
   * and copy it straight away: admission is out of band, so the user needs the
   * value before the profile can work, not after saving it.
   */
  const [stagedPublicKey, setStagedPublicKey] = useState<string | null>(null)
  /** The paste field is open. It holds a secret, so it is never left mounted. */
  const [pasting, setPasting] = useState(false)
  const [pasted, setPasted] = useState('')
  const [keyBusy, setKeyBusy] = useState(false)
  const [clearPsk, setClearPsk] = useState(false)
  /** A static PSK is waiting in Rust, entered during this edit. */
  const [stagedPsk, setStagedPsk] = useState(false)
  /** The PSK paste field is open. It holds a secret, so it is never left mounted. */
  const [pastingPsk, setPastingPsk] = useState(false)
  const [pastedPsk, setPastedPsk] = useState('')
  const [pskBusy, setPskBusy] = useState(false)
  const [issues, setIssues] = useState<Partial<ProfileIssues>>({})
  const [history, setHistory] = useState<ClientProfile[]>([])
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [volumeWarningAction, setVolumeWarningAction] =
    useState<VolumeWarningAction | null>(null)
  const [volumeWarningBusy, setVolumeWarningBusy] = useState(false)
  const [advanced, setAdvanced] = useState(false)
  const [support, setSupport] = useState<KeyNegotiationSupport | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)
  /** Focus target of «Personnalisé»: the list is typed, not chosen. */
  const allowedIpsInput = useRef<HTMLInputElement>(null)
  /**
   * «Personnalisé» was asked for, whatever the list currently says.
   *
   * The choice cannot be read back from the value alone. A hand-written
   * `100.64.0.1/32` is indistinguishable from the one «Helios seul» writes,
   * and a screen that re-derived the row from the text would close the field
   * the moment the user typed a list that happens to match a preset —
   * mid-edit, with the caret in it.
   */
  const [manualPrefixes, setManualPrefixes] = useState(false)
  /**
   * «PSK statique» was chosen, before any key has been entered.
   *
   * Same reason as {@link manualPrefixes}: the rung cannot be read back from
   * the profile alone. A classic profile with no PSK yet and a classic profile
   * that will never have one are the same object, and the difference is the
   * gesture just made — without it, picking the rung would light «Aucune» back
   * up and close the entry field under the user.
   */
  const [wantsStaticPsk, setWantsStaticPsk] = useState(false)
  /**
   * Bumped by «Personnalisé» so the caret lands in the field.
   *
   * The field does not exist while a preset is selected, so it cannot be
   * focused in the click handler: React has to mount it first.
   */
  const [caretRequest, setCaretRequest] = useState(0)

  useEffect(() => {
    if (!notice?.transient) return
    const id = setTimeout(() => setNotice(null), NOTICE_MS)
    return () => clearTimeout(id)
  }, [notice])

  useEffect(() => {
    if (caretRequest === 0) return
    allowedIpsInput.current?.focus()
  }, [caretRequest])

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
      ssh_target: profile.ssh_target,
      key_negotiation: profile.key_negotiation,
      useStagedKey: stagedPublicKey !== null,
      clearPresharedKey: clearPsk,
      useStagedPsk: stagedPsk,
    }),
    [clearPsk, stagedPsk, stagedPublicKey],
  )

  // A staged key wins over the stored one: it is what a save is about to
  // adopt, so it is what the user must copy and hand to the operator.
  const publicKey = stagedPublicKey ?? draft.public_key
  const hasKey = stagedPublicKey !== null || draft.has_private_key

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
    // staged key onto the next profile loaded would attach it to an identity
    // the operator never admitted.
    setStagedPublicKey(null)
    // Same reason: «Personnalisé» and «PSK statique» are gestures made on
    // *this* profile. The next one is read again, and what it actually holds
    // is what must light up.
    setManualPrefixes(false)
    setWantsStaticPsk(false)
    setPasting(false)
    setPasted('')
    void api.discardStagedKey().catch(() => {})
    setClearPsk(false)
    setStagedPsk(false)
    setPastingPsk(false)
    setPastedPsk('')
    void api.discardStagedPsk().catch(() => {})
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
    // The mode and the static PSK are one decision, not two. `orion-core`
    // states it as an equivalence — `static_psk` demands a PSK, every other
    // mode forbids one — so a screen that let them be set apart could only
    // produce profiles it would then have to mark invalid.
    //
    // Choosing a mode is therefore what disposes of the PSK: ML-KEM and
    // classic drop it, and nothing else does. It used to be dropped
    // unconditionally, which is why this screen could only ever take a PSK
    // away.
    if (key === 'mode') dropStagedPskFor(value as ProtectionMode)
    editNegotiation({ [key]: value } as Partial<KeyNegotiationSettings>)
  }

  /**
   * Aligns the static PSK on the mode — both ways.
   *
   * `clearPsk` is the intent sent to Rust for a PSK already stored; the staged
   * one is dropped where it lives, since it never reached this side.
   *
   * Coming *back* to `static_psk` withdraws the removal, because nothing has
   * been destroyed yet: the removal is a consequence of the mode, and a
   * consequence that outlived its cause would make the stored PSK vanish for a
   * mode the user tried and left. Only the save is irreversible.
   *
   * Classic is dropped as well as ML-KEM, though only ML-KEM was asked for:
   * `orion-core` refuses a profile PSK under *any* mode but `static_psk`, so
   * sparing it there would only move the refusal to the save, pointing at a
   * field the user had not touched.
   */
  const dropStagedPskFor = (mode: ProtectionMode) => {
    if (mode === 'static_psk') {
      setClearPsk(false)
      return
    }
    setClearPsk(true)
    if (stagedPsk) {
      setStagedPsk(false)
      void api.discardStagedPsk().catch(() => {})
    }
    setPastingPsk(false)
    setPastedPsk('')
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
    const mode = modeAllowed(settings.mode, floor) ? settings.mode : floor
    // A floor that drags the mode along drags the PSK's fate with it: raising
    // past `static_psk` is one of the ways a profile stops being allowed to
    // hold one.
    dropStagedPskFor(mode)
    editNegotiation({ minimum_mode: floor, ...(mode === settings.mode ? {} : { mode }) })
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
    // Always ML-KEM. A block created over an existing static PSK used to open
    // on `static_psk` so as not to discard the key silently; now the two are
    // separate rungs of one bar, so moving to this one *is* the choice to
    // stop using that key, and `chooseProtection` disposes of it explicitly.
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

  const persistDraft = async () => {
    try {
      await onSave(toDraft(draft))
      setDirty(false)
      // The key has become the profile's: the slot is empty on the Rust side
      // too, and keeping it here would re-send it at the next save.
      setStagedPublicKey(null)
      setPasting(false)
      setPasted('')
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

  /**
   * Checks the measured volume posture before an action can persist a key.
   *
   * A missing BitLocker posture is not silently accepted: the warning is the
   * gesture that turns the strict refusal into the existing, visible local
   * waiver. Once chosen, the backend persists it and subsequent actions do not
   * nag while the posture panel continues to report the downgrade.
   */
  const volumeAllows = async (action: VolumeWarningAction): Promise<boolean> => {
    try {
      const posture = await api.vaultPosture()
      if (posture.volumeProtected || posture.unencryptedVolumeWaived) return true
      setVolumeWarningAction(action)
      return false
    } catch (cause) {
      setNotice({
        tone: 'error',
        message: `Posture du volume indéterminable : ${String(cause)}`,
      })
      return false
    }
  }

  const save = async () => {
    if (await volumeAllows('save')) await persistDraft()
  }

  const requestImport = async () => {
    if (await volumeAllows('import')) fileInput.current?.click()
  }

  const acceptUnencryptedVolume = async () => {
    const action = volumeWarningAction
    if (!action) return
    setVolumeWarningBusy(true)
    try {
      await api.allowUnencryptedVolume()
      setVolumeWarningAction(null)
      setNotice({
        tone: 'success',
        message:
          'Volume non chiffré accepté : le coffre applicatif reste actif, mais la protection au repos est incomplète.',
      })
      if (action === 'import') fileInput.current?.click()
      else await persistDraft()
    } catch (cause) {
      setNotice({
        tone: 'error',
        message: `Impossible d’enregistrer l’autorisation locale : ${String(cause)}`,
      })
    } finally {
      setVolumeWarningBusy(false)
    }
  }

  // The tray's «Importer un profil à partir d'un fichier…» ends here: the
  // picker belongs to this screen, and opening it from the shell would mean a
  // second one. `0` is the mounted value and opens nothing. It follows the
  // same volume warning as the visible Import button.
  useEffect(() => {
    if (importRequest > 0) void requestImport()
    // A counter is the event. The callback intentionally follows the current
    // measured posture on each event rather than becoming another trigger.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [importRequest])

  /** Draws a pair in Rust and shows the public half at once. */
  const generateKey = async () => {
    setKeyBusy(true)
    try {
      setStagedPublicKey(await api.generatePrivateKey())
      setPasting(false)
      setPasted('')
      setDirty(true)
      setNotice({
        tone: 'success',
        message:
          'Clé générée. Transmettre la clé publique à l’opérateur, puis enregistrer.',
      })
    } catch (cause) {
      setNotice({ tone: 'error', message: `Génération impossible : ${String(cause)}` })
    } finally {
      setKeyBusy(false)
    }
  }

  /**
   * Hands a pasted key to Rust, which validates it and answers its public half.
   *
   * The input is cleared on both outcomes. It is the only field in this screen
   * that ever holds a secret, and it must not outlive the gesture.
   */
  const adoptKey = async () => {
    setKeyBusy(true)
    try {
      const publicHalf = await api.adoptPrivateKey(pasted)
      setPasted('')
      setPasting(false)
      setStagedPublicKey(publicHalf)
      setDirty(true)
      setNotice({ tone: 'success', message: 'Clé privée importée.' })
    } catch (cause) {
      setPasted('')
      setNotice({ tone: 'error', message: String(cause) })
    } finally {
      setKeyBusy(false)
    }
  }

  /**
   * Hands a typed PSK to Rust.
   *
   * No mode juggling here any more, and that is the point of the split: the
   * field only exists where a PSK is legal — under `static_psk`, or on a
   * profile with no negotiation block at all. It used to sit among the
   * WireGuard settings whatever the mode said, so entering one had to *move*
   * the mode to avoid a contradiction the core would refuse at save time,
   * naming a field the user had not touched.
   *
   * The input is cleared on both outcomes, like the private-key field: it is
   * the only other place in this screen that ever holds a secret.
   */
  const adoptPsk = async () => {
    setPskBusy(true)
    try {
      await api.adoptPresharedKey(pastedPsk)
      setPastedPsk('')
      setPastingPsk(false)
      setStagedPsk(true)
      setClearPsk(false)
      setDirty(true)
      setNotice({ tone: 'success', message: 'PSK statique enregistré.' })
    } catch (cause) {
      setPastedPsk('')
      setNotice({ tone: 'error', message: String(cause) })
    } finally {
      setPskBusy(false)
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

  /**
   * Makes one saved profile the profile Orion loads and connects with.
   *
   * Selection is persisted by the Rust shell before the editor follows it.
   * If persistence fails, keeping the previous draft avoids showing a profile
   * as loaded while the backend will still connect another one.
   */
  const selectProfile = async (profile: ClientProfile) => {
    if (profile.name === draft.name && profile.name === config.selected) return
    try {
      await onSelect(profile.name)
      loadDraft(profile)
      setDirty(false)
      setNotice(null)
    } catch {
      // The global error surface owns the backend failure. Most importantly,
      // do not make the editor claim the rejected selection was adopted.
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
      // What the file said and Orion does not apply. Appended to whatever the
      // import concluded rather than replacing it: a `DNS` line that will not
      // be honoured does not stop a profile from being imported, and it must
      // not hide a missing private key either.
      const dropped = imported.notices.length > 0 ? ` ${imported.notices.join(' ')}` : ''
      const existing = config.profiles.find((candidate) => candidate.name === profile.name)

      loadDraft(profile)
      setDirty(true)
      // A missing private key outranks the rest: the profile is on screen but
      // WireGuard has nothing to sign with, and the message says which key is
      // expected — that is what lets the user act.
      if (imported.private_key_missing) {
        setNotice({ tone: 'error', message: `${imported.private_key_missing}${dropped}` })
      }
      // A partial document is loaded, not refused: the gap is named so the
      // user can close it in the form they are already looking at.
      else if (imported.incomplete) {
        setNotice({
          tone: 'error',
          message: `« ${profile.name} » chargé, à compléter : ${imported.incomplete}${dropped}`,
        })
      }
      // The identity failing to seal outranks the profile loading fine: the
      // profile is visible on screen, whereas an unsealed identity only
      // shows up much later, as a connection that fails before WireGuard.
      else if (imported.identity_error) {
        setNotice({
          tone: 'error',
          message: `« ${profile.name} » chargé, mais l’identité n’a pas pu être scellée : ${imported.identity_error}${dropped}`,
        })
      } else {
        const sealed = imported.identity_sealed
          ? ' Identité scellée dans le stockage protégé : le fichier peut être détruit.'
          : ''
        setNotice({
          tone: 'success',
          message: existing
            ? `« ${profile.name} » chargé. Enregistrer remplacera le profil existant.${sealed}${dropped}`
            : `« ${profile.name} » chargé. Vérifiez-le puis enregistrez-le.${sealed}${dropped}`,
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
  const storedKind = config.profiles.find((profile) => profile.name === draft.name)?.profile_type
  const draftKind: ClientProfile['profile_type'] = draft.key_negotiation
    ? 'helios_key_negotiation'
    : 'classic'
  const kindChanged = storedKind !== undefined && storedKind !== draftKind
  // A PSK entered during this edit counts as present: it is what the save is
  // about to store, and showing "aucun" next to a value the user just typed
  // would read as the entry having been refused.
  const staticPsk = (draft.has_static_psk && !clearPsk) || stagedPsk
  /**
   * Which rung the profile is on.
   *
   * Read from the profile, except for the one state it cannot express: a
   * «PSK statique» asked for and not yet entered.
   */
  const protection: TunnelProtection = draft.key_negotiation
    ? 'negotiation'
    : staticPsk || wantsStaticPsk
      ? 'static_psk'
      : 'none'
  /**
   * Why a rung cannot be reached, or `undefined` if it can.
   *
   * The refusals are the ones that already existed, said where the gesture is
   * made instead of after it: a stored profile does not change type — that is
   * `kindChanged`, which used to be an alert raised at save time — and a
   * negotiation block is not removed once something has been negotiated, which
   * is the anti-downgrade ratchet of ADR-001 (`ClientConfig::upsert` refuses
   * to lower a known floor, including by deleting the block).
   */
  const protectionRefusal = (rung: TunnelProtection): string | undefined => {
    if (rung === protection) return undefined
    const renameFirst =
      'Un profil enregistré ne change pas de type. Renommez-le pour en créer un autre.'
    if (rung === 'negotiation') return exists ? renameFirst : undefined
    if (protection !== 'negotiation') return undefined
    if (exists) return renameFirst
    return floorBaseline && modeLevel(floorBaseline) > 0
      ? `Plancher « ${modeMeta(floorBaseline).label} » : la négociation ne se retire plus.`
      : undefined
  }

  /**
   * Moves the profile to another rung.
   *
   * Everything it does already existed behind a button or a fold; what it adds
   * is that leaving a rung disposes of what belonged to it. Dropping to
   * «Aucune» clears the PSK for the same reason `dropStagedPskFor` does under
   * a mode that forbids one: `orion-core` refuses a profile holding a PSK
   * nothing uses, and leaving it would move the refusal to the save, pointing
   * at a field the user never opened.
   */
  const chooseProtection = (rung: TunnelProtection) => {
    if (rung === protection || protectionRefusal(rung)) return
    if (rung === 'negotiation') {
      setWantsStaticPsk(false)
      // The rung derives a fresh key on every connection, so it stores none.
      // `orion-core` refuses a profile holding a PSK no mode uses, and
      // leaving it would move the refusal to the save.
      dropStagedPskFor('ml_kem')
      toggleNegotiation(true)
      return
    }
    // The block goes first: on the way down from a negotiated `static_psk`,
    // the key stays and simply becomes what it is without a block — a plain
    // WireGuard preshared key.
    if (draft.key_negotiation) toggleNegotiation(false)
    if (rung === 'static_psk') {
      setWantsStaticPsk(true)
      setClearPsk(false)
      // The entry field is what the rung shows while there is no key, so
      // there is nothing to open here.
      setPastingPsk(false)
      setPastedPsk('')
      return
    }
    setWantsStaticPsk(false)
    dropStagedPskFor('classic')
  }

  const invalid = kindChanged || Object.values(issues).some(Boolean)
  // Read from the value, except when the user has asked to write it himself:
  // a preset that stayed lit after the list was edited would describe a
  // profile that no longer exists, and a list matching no preset is by
  // definition hand-written whether or not the row was ever clicked.
  const detectedPreset = matchPreset(draft.allowed_ips, draft)
  const splitTunnel: SplitTunnelPreset =
    manualPrefixes || detectedPreset === 'custom' ? 'custom' : detectedPreset
  // The "Advanced" collapse must flag what it hides: otherwise a faulty field
  // would stay invisible until someone thinks to open it. A narrowed range is
  // *not* one of those: split tunnelling is a decision, not a defect.
  const advancedFlagged = Boolean(
    issues.allowed_ips || issues.persistent_keepalive || issues.ssh_target,
  )

  /**
   * The static PSK, wherever it belongs on this profile.
   *
   * One component, two homes. Without a negotiation block the PSK is a plain
   * WireGuard setting and sits under «Avancé»; with one it is the material of
   * the `static_psk` mode and sits under that mode. Rendering it twice, or
   * keeping it in the WireGuard block while a mode governs it, is what made
   * the two halves of this screen impossible to tell apart.
   */
  /**
   * The static PSK, as the one thing its rung is about.
   *
   * Same inbound-only rule as the private key (ADR-006 §5): the value travels
   * *towards* Rust once, at an explicit gesture, and no path returns one.
   *
   * There is no «aucun» state line any more, and no «Définir un PSK
   * statique» link. On the rung with no key yet there is exactly one thing to
   * do, so the field to do it with is what the rung shows — a row announcing
   * an absence above a link that opens the field to fix it was three steps
   * for one. What the state line is still worth saying is the opposite case:
   * a key exists, cannot be shown, and the only useful facts about it are
   * that it is there and what can be done to it.
   */
  const pskEntry = !staticPsk || pastingPsk
  const pskField = (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.75 }}>
      {!pskEntry && (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
          <Check size={14} aria-hidden style={{ color: PINE, flexShrink: 0 }} />
          <Typography sx={{ fontSize: 11.5 }}>
            {stagedPsk ? 'Nouveau PSK — à enregistrer' : 'Scellé dans le coffre'}
          </Typography>
          <Button
            size="small"
            variant="text"
            onClick={() => setPastingPsk(true)}
            disabled={pskBusy}
            sx={{ ml: 'auto', fontSize: 11, textTransform: 'none' }}
          >
            Remplacer
          </Button>
          <Button
            size="small"
            variant="text"
            color="inherit"
            onClick={() => {
              setClearPsk(true)
              if (stagedPsk) {
                setStagedPsk(false)
                void api.discardStagedPsk().catch(() => {})
              }
              setWantsStaticPsk(false)
              setDirty(true)
            }}
            disabled={clearPsk && !stagedPsk}
            sx={{ fontSize: 11, textTransform: 'none', color: 'text.secondary' }}
          >
            Retirer
          </Button>
        </Box>
      )}
      {pskEntry && (
        <Box sx={{ display: 'flex', gap: 1, alignItems: 'flex-start' }}>
          <TextField
            fullWidth
            size="small"
            type="password"
            autoComplete="off"
            spellCheck={false}
            label="PSK WireGuard (base64)"
            value={pastedPsk}
            onChange={(event) => setPastedPsk(event.target.value)}
            sx={{ '& input': { fontFamily: 'monospace', fontSize: 12 } }}
          />
          <Button
            size="small"
            variant="contained"
            disableElevation
            disabled={pskBusy || pastedPsk.trim().length === 0}
            onClick={adoptPsk}
            sx={{ mt: 0.5, fontSize: 11.5, textTransform: 'none', flexShrink: 0 }}
          >
            Valider
          </Button>
          {/* Only while replacing: on a rung with no key there is nothing to
              go back to, and leaving is done on the bar above. Named after
              what it abandons, because the footer already has an «Annuler»
              that abandons the whole edit. */}
          {staticPsk && (
            <Button
              size="small"
              variant="text"
              color="inherit"
              onClick={() => {
                setPastingPsk(false)
                setPastedPsk('')
              }}
              sx={{ mt: 0.5, fontSize: 11.5, textTransform: 'none', flexShrink: 0, color: 'text.secondary' }}
            >
              Garder le PSK
            </Button>
          )}
        </Box>
      )}
      {issues.preshared_key && (
        <Typography color="error" sx={{ fontSize: 10.5, lineHeight: 1.4 }}>
          {issues.preshared_key}
        </Typography>
      )}
    </Box>
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
            Profils à charger
          </Typography>

          <Box
            component="ul"
            aria-label="Choisir le profil chargé"
            sx={{ m: 0, p: 0, listStyle: 'none', overflow: 'hidden' }}
          >
            {config.profiles.map((profile) => {
              const active = profile.name === draft.name
              return (
                <Box component="li" key={profile.name}>
                  <ButtonBase
                    onClick={() => void selectProfile(profile)}
                    aria-label={profile.name}
                    aria-current={active ? 'true' : undefined}
                    sx={{
                      position: 'relative',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: 0.75,
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
                        minWidth: 0,
                        flex: 1,
                      }}
                    >
                      {profile.name}
                    </Typography>
                    {active && (
                      <Box
                        aria-hidden
                        sx={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 0.35,
                          color: 'primary.main',
                          flexShrink: 0,
                        }}
                      >
                        <Check size={12} />
                        <Typography sx={{ fontSize: 9.5, fontWeight: 700 }}>chargé</Typography>
                      </Box>
                    )}
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
              // `.orion` d'abord : c'est l'extension que produit
              // `helios enroll` et celle qu'Orion associe au double-clic.
              // Son absence ici la grisait dans le sélecteur, ce qui donnait à
              // penser que le format n'était pas supporté — alors que le
              // parseur l'accepte depuis toujours (il reconnaît le JSON à son
              // premier caractère, pas au suffixe). `.orionprofile` reste
              // proposée : c'est le suffixe distribué jusqu'en août 2026, et
              // les documents déjà écrits survivent au client qui les lit.
              accept=".orion,.orionprofile,.json,.conf,application/json,text/plain"
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
              onClick={() => void requestImport()}
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

          {/* ── Identity ─────────────────────────────────────────────────
              Its own block, full width, above the rest. It used to be two
              rows lost inside the two-column grid — a state line that read
              like a broken label, and a public key showing a dash because no
              key existed yet. Both belong to one act: obtain an identity, then
              hand its public half to the operator. Admission is out of band
              (ADR-004 §6), so this is the step everything else waits on. */}
          <Box
            sx={{
              mb: 1.5,
              p: 1.5,
              border: 1,
              borderColor: 'divider',
              borderRadius: 1,
              display: 'flex',
              flexDirection: 'column',
              gap: 1.25,
            }}
          >
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography sx={{ fontSize: 12, fontWeight: 700 }}>
                Identité de ce poste
              </Typography>
              <Typography
                sx={{
                  fontSize: 10.5,
                  fontFamily: 'monospace',
                  color: hasKey ? 'success.main' : 'text.disabled',
                }}
              >
                {stagedPublicKey
                  ? 'nouvelle clé — à enregistrer'
                  : hasKey
                    ? 'clé scellée dans le coffre'
                    : 'aucune clé'}
              </Typography>
            </Box>

            <ReadOnlyField
              label="Votre clé publique"
              value={publicKey ?? '—'}
              hint="À transmettre à l’opérateur."
            />

            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, alignItems: 'center' }}>
              <Button
                size="small"
                variant="outlined"
                color="inherit"
                disabled={keyBusy}
                onClick={generateKey}
                startIcon={<KeyRound size={14} aria-hidden />}
                sx={{ fontSize: 11.5, textTransform: 'none' }}
              >
                {hasKey ? 'Générer une nouvelle clé' : 'Générer une clé'}
              </Button>
              <Button
                size="small"
                variant="text"
                color="inherit"
                disabled={keyBusy}
                onClick={() => setPasting((open) => !open)}
                sx={{ fontSize: 11.5, textTransform: 'none', color: 'text.secondary' }}
              >
                {pasting ? 'Annuler l’import' : 'Importer une clé privée'}
              </Button>
              {issues.private_key && (
                <Typography color="error" sx={{ fontSize: 10.5 }}>
                  {issues.private_key}
                </Typography>
              )}
            </Box>

            {/* Mounted only while it is being used. This is the single field in
                the screen that carries a secret, and it travels **inbound**
                only: Rust validates it, answers with the public half, and the
                input is cleared on both outcomes (ADR-006 §5). */}
            {pasting && (
              <Box sx={{ display: 'flex', gap: 1, alignItems: 'flex-start' }}>
                <TextField
                  fullWidth
                  size="small"
                  type="password"
                  autoComplete="off"
                  spellCheck={false}
                  label="Clé privée WireGuard (base64)"
                  value={pasted}
                  onChange={(event) => setPasted(event.target.value)}
                  sx={{ '& input': { fontFamily: 'monospace', fontSize: 12 } }}
                />
                <Button
                  size="small"
                  variant="contained"
                  disableElevation
                  disabled={keyBusy || pasted.trim().length === 0}
                  onClick={adoptKey}
                  sx={{ mt: 0.5, fontSize: 11.5, textTransform: 'none', flexShrink: 0 }}
                >
                  Valider
                </Button>
              </Box>
            )}
          </Box>

          {/* ── Tunnel WireGuard ─────────────────────────────────────────
              The strict minimum, and nothing about negotiation. A profile
              with this block filled in and no negotiation connects to any
              WireGuard gateway — which is what «classique» means here. */}
          <Typography component="h3" sx={{ mb: 1, fontSize: 12.5, fontWeight: 650 }}>
            Tunnel WireGuard
          </Typography>
          {/* Two columns of two, and everything optional underneath.
              «Avancé» used to hang off the right column, which made that
              column as tall as the whole block the moment it was opened while
              the left one stopped at three fields. What is folded away is not
              a property of the right-hand half of the form — it belongs under
              both. */}
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
            </Box>

            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
              <Field
                label="Adresse virtuelle"
                error={issues.address}
                placeholder="assignée à l’enrôlement"
                value={draft.address ?? ''}
                onChange={(value) => set('address', value || null)}
              />
              <Field
                label="Clé publique gateway"
                error={issues.peer_public_key}
                value={draft.peer_public_key}
                onChange={(value) => set('peer_public_key', value)}
              />
            </Box>
          </Box>

          <ButtonBase
            onClick={() => setAdvanced((open) => !open)}
            aria-expanded={advanced}
            sx={{
              display: 'flex',
              justifyContent: 'flex-start',
              gap: 0.5,
              mt: 1.5,
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
            {advancedFlagged && <AlertTriangle size={13} aria-hidden style={{ color: '#A16207' }} />}
          </ButtonBase>

          <Collapse in={advanced} unmountOnExit>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5, pt: 0.5 }}>
              {/* Three routine decisions and the field they write into.
                  The field stays the authority — «Personnalisé» is not a
                  fourth value, it is what the three fail to recognise —
                  because the lists a real deployment needs are not
                  guessable from the client side. No caution for a narrowed
                  range: routing one subnet and leaving the rest alone is
                  what most corporate profiles do on purpose. */}
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.75 }}>
                <Typography
                  id="split-tunnel-label"
                  color="text.secondary"
                  sx={{ fontSize: 11.5, fontWeight: 600 }}
                >
                  Que faire passer par Helios ?
                </Typography>
                <ToggleButtonGroup
                  exclusive
                  size="small"
                  value={splitTunnel}
                  aria-labelledby="split-tunnel-label"
                  onChange={(_event, next: SplitTunnelPreset | null) => {
                    // `null` is the selected segment being pressed again:
                    // there is no "no choice" here, the field always holds
                    // one list. `custom` is handled on the segment itself,
                    // because pressing it while it is already selected has
                    // to keep working — that is when it is most useful.
                    if (next === null || next === 'custom') return
                    setManualPrefixes(false)
                    set('allowed_ips', presetPrefixes(next, draft))
                  }}
                  sx={{ '& .MuiToggleButton-root': SEGMENT_BUTTON }}
                >
                  {SPLIT_TUNNEL_CHOICES_ORDER.map((preset) => (
                    <ToggleButton
                      key={preset}
                      value={preset}
                      // The prefixes it would write, before it writes
                      // them — the one thing the bar deliberately does not
                      // print.
                      title={preset === 'custom' ? undefined : presetPrefixes(preset, draft)}
                      // «Personnalisé» writes nothing: it opens the field
                      // on the list the preset left behind, which is the
                      // starting point a narrowed range is edited from.
                      // Handled on the segment rather than on the group so
                      // that pressing it while it is already selected
                      // still hands over the caret.
                      onClick={
                        preset === 'custom'
                          ? () => {
                              setManualPrefixes(true)
                              setCaretRequest((request) => request + 1)
                            }
                          : undefined
                      }
                    >
                      {SPLIT_TUNNEL_CHOICES[preset].label}
                    </ToggleButton>
                  ))}
                </ToggleButtonGroup>
                {/* One line, for the chosen segment only. Four captions
                    printed at once is a paragraph, and a paragraph under a
                    control is what stops being read. */}
                <Typography color="text.secondary" sx={{ fontSize: 10.5, lineHeight: 1.5 }}>
                  {SPLIT_TUNNEL_CHOICES[splitTunnel].detail}
                </Typography>
                {/* A preset owns the list it wrote, so the field states it
                    rather than taking it: an input accepting text that
                    would flip the segment above it is the contradiction
                    this bar was added to remove. The value stays on screen
                    because a choice named «Réseaux privés» has to be
                    checkable against the prefixes it stands for.

                    The example lives in the placeholder, not under the
                    field: it is a value, and a value belongs where the
                    value goes. */}
                {splitTunnel === 'custom' ? (
                  <Field
                    label="Trafic via le tunnel"
                    error={issues.allowed_ips}
                    placeholder="0.0.0.0/0  ·  100.64.0.1/32, 192.168.1.0/24"
                    value={draft.allowed_ips}
                    inputRef={allowedIpsInput}
                    onChange={(value) => set('allowed_ips', value)}
                  />
                ) : (
                  <ReadOnlyField label="Trafic via le tunnel" value={draft.allowed_ips} />
                )}
                {/* The exception this screen makes to its own rule: the
                    field is the one place where «réseaux» has to be read
                    as prefixes, and the bar above no longer spells it. It
                    gives way to the error the moment there is one. */}
                {!issues.allowed_ips && (
                  <Typography color="text.disabled" sx={{ fontSize: 10.5, lineHeight: 1.5 }}>
                    Liste des réseaux qui seront acheminés dans le tunnel.
                  </Typography>
                )}
              </Box>
              {/* Two short fields side by side rather than one above the
                  other: neither a keepalive nor a login is worth the width of
                  the panel, and stacking them would push the PSK below the
                  fold for nothing. */}
              <Box
                sx={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(2, minmax(0, 1fr))',
                  gap: 1.5,
                  alignItems: 'start',
                }}
              >
                <Field
                  label="Keepalive (s)"
                  error={issues.persistent_keepalive}
                  type="number"
                  value={String(draft.persistent_keepalive)}
                  onChange={(value) => set('persistent_keepalive', Number(value) || 0)}
                />
                <Field
                  label="Destination SSH"
                  error={issues.ssh_target}
                  placeholder="utilisateur@100.64.0.1"
                  value={draft.ssh_target ?? ''}
                  onChange={(value) => set('ssh_target', value || null)}
                />
              </Box>
            </Box>
          </Collapse>

          <Divider sx={{ my: 1.75 }} />

          {/* ── Protection du tunnel ─────────────────────────────────────
              One ladder where there used to be a read-only word, a folded
              row and a button. The rung *is* the profile type: «Aucune» and
              «PSK statique» are both `classic`, and only the third one writes
              a negotiation block. */}
          <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 1.5, mb: 1 }}>
            <Typography
              component="h3"
              id="tunnel-protection-label"
              sx={{ fontSize: 12.5, fontWeight: 650 }}
            >
              Protection du tunnel
            </Typography>
            <Typography color="text.secondary" sx={{ fontFamily: 'monospace', fontSize: 11 }}>
              {draftKind}
            </Typography>
          </Box>

          <ToggleButtonGroup
            exclusive
            size="small"
            value={protection}
            aria-labelledby="tunnel-protection-label"
            onChange={(_event, next: TunnelProtection | null) => {
              if (next) chooseProtection(next)
            }}
            sx={{ '& .MuiToggleButton-root': SEGMENT_BUTTON }}
          >
            {TUNNEL_PROTECTIONS.map((rung) => {
              const refusal = protectionRefusal(rung)
              return (
                <ToggleButton
                  key={rung}
                  value={rung}
                  disabled={refusal !== undefined}
                  // Only the refusal is worth a tooltip: it is the one thing a
                  // greyed-out segment cannot say by itself.
                  title={refusal}
                >
                  {TUNNEL_PROTECTION_LABELS[rung]}
                </ToggleButton>
              )
            })}
          </ToggleButtonGroup>
          {kindChanged && (
            <Alert severity="error" role="alert" sx={{ mt: 1.5 }}>
              {`Le type enregistré « ${storedKind} » ne peut pas devenir « ${draftKind} » sous le même identifiant. Rétablissez le type initial ou choisissez un nouveau nom.`}
            </Alert>
          )}

          {/* What the chosen rung is made of, and nothing about the others. */}
          {protection === 'static_psk' && <Box sx={{ mt: 1.5 }}>{pskField}</Box>}

          {draft.key_negotiation && (
            <Box sx={{ mt: 1.5 }}>
              <KeyNegotiation
                settings={draft.key_negotiation}
                floorBaseline={floorBaseline}
                issue={issues.key_negotiation}
                support={support}
                pskField={pskField}
                onChange={setNegotiation}
                onRaiseFloor={raiseFloor}
              />
            </Box>
          )}

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

      <Dialog
        open={volumeWarningAction !== null}
        onClose={() => {
          if (!volumeWarningBusy) setVolumeWarningAction(null)
        }}
        aria-labelledby="unencrypted-volume-title"
        maxWidth="sm"
        fullWidth
      >
        <DialogTitle
          id="unencrypted-volume-title"
          sx={{ display: 'flex', alignItems: 'center', gap: 1 }}
        >
          <AlertTriangle size={20} aria-hidden />
          Continuer sans BitLocker ?
        </DialogTitle>
        <DialogContent>
          <DialogContentText component="div">
            Le volume qui stocke les profils n’est pas chiffré par BitLocker : la protection
            de vos secrets au repos restera incomplète.
            <Box component="span" sx={{ display: 'block', mt: 1.5 }}>
              En continuant, vous acceptez ce niveau de protection pour ce poste.
            </Box>
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button
            color="inherit"
            disabled={volumeWarningBusy}
            onClick={() => setVolumeWarningAction(null)}
          >
            Annuler
          </Button>
          <Button
            color="warning"
            variant="contained"
            disabled={volumeWarningBusy}
            onClick={() => void acceptUnencryptedVolume()}
          >
            {volumeWarningBusy ? 'Autorisation…' : 'Continuer avec une protection incomplète'}
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
 * The block is normally **received**: `helios enroll` fills it, and
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
/**
 * The negotiation rung's own settings.
 *
 * It no longer decides whether it exists: «Protection du tunnel» above owns
 * that, and this component is only rendered on the rung that has a block. The
 * «Ajouter»/«Retirer» pair it used to carry said the same thing as a segment
 * of that bar, one screenful lower and in another grammar.
 */
function KeyNegotiation({
  settings,
  floorBaseline,
  issue,
  support,
  pskField,
  onChange,
  onRaiseFloor,
}: {
  settings: KeyNegotiationSettings
  /** Floor the profile was loaded with: the screen never goes under it. */
  floorBaseline: ProtectionMode | null
  issue?: string | null
  support: KeyNegotiationSupport | null
  /** The static PSK row, for a loaded block that still carries that mode. */
  pskField: React.ReactNode
  onChange: <Key extends keyof KeyNegotiationSettings>(
    key: Key,
    value: KeyNegotiationSettings[Key],
  ) => void
  onRaiseFloor: (floor: ProtectionMode) => void
}) {
  const unusable = support && !support.identity_store
  // Anything but ML-KEM is a block this screen no longer composes.
  //
  // The rung is the choice: a preshared key is «PSK statique» one bar above,
  // and a negotiation that installs one instead of deriving a fresh one is
  // the same decision written twice, in two places, with nothing on screen
  // to say which one wins. So the mode row is gone and this rung writes
  // `ml_kem`.
  //
  // It cannot simply *assume* `ml_kem`, though. `static_psk` remains an
  // explicit v5 mode — the transaction still runs and proves possession with
  // an HMAC commitment bound to the session before the gateway installs the
  // configured key (NEGOCIATION-DE-CLE-V5 §9.1) — so a document produced by
  // `helios enroll` may legitimately carry it, and `classic` may come
  // from a document older than the rule that refuses it. Displaying either
  // one as ML-KEM would be a lie about what the profile does, and hiding the
  // PSK that `static_psk` requires would leave a profile invalid with no
  // field to look at. Both are therefore shown as what they are, with the one
  // gesture that brings the profile back to what this screen composes.
  const legacyMode = settings.mode !== 'ml_kem'

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
      {legacyMode && (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.75 }}>
          <Caution>
            {settings.mode === 'classic'
              ? 'Ce profil négocie en mode « classique », que la gateway refuse par son nom : la connexion échouera.'
              : 'Ce profil négocie un PSK statique. Orion ne compose plus ce mode : une clé partagée se choisit au cran « PSK statique » ci-dessus.'}
          </Caution>
          <Button
            size="small"
            variant="outlined"
            color="inherit"
            onClick={() => onChange('mode', 'ml_kem')}
            disabled={!modeAllowed('ml_kem', settings.minimum_mode)}
            sx={{ alignSelf: 'flex-start', fontSize: 11.5, textTransform: 'none' }}
          >
            Passer en ML-KEM
          </Button>
        </Box>
      )}

      {/* Only for a block that already carried one: the rung this screen
          composes derives its key and stores nothing. */}
      {settings.mode === 'static_psk' && pskField}

      <ModeChoice
        label="Plancher anti-downgrade"
        modes={PROTECTION_MODES}
        value={settings.minimum_mode}
        floor={floorBaseline ?? 'classic'}
        hint="Niveau minimum exigé. Ne redescend jamais."
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
      </Box>

      <EncodedData
        caDer={settings.gateway_ca_der}
        pqCertificate={settings.gateway_pq_certificate}
        onChange={onChange}
      />

      {issue && (
        <Alert severity="error" variant="outlined" sx={{ py: 0, fontSize: 11 }}>
          {issue}
        </Alert>
      )}

      {unusable && (
        <Caution>
          Aucun stockage protégé d’identité sur ce poste : la connexion échouera.
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
 *
 * Title above, segments below, same shape as «Protection du tunnel» and «Que
 * faire passer par Helios ?». It used to be a 62-pixel uppercase label to the
 * left of the bar, which read as a third grammar for the same gesture on a
 * screen that now makes that gesture three times.
 */
function ModeChoice({
  label,
  modes,
  value,
  floor,
  hint,
  onChange,
}: {
  label: string
  /** Which modes this row offers. The mode row omits `classic`. */
  modes: ProtectionMode[]
  value: ProtectionMode
  /** Nothing below this is selectable. */
  floor: ProtectionMode
  /** One line under the bar, for what the segments cannot say themselves. */
  hint?: string
  onChange: (mode: ProtectionMode) => void
}) {
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.75 }}>
      <Typography color="text.secondary" sx={{ fontSize: 11.5, fontWeight: 600 }}>
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
        sx={{ '& .MuiToggleButton-root': SEGMENT_BUTTON }}
      >
        {modes.map((mode) => {
          const meta = modeMeta(mode)
          const allowed = modeAllowed(mode, floor)
          return (
            <ToggleButton
              key={mode}
              value={mode}
              disabled={!allowed}
              aria-label={meta.label}
              // Only the refusal is worth a tooltip: it is the one thing the
              // button cannot say by being greyed out.
              title={allowed ? undefined : `Sous le plancher : ${modeMeta(floor).label}.`}
            >
              {meta.label}
            </ToggleButton>
          )
        })}
      </ToggleButtonGroup>
      {hint && (
        <Typography color="text.disabled" sx={{ fontSize: 10.5, lineHeight: 1.5 }}>
          {hint}
        </Typography>
      )}
    </Box>
  )
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
        {/* The pin is static on this side. The certificate lifecycle rotates
            the gateway's leaves on Helios and Astra, but Orion holds no trust
            store yet: a reissued certificate is re-pasted here. Saying so on
            hover is what keeps the day it happens from looking like a
            breakage. */}
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
  inputRef,
}: {
  label: string
  value: string
  onChange: (value: string) => void
  type?: 'text' | 'number'
  placeholder?: string
  /** Lets a control above the field put the caret in it. */
  inputRef?: React.Ref<HTMLInputElement>
  /**
   * Message from the core, `null` if the field is acceptable.
   *
   * The only text a field ever prints under itself. There is deliberately no
   * `hint`: an explanation shown at all times is read once and then becomes
   * part of the furniture, and it pushes the error — the one line that has to
   * be seen — further down the form.
   */
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
      helperText={error}
      inputRef={inputRef}
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

