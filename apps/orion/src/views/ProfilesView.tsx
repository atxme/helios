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
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import {
  AlertTriangle,
  ChevronRight,
  Eye,
  EyeOff,
  Plus,
  RotateCcw,
  Save,
  Trash2,
  Upload,
} from 'lucide-react'
import * as api from '../api'
import { GUTTER } from '../theme'
import type { ClientConfig, ClientProfile, ProfileIssues } from '../types'

/**
 * Profiles view — master-detail.
 *
 * The stance comes from actual usage: **a profile is imported, not typed**.
 * Nobody enters a base64 key by hand. The screen therefore favors choosing
 * and importing, not filling in; the four settings almost never touched
 * live under "Advanced".
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
  onImport: (contents: string, fileName: string) => Promise<ClientProfile>
  onSave: (profile: ClientProfile) => Promise<void>
  onDelete: (name: string) => Promise<void>
  onSelect: (name: string) => Promise<void>
}

function blankProfile(): ClientProfile {
  return {
    name: 'nouveau',
    endpoint: '',
    private_key: '',
    peer_public_key: '',
    preshared_key: null,
    address: null,
    allowed_ips: '0.0.0.0/0',
    persistent_keepalive: 25,
    heliosd_url: null,
  }
}

type ImportNotice = { tone: 'success' | 'error'; message: string }

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

export function ProfilesView({
  config,
  pathImport,
  onPathImportHandled,
  onImport,
  onSave,
  onDelete,
  onSelect,
}: Props) {
  const [draft, setDraft] = useState<ClientProfile>(
    () =>
      config.profiles.find((profile) => profile.name === config.selected) ??
      config.profiles[0] ??
      blankProfile(),
  )
  const [dirty, setDirty] = useState(false)
  const [importing, setImporting] = useState(false)
  const [importNotice, setImportNotice] = useState<ImportNotice | null>(null)
  const [publicKey, setPublicKey] = useState<string | null>(null)
  const [issues, setIssues] = useState<Partial<ProfileIssues>>({})
  const [history, setHistory] = useState<ClientProfile[]>([])
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [advanced, setAdvanced] = useState(false)
  const fileInput = useRef<HTMLInputElement>(null)

  // Derivation lives on the Rust side: the UI doesn't handle crypto, and an
  // incomplete private key mid-entry simply yields an absent value.
  useEffect(() => {
    let cancelled = false
    api
      .profilePublicKey(draft)
      .then((key) => {
        if (!cancelled) setPublicKey(key)
      })
      .catch(() => {
        if (!cancelled) setPublicKey(null)
      })
    return () => {
      cancelled = true
    }
  }, [draft])

  // The rules live in `orion-core`: we query the core rather than duplicate
  // its validation grammar in the UI. The call is deferred until typing
  // finishes.
  useEffect(() => {
    let cancelled = false
    const timer = setTimeout(() => {
      api
        .validateProfile(draft)
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
  }, [draft])

  useEffect(() => {
    if (dirty) return
    const selected =
      config.profiles.find((profile) => profile.name === config.selected) ?? config.profiles[0]
    if (selected) setDraft(selected)
  }, [config, dirty])

  useEffect(() => {
    if (!pathImport) return
    const replaces = config.profiles.some((candidate) => candidate.name === pathImport.name)
    setDraft(pathImport)
    setHistory([])
    setDirty(true)
    setImportNotice({
      tone: 'success',
      message: replaces
        ? `« ${pathImport.name} » chargé. Enregistrer remplacera le profil existant.`
        : `« ${pathImport.name} » chargé. Vérifiez-le puis enregistrez-le.`,
    })
    onPathImportHandled()
  }, [config.profiles, onPathImportHandled, pathImport])

  const set = <Key extends keyof ClientProfile>(key: Key, value: ClientProfile[Key]) => {
    setHistory((past) => [...past, draft].slice(-HISTORY_LIMIT))
    setDraft((profile) => ({ ...profile, [key]: value }))
    setDirty(true)
    setImportNotice(null)
  }

  /** Undoes the last field modification. */
  const undo = useCallback(() => {
    if (history.length === 0) return
    setDraft(history[history.length - 1])
    setHistory((past) => past.slice(0, -1))
    setDirty(true)
    setImportNotice(null)
  }, [history])

  /** Reverts to the profile as saved, in one go. */
  const revert = () => {
    const saved =
      config.profiles.find((profile) => profile.name === draft.name) ??
      config.profiles.find((profile) => profile.name === config.selected) ??
      config.profiles[0]
    if (!saved) return
    setDraft(saved)
    setHistory([])
    setDirty(false)
    setImportNotice(null)
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
      await onSave(draft)
      setDirty(false)
      setImportNotice(null)
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
    setImportNotice(null)
    if (file.size > MAX_IMPORT_BYTES) {
      setImportNotice({ tone: 'error', message: 'Fichier trop volumineux (maximum 64 Kio).' })
      if (fileInput.current) fileInput.current.value = ''
      return
    }

    setImporting(true)
    try {
      const profile = await onImport(await file.text(), file.name)
      const existing = config.profiles.find((candidate) => candidate.name === profile.name)

      setDraft(profile)
      setHistory([])
      setDirty(true)
      setImportNotice({
        tone: 'success',
        message: existing
          ? `« ${profile.name} » chargé. Enregistrer remplacera le profil existant.`
          : `« ${profile.name} » chargé. Vérifiez-le puis enregistrez-le.`,
      })
    } catch (cause) {
      setImportNotice({ tone: 'error', message: `Import impossible : ${String(cause)}` })
    } finally {
      setImporting(false)
      if (fileInput.current) fileInput.current.value = ''
    }
  }

  const exists = config.profiles.some((profile) => profile.name === draft.name)
  const narrowed = draft.allowed_ips.trim() !== CAPTURE_ALL
  const staticPsk = Boolean(draft.preshared_key?.trim())
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
                      setDraft(profile)
                      setHistory([])
                      setDirty(false)
                      setImportNotice(null)
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
              accept=".json,.conf,application/json,text/plain"
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
                setDraft(blankProfile())
                setHistory([])
                setDirty(true)
                setImportNotice(null)
              }}
              sx={{ color: 'text.secondary' }}
            >
              Nouveau
            </Button>
          </Box>
        </Box>

        {/* ── Detail: the essentials visible, the rare things collapsed. ── */}
        <Box sx={{ minWidth: 0, overflow: 'hidden', px: GUTTER, py: 1.5 }}>
          {importNotice && (
            <Alert
              severity={importNotice.tone}
              variant="outlined"
              role={importNotice.tone === 'error' ? 'alert' : 'status'}
              sx={{ mb: 1.5, py: 0, fontSize: 12 }}
            >
              {importNotice.message}
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
              <Secret
                label="Clé privée"
                error={issues.private_key}
                value={draft.private_key}
                onChange={(value) => set('private_key', value)}
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
                  <Secret
                    label="PSK statique"
                error={issues.preshared_key}
                    value={draft.preshared_key ?? ''}
                    onChange={(value) => set('preshared_key', value || null)}
                  />
                  {staticPsk && (
                    <Caution>
                      Laisser vide pour obtenir un <strong>PSK PQC</strong> négocié en ML-KEM-768 à
                      chaque connexion. Une valeur ici la <strong>désactive</strong> : le secret ne
                      tourne plus et les deux pairs doivent porter la même valeur.
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
      slotProps={{ htmlInput: { readOnly: true } }}
      sx={{ '& input': { fontFamily: 'monospace', fontSize: 12, opacity: 0.72 } }}
    />
  )
  return hint ? <Tooltip title={hint}>{field}</Tooltip> : field
}

/** Secret field: masked by default, revealable without forcing blind entry. */
function Secret({
  label,
  value,
  onChange,
  error,
}: {
  label: string
  value: string
  onChange: (value: string) => void
  /** Message from the core, `null` if the field is acceptable. */
  error?: string | null
}) {
  const [visible, setVisible] = useState(false)
  return (
    <TextField
      fullWidth
      size="small"
      label={label}
      type={visible ? 'text' : 'password'}
      value={value}
      error={Boolean(error)}
      helperText={error ?? undefined}
      onChange={(event) => onChange(event.target.value)}
      slotProps={{
        input: {
          endAdornment: (
            <InputAdornment position="end">
              <Tooltip title={visible ? 'Masquer la valeur' : 'Afficher la valeur'}>
                <IconButton
                  edge="end"
                  size="small"
                  onClick={() => setVisible((shown) => !shown)}
                  aria-label={visible ? 'Masquer la valeur' : 'Afficher la valeur'}
                >
                  {visible ? <EyeOff size={15} aria-hidden /> : <Eye size={15} aria-hidden />}
                </IconButton>
              </Tooltip>
            </InputAdornment>
          ),
        },
      }}
      sx={{
        '& input': { fontFamily: 'monospace', fontSize: 12 },
        '& .MuiFormHelperText-root': { fontSize: 10.5, lineHeight: 1.4 },
      }}
    />
  )
}
