import { useEffect, useRef, useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Chip from '@mui/material/Chip'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogContentText from '@mui/material/DialogContentText'
import DialogTitle from '@mui/material/DialogTitle'
import Divider from '@mui/material/Divider'
import IconButton from '@mui/material/IconButton'
import InputAdornment from '@mui/material/InputAdornment'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { Check, Eye, EyeOff, Plus, Save, Trash2, Upload } from 'lucide-react'
import * as api from '../api'
import type { ClientConfig, ClientProfile } from '../types'

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
  const [deleteOpen, setDeleteOpen] = useState(false)
  const fileInput = useRef<HTMLInputElement>(null)

  // La dérivation vit côté Rust : l’IHM ne manipule pas de crypto, et une clé
  // privée incomplète en cours de saisie rend simplement une valeur absente.
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

  useEffect(() => {
    if (dirty) return
    const selected = config.profiles.find((profile) => profile.name === config.selected) ?? config.profiles[0]
    if (selected) setDraft(selected)
  }, [config, dirty])

  useEffect(() => {
    if (!pathImport) return
    const replaces = config.profiles.some((candidate) => candidate.name === pathImport.name)
    setDraft(pathImport)
    setDirty(true)
    setImportNotice({
      tone: 'success',
      message: replaces
        ? `Profil « ${pathImport.name} » chargé par l’association de fichier. Enregistrer remplacera le profil existant.`
        : `Profil « ${pathImport.name} » chargé par l’association de fichier. Vérifiez-le puis enregistrez-le.`,
    })
    onPathImportHandled()
  }, [config.profiles, onPathImportHandled, pathImport])

  const set = <Key extends keyof ClientProfile>(key: Key, value: ClientProfile[Key]) => {
    setDraft((profile) => ({ ...profile, [key]: value }))
    setDirty(true)
    setImportNotice(null)
  }

  const save = async () => {
    try {
      await onSave(draft)
      setDirty(false)
      setImportNotice(null)
    } catch {
      // L’erreur globale garde le brouillon intact pour permettre une correction.
    }
  }

  const remove = async () => {
    try {
      await onDelete(draft.name)
      setDeleteOpen(false)
      setDirty(false)
    } catch {
      // L’erreur globale explique l’échec et la boîte reste ouverte.
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
      setDirty(true)
      setImportNotice({
        tone: 'success',
        message: existing
          ? `Profil « ${profile.name} » chargé. Enregistrer remplacera le profil existant.`
          : `Profil « ${profile.name} » chargé. Vérifiez-le puis enregistrez-le.`,
      })
    } catch (cause) {
      setImportNotice({ tone: 'error', message: `Import impossible : ${String(cause)}` })
    } finally {
      setImporting(false)
      if (fileInput.current) fileInput.current.value = ''
    }
  }

  const exists = config.profiles.some((profile) => profile.name === draft.name)

  return (
    <Box sx={{ display: 'flex', height: '100%', flexDirection: 'column' }}>
      <Box
        sx={{
          display: 'flex',
          flexShrink: 0,
          flexWrap: 'wrap',
          alignItems: 'center',
          gap: 0.75,
          px: 2,
          py: 1.5,
        }}
      >
        <Typography component="h2" variant="overline" color="text.disabled" sx={{ width: '100%' }}>
          Profils disponibles
        </Typography>
        {config.profiles.map((profile) => {
          const selected = profile.name === config.selected
          return (
            <Chip
              key={profile.name}
              label={profile.name}
              icon={selected ? <Check size={14} aria-hidden /> : undefined}
              color={selected ? 'primary' : 'default'}
              variant={selected ? 'filled' : 'outlined'}
              size="small"
              onClick={() => {
                setDraft(profile)
                setDirty(false)
                setImportNotice(null)
                void onSelect(profile.name).catch(() => {})
              }}
              aria-pressed={selected}
            />
          )
        })}
        <Button
          size="small"
          variant="outlined"
          color="inherit"
          startIcon={<Plus size={15} aria-hidden />}
          onClick={() => {
            setDraft(blankProfile())
            setDirty(true)
            setImportNotice(null)
          }}
          sx={{ minHeight: 32, borderStyle: 'dashed', color: 'text.secondary' }}
        >
          Nouveau
        </Button>
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
          variant="text"
          startIcon={<Upload size={15} aria-hidden />}
          disabled={importing}
          onClick={() => fileInput.current?.click()}
          sx={{ ml: 'auto', minHeight: 32 }}
        >
          {importing ? 'Chargement…' : 'Importer'}
        </Button>
      </Box>
      <Divider />

      <Stack spacing={2} sx={{ minHeight: 0, flex: 1, overflowY: 'auto', px: 2, py: 2 }}>
        {importNotice && (
          <Alert
            severity={importNotice.tone}
            variant="outlined"
            role={importNotice.tone === 'error' ? 'alert' : 'status'}
          >
            {importNotice.message}
          </Alert>
        )}

        <Section title="Identité">
          <Field label="Nom du profil" value={draft.name} onChange={(value) => set('name', value)} />
          <Field
            label="Endpoint de la gateway"
            placeholder="203.0.113.10:51820"
            value={draft.endpoint}
            onChange={(value) => set('endpoint', value)}
          />
          <Secret
            label="Clé privée du client"
            value={draft.private_key}
            onChange={(value) => set('private_key', value)}
          />
          <ReadOnlyField
            label="Clé publique du client"
            value={publicKey ?? '—'}
            hint="À transmettre à l’opérateur pour être admis."
          />
          <Field
            label="Clé publique de la gateway"
            value={draft.peer_public_key}
            onChange={(value) => set('peer_public_key', value)}
          />
          <Note tone="warn">
            L’admission est <strong>hors bande</strong> : la clé publique ci-dessus doit être
            déclarée sur Helios avant le premier handshake.
          </Note>
        </Section>

        <Section title="Réseau">
          <Field
            label="Adresse virtuelle"
            placeholder="100.64.1.2/32 — assignée à l’enrôlement"
            value={draft.address ?? ''}
            onChange={(value) => set('address', value || null)}
          />
          <Field
            label="Trafic capté (AllowedIPs)"
            value={draft.allowed_ips}
            onChange={(value) => set('allowed_ips', value)}
          />
          <Note>
            <Box component="span" sx={{ fontFamily: 'monospace' }}>
              0.0.0.0/0
            </Box>{' '}
            capte tout le trafic : c’est ce qui fait tenir l’invariante fail-open d’Orion. Le
            restreindre ouvre une fuite en clair.
          </Note>
          <Field
            label="Keepalive persistant (secondes)"
            type="number"
            value={String(draft.persistent_keepalive)}
            onChange={(value) => set('persistent_keepalive', Number(value) || 0)}
          />
        </Section>

        <Section title="Post-quantique">
          <Secret
            label="PSK dérivé de ML-KEM-768"
            value={draft.preshared_key ?? ''}
            onChange={(value) => set('preshared_key', value || null)}
          />
          <Note>
            Laissez ce champ vide : le PSK est négocié automatiquement à la connexion (ML-KEM-768),
            à condition que l’URL Helios interne soit renseignée ci-dessous. Une valeur saisie ici
            est considérée comme un PSK statique et <strong>désactive</strong> la négociation. Les
            deux pairs doivent alors porter exactement la même valeur, faute de quoi tous les
            handshakes échouent.
          </Note>
        </Section>

        <Section title="Supervision">
          <Field
            label="URL Helios interne"
            placeholder="http://100.64.0.1:8080"
            value={draft.heliosd_url ?? ''}
            onChange={(value) => set('heliosd_url', value || null)}
          />
          <Note>
            Joignable uniquement <em>après</em> le montage du tunnel : l’API d’Helios vit derrière
            lui.
          </Note>
        </Section>
      </Stack>

      <Divider />
      <Box sx={{ display: 'flex', flexShrink: 0, alignItems: 'center', gap: 1, px: 2, py: 1.5 }}>
        <Typography
          role="status"
          color={dirty ? 'warning.main' : 'text.disabled'}
          sx={{ mr: 'auto', fontSize: 11 }}
        >
          {dirty ? 'Modifications non enregistrées' : 'Profil à jour'}
        </Typography>
        <Button
          variant="contained"
          startIcon={<Save size={16} aria-hidden />}
          onClick={() => void save()}
          disabled={!dirty}
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

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Paper component="section" variant="outlined" sx={{ bgcolor: 'rgba(0, 0, 0, 0.14)', p: 1.5 }}>
      <Typography component="h3" variant="overline" color="text.disabled">
        {title}
      </Typography>
      <Stack spacing={1.5} sx={{ mt: 1 }}>
        {children}
      </Stack>
    </Paper>
  )
}

function Note({
  children,
  tone = 'plain',
}: {
  children: React.ReactNode
  tone?: 'plain' | 'warn'
}) {
  return (
    <Typography
      component="p"
      color={tone === 'warn' ? 'warning.main' : 'text.disabled'}
      sx={{ m: 0, fontSize: 11, lineHeight: 1.55, opacity: tone === 'warn' ? 0.85 : 1 }}
    >
      {children}
    </Typography>
  )
}

function Field({
  label,
  value,
  onChange,
  type = 'text',
  placeholder,
}: {
  label: string
  value: string
  onChange: (value: string) => void
  type?: 'text' | 'number'
  placeholder?: string
}) {
  return (
    <TextField
      fullWidth
      size="small"
      label={label}
      type={type}
      placeholder={placeholder}
      value={value}
      onChange={(event) => onChange(event.target.value)}
      sx={{ '& input': { fontFamily: 'monospace', fontSize: 12 } }}
    />
  )
}

/** Valeur dérivée, non saisissable : la modifier n’aurait aucun sens. */
function ReadOnlyField({
  label,
  value,
  hint,
}: {
  label: string
  value: string
  hint?: string
}) {
  return (
    <TextField
      fullWidth
      size="small"
      label={label}
      value={value}
      helperText={hint}
      slotProps={{ htmlInput: { readOnly: true } }}
      sx={{
        '& input': { fontFamily: 'monospace', fontSize: 12, opacity: 0.72 },
        '& .MuiFormHelperText-root': { fontSize: 11 },
      }}
    />
  )
}

/** Champ secret : masqué par défaut, révélable sans imposer une saisie à l’aveugle. */
function Secret({
  label,
  value,
  onChange,
}: {
  label: string
  value: string
  onChange: (value: string) => void
}) {
  const [visible, setVisible] = useState(false)
  return (
    <TextField
      fullWidth
      size="small"
      label={label}
      type={visible ? 'text' : 'password'}
      value={value}
      onChange={(event) => onChange(event.target.value)}
      slotProps={{
        input: {
          endAdornment: (
            <InputAdornment position="end">
              <Tooltip title={visible ? 'Masquer la valeur' : 'Afficher la valeur'}>
                <IconButton
                  edge="end"
                  size="small"
                  onClick={() => setVisible((current) => !current)}
                  aria-label={visible ? `Masquer ${label}` : `Afficher ${label}`}
                >
                  {visible ? <EyeOff size={17} aria-hidden /> : <Eye size={17} aria-hidden />}
                </IconButton>
              </Tooltip>
            </InputAdornment>
          ),
        },
      }}
      sx={{ '& input': { fontFamily: 'monospace', fontSize: 12 } }}
    />
  )
}
