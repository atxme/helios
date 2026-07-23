import { useEffect, useRef, useState } from 'react'
import { Check, Eye, EyeOff, Plus, Save, Trash2, Upload } from 'lucide-react'
import * as api from '../api'
import type { ClientConfig, ClientProfile } from '../types'

interface Props {
  config: ClientConfig
  pathImport: ClientProfile | null
  onPathImportHandled: () => void
  onImport: (contents: string, fileName: string) => Promise<ClientProfile>
  onSave: (p: ClientProfile) => Promise<void>
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
      config.profiles.find((p) => p.name === config.selected) ??
      config.profiles[0] ??
      blankProfile(),
  )
  const [dirty, setDirty] = useState(false)
  const [importing, setImporting] = useState(false)
  const [importNotice, setImportNotice] = useState<ImportNotice | null>(null)
  const [publicKey, setPublicKey] = useState<string | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)

  // La dérivation vit côté Rust : l'IHM ne manipule pas de crypto, et une clé
  // privée incomplète en cours de saisie rend simplement une valeur absente.
  useEffect(() => {
    let annule = false
    api
      .profilePublicKey(draft)
      .then((key) => {
        if (!annule) setPublicKey(key)
      })
      .catch(() => {
        if (!annule) setPublicKey(null)
      })
    return () => {
      annule = true
    }
  }, [draft])

  useEffect(() => {
    if (dirty) return
    const selected = config.profiles.find((p) => p.name === config.selected) ?? config.profiles[0]
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
        ? `Profil « ${pathImport.name} » chargé par l'association de fichier. Enregistrer remplacera le profil existant.`
        : `Profil « ${pathImport.name} » chargé par l'association de fichier. Vérifiez-le puis enregistrez-le.`,
    })
    onPathImportHandled()
  }, [config.profiles, onPathImportHandled, pathImport])

  const set = <K extends keyof ClientProfile>(key: K, value: ClientProfile[K]) => {
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
      // L'erreur est affichée par le hook global ; le brouillon reste modifié.
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
    <div className="flex h-full flex-col">
      {/* ── Sélecteur de profil ── */}
      <div className="flex shrink-0 flex-wrap gap-1.5 border-b border-white/5 px-4 py-3">
        {config.profiles.map((profile) => {
          const selected = profile.name === config.selected
          return (
            <button
              key={profile.name}
              onClick={() => {
                setDraft(profile)
                setDirty(false)
                setImportNotice(null)
                void onSelect(profile.name).catch(() => {})
              }}
              className={`flex items-center gap-1.5 rounded-full px-3 py-1 text-xs transition ${
                selected
                  ? 'bg-node/20 text-node ring-1 ring-node/30'
                  : 'bg-white/5 text-slate-300 hover:bg-white/10'
              }`}
            >
              {selected && <Check size={11} />}
              {profile.name}
            </button>
          )
        })}
        <button
          onClick={() => {
            setDraft(blankProfile())
            setDirty(true)
            setImportNotice(null)
          }}
          className="flex items-center gap-1 rounded-full border border-dashed border-white/15 px-3 py-1 text-xs text-slate-400 hover:border-white/25 hover:text-slate-200"
        >
          <Plus size={11} /> Nouveau
        </button>
        <input
          ref={fileInput}
          className="hidden"
          type="file"
          accept=".json,.conf,application/json,text/plain"
          onChange={(event) => void importFile(event.target.files?.[0])}
        />
        <button
          type="button"
          disabled={importing}
          onClick={() => fileInput.current?.click()}
          className="ml-auto flex items-center gap-1 rounded-full border border-node/20 bg-node/10 px-3 py-1 text-xs text-node transition hover:bg-node/20 disabled:opacity-50"
          title="Charger un profil Orion JSON ou WireGuard"
        >
          <Upload size={11} /> {importing ? 'Chargement…' : 'Importer'}
        </button>
      </div>

      {/* ── Formulaire, groupé par ce que chaque champ décide ── */}
      <div className="min-h-0 flex-1 space-y-5 overflow-y-auto px-4 py-4">
        {importNotice && (
          <div
            role={importNotice.tone === 'error' ? 'alert' : 'status'}
            className={`rounded-lg border px-3 py-2 text-xs leading-relaxed ${
              importNotice.tone === 'error'
                ? 'border-red-500/30 bg-red-950/40 text-red-200'
                : 'border-node/25 bg-node/10 text-node'
            }`}
          >
            {importNotice.message}
          </div>
        )}
        <Section title="Identité">
          <Field label="Nom du profil" value={draft.name} onChange={(v) => set('name', v)} />
          <Field
            label="Endpoint de la gateway"
            placeholder="203.0.113.10:51820"
            value={draft.endpoint}
            onChange={(v) => set('endpoint', v)}
          />
          <Secret
            label="Clé privée du client"
            value={draft.private_key}
            onChange={(v) => set('private_key', v)}
          />
          <ReadOnlyField
            label="Clé publique du client"
            value={publicKey ?? '—'}
            hint="À transmettre à l’opérateur pour être admis."
          />
          <Field
            label="Clé publique de la gateway"
            value={draft.peer_public_key}
            onChange={(v) => set('peer_public_key', v)}
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
            onChange={(v) => set('address', v || null)}
          />
          <Field
            label="Trafic capté (AllowedIPs)"
            value={draft.allowed_ips}
            onChange={(v) => set('allowed_ips', v)}
          />
          <Note>
            <span className="font-mono">0.0.0.0/0</span> capte tout le trafic — c’est ce qui fait
            tenir l’invariante fail-open d’Orion. Le restreindre y ouvre une fuite en clair.
          </Note>
          <Field
            label="Keepalive persistant (secondes)"
            type="number"
            value={String(draft.persistent_keepalive)}
            onChange={(v) => set('persistent_keepalive', Number(v) || 0)}
          />
        </Section>

        <Section title="Post-quantique">
          <Secret
            label="PSK dérivé de ML-KEM-768"
            value={draft.preshared_key ?? ''}
            onChange={(v) => set('preshared_key', v || null)}
          />
          <Note>
            Laissez ce champ vide : le PSK est négocié automatiquement à la connexion (ML-KEM-768),
            à condition que l’URL Helios interne soit renseignée ci-dessous. Une valeur saisie ici
            est considérée comme un PSK statique et <strong>désactive</strong> la négociation — les
            deux pairs doivent alors porter exactement la même, faute de quoi tous les handshakes
            échouent.
          </Note>
        </Section>

        <Section title="Supervision">
          <Field
            label="URL Helios interne"
            placeholder="http://100.64.0.1:8080"
            value={draft.heliosd_url ?? ''}
            onChange={(v) => set('heliosd_url', v || null)}
          />
          <Note>
            Joignable uniquement <em>après</em> le montage du tunnel — l’API d’Helios vit derrière
            lui.
          </Note>
        </Section>
      </div>

      {/* ── Actions ── */}
      <div className="flex shrink-0 items-center gap-2 border-t border-white/5 px-4 py-3">
        {dirty && (
          <span className="mr-auto text-[11px] text-amber-400/80">
            Modifications non enregistrées
          </span>
        )}
        <button
          className={`btn flex items-center gap-1.5 border ${
            dirty
              ? 'border-node/30 bg-node/20 text-node hover:bg-node/30'
              : 'ml-auto border-white/10 bg-white/5 text-slate-400'
          }`}
          onClick={() => void save()}
        >
          <Save size={14} /> Enregistrer
        </button>
        {exists && (
          <button
            className="btn border border-red-500/25 bg-red-950/40 text-red-300 hover:bg-red-900/50"
            onClick={() => void onDelete(draft.name).catch(() => {})}
            title="Supprimer le profil"
            aria-label="Supprimer le profil"
          >
            <Trash2 size={15} />
          </button>
        )}
      </div>
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="space-y-2.5">
      <h2 className="text-[10px] uppercase tracking-[0.18em] text-slate-500">{title}</h2>
      {children}
    </section>
  )
}

function Note({ children, tone = 'plain' }: { children: React.ReactNode; tone?: 'plain' | 'warn' }) {
  return (
    <p
      className={`text-[11px] leading-relaxed ${
        tone === 'warn' ? 'text-amber-400/75' : 'text-slate-500'
      }`}
    >
      {children}
    </p>
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
    <div>
      <label className="label">{label}</label>
      <input
        className="field font-mono text-xs"
        type={type}
        placeholder={placeholder}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
    </div>
  )
}

/** Valeur dérivée, non saisissable : la modifier n'aurait aucun sens. */
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
    <div>
      <label className="label">{label}</label>
      <input className="field font-mono text-xs opacity-70" value={value} readOnly />
      {hint && <p className="mt-1 text-[11px] text-slate-500">{hint}</p>}
    </div>
  )
}

/** Champ secret : masqué par défaut, révélable — on ne saisit pas une clé à l'aveugle. */
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
    <div>
      <label className="label">{label}</label>
      <div className="relative">
        <input
          className="field pr-9 font-mono text-xs"
          type={visible ? 'text' : 'password'}
          value={value}
          onChange={(event) => onChange(event.target.value)}
        />
        <button
          type="button"
          onClick={() => setVisible((v) => !v)}
          className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-slate-500 hover:text-slate-300"
          aria-label={visible ? 'Masquer' : 'Afficher'}
        >
          {visible ? <EyeOff size={13} /> : <Eye size={13} />}
        </button>
      </div>
    </div>
  )
}
