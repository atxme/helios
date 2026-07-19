import { useEffect, useState } from 'react'
import { Check, Eye, EyeOff, Plus, Save, Trash2 } from 'lucide-react'
import type { ClientConfig, ClientProfile } from '../types'

interface Props {
  config: ClientConfig
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

export function ProfilesView({ config, onSave, onDelete, onSelect }: Props) {
  const [draft, setDraft] = useState<ClientProfile>(
    () =>
      config.profiles.find((p) => p.name === config.selected) ??
      config.profiles[0] ??
      blankProfile(),
  )
  const [dirty, setDirty] = useState(false)

  useEffect(() => {
    if (dirty) return
    const selected = config.profiles.find((p) => p.name === config.selected) ?? config.profiles[0]
    if (selected) setDraft(selected)
  }, [config, dirty])

  const set = <K extends keyof ClientProfile>(key: K, value: ClientProfile[K]) => {
    setDraft((profile) => ({ ...profile, [key]: value }))
    setDirty(true)
  }

  const save = async () => {
    try {
      await onSave(draft)
      setDirty(false)
    } catch {
      // L'erreur est affichée par le hook global ; le brouillon reste modifié.
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
          }}
          className="flex items-center gap-1 rounded-full border border-dashed border-white/15 px-3 py-1 text-xs text-slate-400 hover:border-white/25 hover:text-slate-200"
        >
          <Plus size={11} /> Nouveau
        </button>
      </div>

      {/* ── Formulaire, groupé par ce que chaque champ décide ── */}
      <div className="min-h-0 flex-1 space-y-5 overflow-y-auto px-4 py-4">
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
          <Field
            label="Clé publique de la gateway"
            value={draft.peer_public_key}
            onChange={(v) => set('peer_public_key', v)}
          />
          <Note tone="warn">
            L’admission est <strong>hors bande</strong> : la clé publique dérivée de cette clé privée
            doit être déclarée sur Helios avant le premier handshake.
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
