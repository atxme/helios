import { useEffect, useState } from 'react'
import { Check, Plus, Save, Trash2 } from 'lucide-react'
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
    () => config.profiles.find((p) => p.name === config.selected) ?? config.profiles[0] ?? blankProfile(),
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

  return (
    <div className="flex h-full flex-col gap-3 px-4 py-4">
      <div className="flex flex-wrap gap-2">
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
              className={`flex items-center gap-1 rounded-full px-3 py-1 text-xs transition ${
                selected ? 'bg-node/20 text-node' : 'bg-white/5 text-slate-300 hover:bg-white/10'
              }`}
            >
              {selected && <Check size={12} />}
              {profile.name}
            </button>
          )
        })}
        <button
          onClick={() => { setDraft(blankProfile()); setDirty(true) }}
          className="flex items-center gap-1 rounded-full bg-white/5 px-3 py-1 text-xs text-slate-300 hover:bg-white/10"
        >
          <Plus size={12} /> Nouveau
        </button>
      </div>

      <div className="flex-1 space-y-3 overflow-y-auto pr-1">
        <Field label="Nom du profil" value={draft.name} onChange={(value) => set('name', value)} />
        <Field label="Endpoint WireGuard (IP/FQDN:port)" placeholder="203.0.113.10:51820" value={draft.endpoint} onChange={(value) => set('endpoint', value)} />
        <Field label="Clé privée du client" type="password" value={draft.private_key} onChange={(value) => set('private_key', value)} />
        <Field label="Clé publique de la gateway" value={draft.peer_public_key} onChange={(value) => set('peer_public_key', value)} />
        <Field label="Adresse virtuelle (optionnelle)" placeholder="100.64.1.2/32" value={draft.address ?? ''} onChange={(value) => set('address', value || null)} />
        <Field label="AllowedIPs" value={draft.allowed_ips} onChange={(value) => set('allowed_ips', value)} />
        <Field label="Keepalive persistant (secondes)" type="number" value={String(draft.persistent_keepalive)} onChange={(value) => set('persistent_keepalive', Number(value) || 0)} />
        <Field label="PSK post-quantique (optionnelle)" type="password" value={draft.preshared_key ?? ''} onChange={(value) => set('preshared_key', value || null)} />
        <p className="-mt-2 text-[11px] text-slate-500">
          Dérivée du provisioning ML-KEM. L’installation automatique côté gateway n’est pas encore câblée : renseignez-la uniquement si les deux pairs ont déjà la même valeur.
        </p>
        <Field label="URL Helios interne (optionnelle, post-tunnel)" placeholder="http://100.64.0.1:8080" value={draft.heliosd_url ?? ''} onChange={(value) => set('heliosd_url', value || null)} />
      </div>

      <p className="text-[11px] text-amber-400/80">
        Admission initiale hors bande : la clé publique dérivée de la clé privée du client doit être déclarée sur Helios avant le premier handshake.
      </p>

      <div className="flex gap-2">
        <button className="btn flex-1 bg-node/20 text-node hover:bg-node/30" onClick={() => void save()}>
          <span className="inline-flex items-center gap-1.5 justify-center"><Save size={14} /> Enregistrer</span>
        </button>
        {config.profiles.some((profile) => profile.name === draft.name) && (
          <button
            className="btn bg-red-950/50 text-red-300 hover:bg-red-900/50"
            onClick={() => void onDelete(draft.name).catch(() => {})}
            title="Supprimer le profil"
          >
            <Trash2 size={15} />
          </button>
        )}
      </div>
    </div>
  )
}

function Field({ label, value, onChange, type = 'text', placeholder }: {
  label: string
  value: string
  onChange: (value: string) => void
  type?: 'text' | 'password' | 'number'
  placeholder?: string
}) {
  return (
    <div>
      <label className="label">{label}</label>
      <input className="field font-mono text-xs" type={type} placeholder={placeholder} value={value} onChange={(event) => onChange(event.target.value)} />
    </div>
  )
}
