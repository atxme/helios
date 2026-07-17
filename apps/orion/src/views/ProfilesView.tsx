import { useEffect, useState } from 'react'
import { Plus, Save, Trash2, Check } from 'lucide-react'
import type { AuthConfig, ClientConfig, ClientProfile, PredefinedProfile } from '../types'

interface Props {
  config: ClientConfig
  predefined: PredefinedProfile[]
  onSave: (p: ClientProfile) => Promise<void>
  onDelete: (name: string) => Promise<void>
  onSelect: (name: string) => Promise<void>
}

function blankProfile(): ClientProfile {
  return {
    name: 'nouveau',
    gateway: '',
    local_id: null,
    remote_id: null,
    auth: { method: 'psk', secret: '' },
    profile_id: 'hybrid',
    ike_proposal: null,
    esp_proposal: null,
    heliosd_url: null,
  }
}

export function ProfilesView({ config, predefined, onSave, onDelete, onSelect }: Props) {
  const [draft, setDraft] = useState<ClientProfile>(
    () => config.profiles.find((p) => p.name === config.selected) ?? config.profiles[0] ?? blankProfile(),
  )
  const [dirty, setDirty] = useState(false)

  // Recale le brouillon si la sélection change côté backend (et pas d'édition en cours).
  useEffect(() => {
    if (dirty) return
    const sel = config.profiles.find((p) => p.name === config.selected) ?? config.profiles[0]
    if (sel) setDraft(sel)
  }, [config, dirty])

  const set = <K extends keyof ClientProfile>(k: K, v: ClientProfile[K]) => {
    setDraft((d) => ({ ...d, [k]: v }))
    setDirty(true)
  }

  const setAuth = (auth: AuthConfig) => set('auth', auth)

  const usesPq = Boolean(draft.profile_id && draft.profile_id !== 'classic' && draft.profile_id !== null)

  const save = async () => {
    await onSave(draft)
    setDirty(false)
  }

  return (
    <div className="flex h-full flex-col gap-3 px-4 py-4">
      {/* Sélecteur de profils existants */}
      <div className="flex flex-wrap gap-2">
        {config.profiles.map((p) => {
          const selected = p.name === config.selected
          return (
            <button
              key={p.name}
              onClick={() => { setDirty(false); onSelect(p.name) }}
              className={`flex items-center gap-1 rounded-full px-3 py-1 text-xs transition ${
                selected ? 'bg-node/20 text-node' : 'bg-white/5 text-slate-300 hover:bg-white/10'
              }`}
            >
              {selected && <Check size={12} />}
              {p.name}
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
        <div>
          <label className="label">Nom du profil</label>
          <input className="field" value={draft.name} onChange={(e) => set('name', e.target.value)} />
        </div>

        <div>
          <label className="label">Endpoint gateway (IP ou FQDN)</label>
          <input
            className="field font-mono"
            placeholder="203.0.113.10"
            value={draft.gateway}
            onChange={(e) => set('gateway', e.target.value)}
          />
        </div>

        <div className="grid grid-cols-2 gap-2">
          <div>
            <label className="label">Identité locale</label>
            <input
              className="field font-mono"
              placeholder="client@helios"
              value={draft.local_id ?? ''}
              onChange={(e) => set('local_id', e.target.value || null)}
            />
          </div>
          <div>
            <label className="label">Identité gateway</label>
            <input
              className="field font-mono"
              placeholder="gw@example.net"
              value={draft.remote_id ?? ''}
              onChange={(e) => set('remote_id', e.target.value || null)}
            />
          </div>
        </div>

        {/* Profil cryptographique */}
        <div>
          <label className="label">Profil cryptographique (IKE/ESP)</label>
          <select
            className="field"
            value={draft.profile_id ?? '__custom__'}
            onChange={(e) =>
              set('profile_id', e.target.value === '__custom__' ? null : e.target.value)
            }
          >
            {predefined.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}{p.reserved ? ' (réservé)' : ''}
              </option>
            ))}
            <option value="__custom__">Personnalisé…</option>
          </select>
          {draft.profile_id && (
            <p className="mt-1 text-[11px] text-slate-500">
              {predefined.find((p) => p.id === draft.profile_id)?.description}
            </p>
          )}
          {usesPq && (
            <p className="mt-1 text-[11px] text-amber-400/90">
              ⚠ Échange post-quantique (ML-KEM) : nécessite strongSwan ≥ 6 côté client.
              Indisponible sur les piles IKEv2 natives Windows/macOS.
            </p>
          )}
        </div>

        {draft.profile_id === null && (
          <div className="grid grid-cols-1 gap-2">
            <div>
              <label className="label">Proposition IKE</label>
              <input
                className="field font-mono text-xs"
                placeholder="aes256gcm16-prfsha384-ecp384"
                value={draft.ike_proposal ?? ''}
                onChange={(e) => set('ike_proposal', e.target.value || null)}
              />
            </div>
            <div>
              <label className="label">Proposition ESP</label>
              <input
                className="field font-mono text-xs"
                placeholder="aes256gcm16-ecp384"
                value={draft.esp_proposal ?? ''}
                onChange={(e) => set('esp_proposal', e.target.value || null)}
              />
            </div>
          </div>
        )}

        {/* Authentification */}
        <div>
          <label className="label">Authentification</label>
          <select
            className="field"
            value={draft.auth.method}
            onChange={(e) => {
              const m = e.target.value
              if (m === 'psk') setAuth({ method: 'psk', secret: '' })
              else if (m === 'eap') setAuth({ method: 'eap', username: '', password: '' })
              else setAuth({ method: 'cert', cert_path: '', key_path: '' })
            }}
          >
            <option value="psk">Clé pré-partagée (PSK)</option>
            <option value="eap">EAP (utilisateur / mot de passe)</option>
            <option value="cert">Certificat X.509</option>
          </select>
        </div>

        {draft.auth.method === 'psk' && (
          <input
            className="field font-mono"
            type="password"
            placeholder="clé pré-partagée"
            value={draft.auth.secret}
            onChange={(e) => setAuth({ method: 'psk', secret: e.target.value })}
          />
        )}
        {draft.auth.method === 'eap' && (
          <div className="grid grid-cols-2 gap-2">
            <input
              className="field"
              placeholder="utilisateur"
              value={draft.auth.username}
              onChange={(e) =>
                setAuth({ method: 'eap', username: e.target.value, password: (draft.auth as { password: string }).password })
              }
            />
            <input
              className="field"
              type="password"
              placeholder="mot de passe"
              value={draft.auth.password}
              onChange={(e) =>
                setAuth({ method: 'eap', username: (draft.auth as { username: string }).username, password: e.target.value })
              }
            />
          </div>
        )}
        {draft.auth.method === 'cert' && (
          <div className="grid grid-cols-1 gap-2">
            <input
              className="field font-mono text-xs"
              placeholder="/chemin/vers/cert.pem"
              value={draft.auth.cert_path}
              onChange={(e) =>
                setAuth({ method: 'cert', cert_path: e.target.value, key_path: (draft.auth as { key_path: string }).key_path })
              }
            />
            <input
              className="field font-mono text-xs"
              placeholder="/chemin/vers/key.pem"
              value={draft.auth.key_path}
              onChange={(e) =>
                setAuth({ method: 'cert', cert_path: (draft.auth as { cert_path: string }).cert_path, key_path: e.target.value })
              }
            />
          </div>
        )}

        {/* Télémétrie heliosd (post-tunnel) */}
        <div>
          <label className="label">URL heliosd interne (optionnel, post-tunnel)</label>
          <input
            className="field font-mono text-xs"
            placeholder="http://10.10.0.1:8080"
            value={draft.heliosd_url ?? ''}
            onChange={(e) => set('heliosd_url', e.target.value || null)}
          />
          <p className="mt-1 text-[11px] text-slate-500">
            Joignable uniquement une fois le tunnel monté — sert à la télémétrie enrichie.
          </p>
        </div>
      </div>

      {/* Actions */}
      <div className="flex gap-2">
        <button className="btn flex-1 bg-node/20 text-node hover:bg-node/30" onClick={save}>
          <span className="inline-flex items-center gap-1.5 justify-center">
            <Save size={14} /> Enregistrer
          </span>
        </button>
        {config.profiles.some((p) => p.name === draft.name) && (
          <button
            className="btn bg-red-950/60 text-red-300 hover:bg-red-900/60"
            onClick={() => onDelete(draft.name)}
          >
            <Trash2 size={14} />
          </button>
        )}
      </div>
    </div>
  )
}
