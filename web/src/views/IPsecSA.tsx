import {
  Atom, CheckCircle, ChevronDown, ChevronRight, KeyRound,
  RefreshCw, Shield, ShieldCheck, WifiOff, Zap,
} from 'lucide-react'
import { useEffect, useState } from 'react'
import { connectionApply, tunnelStart, tunnelStop } from '../api'
import type { Status, TunnelState } from '../types'

interface Props { status: Status | null; currentState: TunnelState }

// ─── Tables des paramètres ───────────────────────────────────────────────────

const ENC = [
  { v: 'aes256gcm16',      label: 'AES-256-GCM',       desc: 'AEAD 256 bits — recommandé'    },
  { v: 'aes128gcm16',      label: 'AES-128-GCM',       desc: 'AEAD 128 bits — plus rapide'   },
  { v: 'chacha20poly1305', label: 'ChaCha20-Poly1305',  desc: 'AEAD — sans AES-NI'           },
]
const PRF = [
  { v: 'prfsha512', label: 'PRF-SHA-512', desc: 'Niveau 5'                },
  { v: 'prfsha384', label: 'PRF-SHA-384', desc: 'Niveau 3 — recommandé'  },
  { v: 'prfsha256', label: 'PRF-SHA-256', desc: 'Niveau 2'                },
]
const DH_IKE = [
  { v: 'ecp521',     label: 'ECDH P-521',      family: 'ec',   desc: '521 bits'  },
  { v: 'ecp384',     label: 'ECDH P-384',      family: 'ec',   desc: '384 bits — recommandé' },
  { v: 'ecp256',     label: 'ECDH P-256',      family: 'ec',   desc: '256 bits'  },
  { v: 'curve25519', label: 'X25519',           family: 'ec25', desc: 'Bernstein' },
  { v: 'modp4096',   label: 'DH modp-4096',    family: 'modp', desc: 'FF — 4096 bits' },
  { v: 'modp2048',   label: 'DH modp-2048',    family: 'modp', desc: 'FF — 2048 bits' },
  { v: '',           label: 'Aucun (PQC seul)', family: 'none', desc: 'Full PQC — pas de DH classique' },
]
const KEM = [
  { v: '',              label: 'Aucun',       desc: 'Classique seul, pas de PQC'  },
  { v: 'ke1_mlkem512',  label: 'ML-KEM-512',  desc: 'NIST niveau 1 — FIPS 203'   },
  { v: 'ke1_mlkem768',  label: 'ML-KEM-768',  desc: 'NIST niveau 3 — recommandé' },
  { v: 'ke1_mlkem1024', label: 'ML-KEM-1024', desc: 'NIST niveau 5 — maximum'    },
]
const ESP_ENC = ENC

// Toutes les options PFS (montrées en permanence, incompatibles grisées)
const ALL_PFS = [
  { v: '',          label: 'Aucun (pas de PFS)',  family: 'any'  },
  { v: 'ecp521',    label: 'ECDH P-521',           family: 'ec'   },
  { v: 'ecp384',    label: 'ECDH P-384',           family: 'ec'   },
  { v: 'ecp256',    label: 'ECDH P-256',           family: 'ec'   },
  { v: 'curve25519',label: 'X25519',                family: 'ec25' },
  { v: 'modp4096',  label: 'DH modp-4096',         family: 'modp' },
  { v: 'modp2048',  label: 'DH modp-2048',         family: 'modp' },
]

function getDhFamily(dh: string) {
  return DH_IKE.find(o => o.v === dh)?.family ?? 'ec'
}

function pfsCompatible(pfsFamily: string, ikeFamily: string): boolean {
  if (ikeFamily === 'none') return pfsFamily === 'any'
  return pfsFamily === 'any' || pfsFamily === ikeFamily
}

// ─── Profils prédéfinis ──────────────────────────────────────────────────────

interface Preset {
  id: string; label: string; icon: React.ElementType
  cls: string; activeCls: string
  ikeEnc: string; ikePrf: string; ikeDh: string; ikeKem: string
  espEnc: string; espDh: string
  reserved?: boolean
}
const PRESETS: Preset[] = [
  {
    id: 'classic', label: 'Classique', icon: Shield,
    cls: 'border-slate-300 dark:border-slate-700',
    activeCls: 'border-slate-500 dark:border-slate-400 ring-slate-400/40 bg-slate-100/80 dark:bg-slate-800/60',
    ikeEnc:'aes256gcm16', ikePrf:'prfsha256', ikeDh:'ecp256', ikeKem:'',
    espEnc:'aes256gcm16', espDh:'',
  },
  {
    id: 'hybrid', label: 'Hybride PQC', icon: ShieldCheck,
    cls: 'border-violet-300/50 dark:border-violet-700/50',
    activeCls: 'border-violet-500 dark:border-violet-400 ring-violet-500/30 bg-violet-50 dark:bg-violet-950/40',
    ikeEnc:'aes256gcm16', ikePrf:'prfsha384', ikeDh:'ecp384', ikeKem:'ke1_mlkem768',
    espEnc:'aes256gcm16', espDh:'ecp384',
  },
  {
    id: 'hybrid-max', label: 'Hybride Max', icon: Zap,
    cls: 'border-amber-300/50 dark:border-amber-700/50',
    activeCls: 'border-amber-500 dark:border-amber-400 ring-amber-500/30 bg-amber-50 dark:bg-amber-950/40',
    ikeEnc:'aes256gcm16', ikePrf:'prfsha512', ikeDh:'ecp521', ikeKem:'ke1_mlkem1024',
    espEnc:'aes256gcm16', espDh:'ecp521',
    reserved: true,
  },
  {
    id: 'full-pqc', label: 'Full PQC', icon: Atom,
    cls: 'border-fuchsia-300/50 dark:border-fuchsia-700/50',
    activeCls: 'border-fuchsia-500 dark:border-fuchsia-400 ring-fuchsia-500/30 bg-fuchsia-50 dark:bg-fuchsia-950/40',
    ikeEnc:'aes256gcm16', ikePrf:'prfsha512', ikeDh:'', ikeKem:'ke1_mlkem1024',
    espEnc:'aes256gcm16', espDh:'',
    reserved: true,
  },
]

// ─── Parseurs ────────────────────────────────────────────────────────────────

function parseIke(prop: string) {
  const p = prop.split('-')
  return {
    enc: ENC.find(o => p.includes(o.v))?.v ?? 'aes256gcm16',
    prf: PRF.find(o => p.includes(o.v))?.v ?? 'prfsha384',
    // '' quand aucun DH classique (mode Full PQC)
    dh:  DH_IKE.find(o => o.v && p.includes(o.v))?.v ?? '',
    kem: KEM.find(o => o.v && p.includes(o.v))?.v ?? '',
  }
}
function parseEsp(prop: string) {
  const p = prop.split('-')
  return {
    enc: ESP_ENC.find(o => p.includes(o.v))?.v ?? 'aes256gcm16',
    dh:  ALL_PFS.find(o => o.v && p.includes(o.v))?.v ?? '',
  }
}
function buildIke(enc: string, prf: string, dh: string, kem: string) {
  return [enc, prf, dh, kem].filter(Boolean).join('-')
}
function buildEsp(enc: string, dh: string) {
  return [enc, dh].filter(Boolean).join('-')
}

// ─── Chips de proposition ────────────────────────────────────────────────────

function ProposalChips({ value }: { value: string }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {value.split('-').filter(Boolean).map((part, i) => {
        const isPqc = part.includes('mlkem')
        return (
          <span key={i} className={`font-mono text-[10px] px-2 py-0.5 rounded border ${
            isPqc
              ? 'border-violet-500/40 bg-violet-500/10 text-violet-600 dark:text-violet-400'
              : 'border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/60 text-slate-600 dark:text-slate-400'
          }`}>{part}</span>
        )
      })}
    </div>
  )
}

// ─── Sélecteur avec contraintes (options grises pour incompatibles) ───────────

function ConstrainedSelect<T extends string>({
  label, value, options, onChange, disabled = false, highlight = false,
  isOptionDisabled,
}: {
  label: string; value: T
  options: { v: T; label: string; desc?: string }[]
  onChange: (v: T) => void
  disabled?: boolean; highlight?: boolean
  isOptionDisabled?: (v: T) => boolean
}) {
  // Garantir que la valeur est dans une option activée ; sinon première option activée
  const safeValue = (() => {
    const available = options.filter(o => !isOptionDisabled?.(o.v))
    if (available.find(o => o.v === value)) return value
    return available[0]?.v ?? value
  })()

  return (
    <div className="space-y-1">
      <label className={`block text-[9px] uppercase tracking-widest font-semibold ${
        disabled ? 'text-slate-300 dark:text-slate-700' : 'text-slate-500 dark:text-slate-400'
      }`}>{label}</label>
      <div className={`relative rounded-lg border transition-all ${
        disabled
          ? 'border-slate-200 dark:border-slate-800 opacity-40'
          : highlight
          ? 'border-violet-400/60 dark:border-violet-600/60 ring-1 ring-violet-400/20 bg-white dark:bg-slate-900'
          : 'border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900'
      }`}>
        <select
          value={safeValue}
          disabled={disabled}
          onChange={e => !disabled && onChange(e.target.value as T)}
          className={`w-full text-xs font-mono px-3 py-2.5 rounded-lg appearance-none bg-transparent focus:outline-none ${
            disabled ? 'cursor-not-allowed text-slate-400 dark:text-slate-600'
            : highlight ? 'text-violet-700 dark:text-violet-300 cursor-pointer'
            : 'text-slate-700 dark:text-slate-300 cursor-pointer'
          }`}
        >
          {options.map(o => {
            const incompatible = isOptionDisabled?.(o.v) ?? false
            return (
              <option key={o.v} value={o.v} disabled={incompatible}>
                {incompatible ? '⊘ ' : ''}{o.label}{o.desc ? `  —  ${o.desc}` : ''}
              </option>
            )
          })}
        </select>
        <div className="absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none text-slate-400 dark:text-slate-600 text-[10px]">▾</div>
      </div>
    </div>
  )
}

function SectionDivider({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-2 my-1">
      <div className="h-px flex-1 bg-slate-100 dark:bg-slate-800" />
      <span className="text-[10px] font-semibold uppercase tracking-widest text-slate-400 dark:text-slate-600 px-2">{label}</span>
      <div className="h-px flex-1 bg-slate-100 dark:bg-slate-800" />
    </div>
  )
}

// ─── Carte SA ────────────────────────────────────────────────────────────────

interface SACardProps {
  name: string; remoteAddr: string
  localId: string | null; remoteId: string | null
  ikeProposal: string; espProposal: string
  currentState: TunnelState
}

function SACard({ name, remoteAddr, localId, ikeProposal, espProposal, currentState }: SACardProps) {
  const [open, setOpen] = useState(false)

  const [ikeEnc, setIkeEnc] = useState(() => parseIke(ikeProposal).enc)
  const [ikePrf, setIkePrf] = useState(() => parseIke(ikeProposal).prf)
  const [ikeDh,  setIkeDh]  = useState(() => parseIke(ikeProposal).dh)
  const [ikeKem, setIkeKem] = useState(() => parseIke(ikeProposal).kem)
  const [espEnc, setEspEnc] = useState(() => parseEsp(espProposal).enc)
  const [espDh,  setEspDh]  = useState(() => parseEsp(espProposal).dh)
  const [activePreset, setActivePreset] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [feedback, setFeedback] = useState<{ ok: boolean; msg: string } | null>(null)

  // Resync depuis les props quand le status se met à jour (après apply)
  useEffect(() => {
    const p = parseIke(ikeProposal)
    setIkeEnc(p.enc); setIkePrf(p.prf); setIkeDh(p.dh); setIkeKem(p.kem)
  }, [ikeProposal])
  useEffect(() => {
    const p = parseEsp(espProposal)
    setEspEnc(p.enc); setEspDh(p.dh)
  }, [espProposal])

  // Famille DH IKE → contrainte PFS ESP
  const family       = getDhFamily(ikeDh)
  const pfsForcedOff = family === 'none'

  // isOptionDisabled pour le sélecteur PFS
  const isPfsDisabled = (v: string) => !pfsCompatible(ALL_PFS.find(o => o.v === v)?.family ?? 'any', family)

  // Changement du DH IKE → auto-sync PFS si la valeur actuelle devient incompatible
  const handleIkeDhChange = (v: string) => {
    setIkeDh(v); setActivePreset(null)
    const newFamily = getDhFamily(v)
    if (!pfsCompatible(ALL_PFS.find(o => o.v === espDh)?.family ?? 'any', newFamily)) {
      // Reset vers la première option compatible non-vide (ou vide pour Full PQC)
      const first = ALL_PFS.find(o => o.v !== '' && pfsCompatible(o.family, newFamily))
      setEspDh(newFamily === 'none' ? '' : (first?.v ?? ''))
    }
  }

  const ikeStr = buildIke(ikeEnc, ikePrf, ikeDh, ikeKem)
  const espStr = buildEsp(espEnc, pfsForcedOff ? '' : espDh)
  // S'assurer que espDh actuel est compatible (fallback immédiat si état incohérent)
  const safeEspDh = isPfsDisabled(espDh) ? '' : espDh

  const isUp   = currentState === 'up' || currentState === 'rekeying'
  const isBusy = currentState === 'connecting' || loading
  const hasPqc = ikeProposal.includes('mlkem')

  const applyPreset = (p: Preset) => {
    if (p.reserved) {
      if (!window.confirm(`⚠️ Profil réservé — ${p.label}\nNécessite strongSwan ≥ 6 + plugin ML-KEM.\nConfirmer ?`)) return
    }
    setActivePreset(p.id)
    setIkeEnc(p.ikeEnc); setIkePrf(p.ikePrf)
    setIkeDh(p.ikeDh);   setIkeKem(p.ikeKem)
    setEspEnc(p.espEnc); setEspDh(p.espDh)
    setFeedback(null)
  }

  const applyAndRekey = async () => {
    setLoading(true); setFeedback(null)
    try {
      await connectionApply(ikeStr, espStr)
      setFeedback({ ok: true, msg: 'Commande envoyée — reconnexion en cours' })
    } catch {
      setFeedback({ ok: false, msg: "Erreur d'envoi de la commande" })
    } finally { setLoading(false) }
  }

  return (
    <div className="card overflow-hidden">
      {/* En-tête */}
      <button
        className="w-full flex items-center gap-3 p-5 text-left hover:bg-slate-50/40 dark:hover:bg-slate-800/20 transition-colors"
        onClick={() => setOpen(o => !o)}
      >
        <div className="h-9 w-9 rounded-lg bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 flex items-center justify-center shrink-0">
          <KeyRound className="h-4 w-4 text-slate-400 dark:text-slate-500" strokeWidth={1.5} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold text-slate-800 dark:text-slate-200">{name}</span>
            {hasPqc && (
              <span className="text-[9px] font-mono px-1.5 py-0.5 rounded border border-violet-500/30 bg-violet-500/8 text-violet-600 dark:text-violet-400 uppercase">PQC</span>
            )}
          </div>
          <div className="text-[11px] text-slate-400 dark:text-slate-600 font-mono mt-0.5">
            {remoteAddr}{localId ? ` · ${localId}` : ''}
          </div>
          {!open && <ProposalChips value={ikeProposal} />}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className={`flex items-center gap-1.5 text-[10px] font-mono uppercase px-2 py-1 rounded border ${
            isUp
              ? 'border-emerald-500/30 text-emerald-600 dark:text-emerald-400 bg-emerald-500/6'
              : 'border-slate-200 dark:border-slate-700 text-slate-400 dark:text-slate-600'
          }`}>
            <span className={`h-1.5 w-1.5 rounded-full ${isUp ? 'bg-emerald-500 animate-pulse' : 'bg-slate-300 dark:bg-slate-600'}`} />
            {currentState}
          </span>
          {open ? <ChevronDown className="h-4 w-4 text-slate-400" strokeWidth={1.5} />
                : <ChevronRight className="h-4 w-4 text-slate-400" strokeWidth={1.5} />}
        </div>
      </button>

      {/* Panneau de configuration */}
      {open && (
        <div className="border-t border-slate-200/60 dark:border-slate-800/60 p-5 space-y-5 bg-slate-50/30 dark:bg-slate-950/20">

          {/* Profils prédéfinis */}
          <div>
            <div className="text-[9px] uppercase tracking-widest font-semibold text-slate-400 dark:text-slate-600 mb-2">Profil prédéfini</div>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">
              {PRESETS.map(p => {
                const Icon = p.icon
                const isActive = activePreset === p.id
                return (
                  <button key={p.id} onClick={() => applyPreset(p)}
                    className={`flex flex-col items-center gap-1.5 py-3 px-2 rounded-lg border text-[11px] font-medium text-center transition-all ${
                      isActive
                        ? `${p.activeCls} ring-1 ring-offset-1 ring-offset-white dark:ring-offset-slate-950 text-slate-800 dark:text-slate-200`
                        : `${p.cls} text-slate-500 dark:text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 hover:bg-white/60 dark:hover:bg-slate-800/40`
                    }`}>
                    <Icon className="h-5 w-5" strokeWidth={1.5} />
                    <span>{p.label}</span>
                    {p.reserved && <span className="text-[9px] text-amber-500 dark:text-amber-400">⚠ réservé</span>}
                  </button>
                )
              })}
            </div>
          </div>

          {/* IKE SA */}
          <div>
            <SectionDivider label="IKE SA" />
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3">
              <ConstrainedSelect label="Chiffrement (AEAD)" value={ikeEnc} options={ENC}
                onChange={v => { setIkeEnc(v); setActivePreset(null) }} />
              <ConstrainedSelect label="Pseudo-Random Function (PRF)" value={ikePrf} options={PRF}
                onChange={v => { setIkePrf(v); setActivePreset(null) }} />
              <ConstrainedSelect label="Échange de clés classique (DH)"
                value={ikeDh} options={DH_IKE.map(o => ({ v: o.v, label: o.label, desc: o.desc }))}
                onChange={handleIkeDhChange} />
              <ConstrainedSelect label="PQC — ML-KEM (RFC 9370)"
                value={ikeKem} options={KEM}
                onChange={v => { setIkeKem(v); setActivePreset(null) }}
                highlight={!!ikeKem} />
            </div>
          </div>

          {/* Child SA / ESP */}
          <div>
            <SectionDivider label="Child SA / ESP" />
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3">
              <ConstrainedSelect label="Chiffrement ESP (AEAD)" value={espEnc} options={ESP_ENC}
                onChange={v => { setEspEnc(v); setActivePreset(null) }} />
              <ConstrainedSelect
                key={`pfs-${family}`}
                label={pfsForcedOff ? 'PFS — désactivé (Full PQC)' : 'Perfect Forward Secrecy (PFS / DH)'}
                value={pfsForcedOff ? '' : safeEspDh}
                options={pfsForcedOff
                  ? [{ v: '', label: 'Désactivé — mode Full PQC', desc: '' }]
                  : ALL_PFS.map(o => ({ v: o.v, label: o.label, desc: '' }))
                }
                onChange={v => { setEspDh(v); setActivePreset(null) }}
                disabled={pfsForcedOff}
                isOptionDisabled={pfsForcedOff ? undefined : isPfsDisabled}
              />
            </div>
            {pfsForcedOff && (
              <p className="mt-1.5 text-[10px] text-slate-400 dark:text-slate-600 font-mono leading-relaxed">
                Mode Full PQC : aucun DH classique → PFS via re-clé IKE ML-KEM uniquement
              </p>
            )}
          </div>

          {/* Aperçu résultat */}
          <div>
            <SectionDivider label="Aperçu — propositions à appliquer" />
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3">
              {([['IKE SA', ikeStr], ['Child SA / ESP', espStr]] as const).map(([lbl, val]) => (
                <div key={lbl} className="bg-white dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-lg px-4 py-3 space-y-2">
                  <div className="text-[9px] uppercase tracking-widest text-slate-400 dark:text-slate-600">{lbl}</div>
                  <ProposalChips value={val} />
                  <div className="font-mono text-[10px] text-slate-400 dark:text-slate-600 break-all">{val}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Actions rapides */}
          <div className="flex gap-2">
            <button onClick={async () => { setLoading(true); await tunnelStart(); setLoading(false) }}
              disabled={isBusy}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs border border-sky-500/30 bg-sky-500/5 text-sky-600 dark:text-sky-400 hover:bg-sky-500/10 transition-colors disabled:opacity-40 disabled:cursor-not-allowed">
              <RefreshCw className="h-3 w-3" strokeWidth={2} /> Re-clé (config actuelle)
            </button>
            <button onClick={async () => { setLoading(true); await tunnelStop(); setLoading(false) }}
              disabled={isBusy || !isUp}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs border border-red-500/30 bg-red-500/5 text-red-500 dark:text-red-400 hover:bg-red-500/10 transition-colors disabled:opacity-40 disabled:cursor-not-allowed">
              <WifiOff className="h-3 w-3" strokeWidth={2} /> Terminer
            </button>
          </div>

          {isUp && (
            <div className="flex items-start gap-2 p-3 rounded-lg border border-amber-500/25 bg-amber-500/5 text-xs text-amber-600 dark:text-amber-400">
              <RefreshCw className="h-3.5 w-3.5 shrink-0 mt-0.5" strokeWidth={1.5} />
              Un changement de propositions entraîne le ré-établissement de la IKE SA — coupure brève.
            </div>
          )}

          {feedback && (
            <div className={`flex items-center gap-2 p-3 rounded-lg border text-xs ${
              feedback.ok
                ? 'border-emerald-500/25 bg-emerald-500/5 text-emerald-600 dark:text-emerald-400'
                : 'border-red-500/25 bg-red-500/5 text-red-500'
            }`}>
              {feedback.ok && <CheckCircle className="h-3.5 w-3.5 shrink-0" strokeWidth={1.5} />}
              {feedback.msg}
            </div>
          )}

          <button onClick={applyAndRekey} disabled={isBusy}
            className="w-full flex items-center justify-center gap-2 py-3 rounded-lg
              border border-emerald-600/40 bg-emerald-500/8 text-emerald-700 dark:text-emerald-400 text-sm font-medium
              hover:bg-emerald-500/15 hover:border-emerald-500/60 transition-colors
              disabled:opacity-30 disabled:cursor-not-allowed">
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} strokeWidth={1.5} />
            {loading ? 'Envoi…' : 'Appliquer et re-clé'}
          </button>
        </div>
      )}
    </div>
  )
}

// ─── Vue principale ──────────────────────────────────────────────────────────

export function IPsecSAView({ status, currentState }: Props) {
  if (!status) {
    return (
      <div className="space-y-3 max-w-3xl animate-pulse">
        <div className="h-4 w-48 rounded bg-slate-200 dark:bg-slate-800" />
        <div className="card h-20" />
      </div>
    )
  }
  return (
    <div className="space-y-4 max-w-3xl">
      <div>
        <h1 className="text-sm font-semibold text-slate-800 dark:text-slate-200 tracking-wide">IKE Security Associations</h1>
        <p className="text-xs text-slate-500 mt-0.5">Dépliez une SA pour modifier ses propositions cryptographiques</p>
      </div>
      {status.connections.length === 0 ? (
        <div className="card p-12 text-center">
          <KeyRound className="h-8 w-8 text-slate-300 dark:text-slate-700 mx-auto mb-3" strokeWidth={1.5} />
          <p className="text-sm text-slate-500">Aucune SA configurée</p>
        </div>
      ) : (
        status.connections.map(c => (
          <SACard key={c.name} name={c.name} remoteAddr={c.remote_addr}
            localId={c.local_id} remoteId={c.remote_id}
            ikeProposal={c.ike_proposal} espProposal={c.esp_proposal}
            currentState={currentState} />
        ))
      )}
      {status.dry_run && (
        <p className="text-center text-[10px] font-mono text-slate-400 dark:text-slate-700 py-1">
          Mode simulation — les commandes re-clé ne déclenchent pas de vraie négociation VICI
        </p>
      )}
    </div>
  )
}
