import { Lock, LockOpen, Shield, Wifi, WifiOff, Zap } from 'lucide-react'
import { useState } from 'react'
import type { ProfileSummary, TunnelState } from '../types'

interface Props {
  state: TunnelState
  daemonError: boolean
  status_profiles: ProfileSummary[]
  selectedProfile: string | null
  onProfileChange: (id: string) => void
  onConnect: () => Promise<void>
  onDisconnect: () => Promise<void>
}

const KILL_SWITCH = {
  up:         { engaged: false, label: 'Kill-switch levé',   color: 'text-emerald-600 dark:text-emerald-500', dot: 'bg-emerald-500' },
  rekeying:   { engaged: false, label: 'Kill-switch levé',   color: 'text-emerald-600 dark:text-emerald-500', dot: 'bg-emerald-500' },
  connecting: { engaged: true,  label: 'Kill-switch actif',  color: 'text-amber-600 dark:text-amber-500',     dot: 'bg-amber-500 animate-pulse' },
  down:       { engaged: true,  label: 'Kill-switch engagé', color: 'text-slate-500',                         dot: 'bg-slate-400 dark:bg-slate-600' },
  failed:     { engaged: true,  label: 'Kill-switch engagé', color: 'text-red-500 dark:text-red-400',         dot: 'bg-red-500' },
} satisfies Record<TunnelState, { engaged: boolean; label: string; color: string; dot: string }>

const PQC_BADGE: Record<string, { label: string; cls: string }> = {
  None:           { label: 'Classique',  cls: 'border-slate-300 dark:border-slate-700 text-slate-500' },
  Hybrid768:      { label: 'PQC-768',   cls: 'border-violet-400/40 text-violet-600 dark:text-violet-400 bg-violet-500/5' },
  Hybrid1024:     { label: 'PQC-1024',  cls: 'border-violet-500/50 text-violet-600 dark:text-violet-400 bg-violet-500/8' },
  FullStrict1024: { label: 'Full PQC',  cls: 'border-fuchsia-500/50 text-fuchsia-600 dark:text-fuchsia-400 bg-fuchsia-500/8' },
}

export function TunnelControls({
  state, daemonError, status_profiles, selectedProfile, onProfileChange, onConnect, onDisconnect,
}: Props) {
  const [loading, setLoading] = useState(false)
  const ks = KILL_SWITCH[state]

  const handle = async (action: () => Promise<void>) => {
    setLoading(true)
    try { await action() } finally { setLoading(false) }
  }

  const canConnect    = !daemonError && (state === 'down' || state === 'failed')
  const canDisconnect = !daemonError && (state === 'up' || state === 'rekeying')
  const busy          = state === 'connecting' || loading

  const currentProfileMeta = status_profiles.find(p => p.id === selectedProfile)

  const handleConnect = async () => {
    if (currentProfileMeta?.reserved) {
      const ok = window.confirm(
        `⚠️ Profil réservé : "${currentProfileMeta.name}"\n\n` +
        `${currentProfileMeta.description}\n\nConfirmer la connexion ?`
      )
      if (!ok) return
    }
    await handle(onConnect)
  }

  return (
    <div className="panel hud p-5 flex flex-col gap-4">
      <h2 className="hud-title">Contrôles</h2>

      {/* Sélecteur de profil IKE */}
      {status_profiles.length > 0 && (
        <div className="space-y-2">
          <label className="text-[10px] uppercase tracking-widest text-slate-500 dark:text-slate-400">
            Profil IKEv2
          </label>
          <div className="grid grid-cols-1 gap-1.5">
            {status_profiles.map(p => {
              const badge = PQC_BADGE[p.pqc_level] ?? PQC_BADGE.None
              const active = p.id === selectedProfile
              return (
                <button
                  key={p.id}
                  onClick={() => onProfileChange(p.id)}
                  disabled={busy || (!canConnect && state !== 'down' && state !== 'failed')}
                  className={`
                    flex items-center gap-2 w-full px-3 py-2 rounded-lg border text-left text-xs
                    transition-all duration-150
                    ${active
                      ? 'border-cyan-400/50 bg-cyan-400/10 text-slate-900 dark:text-cyan-100 shadow-neon-cyan'
                      : 'border-slate-300/60 dark:border-slate-700/50 text-slate-500 dark:text-slate-400 hover:border-cyan-400/40 hover:text-cyan-700 dark:hover:text-cyan-300'
                    }
                    disabled:opacity-40 disabled:cursor-not-allowed
                  `}
                >
                  {p.reserved && <Zap className="h-3 w-3 text-amber-500 shrink-0" strokeWidth={2} />}
                  <span className="flex-1 font-medium">{p.name}</span>
                  <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${badge.cls}`}>
                    {badge.label}
                  </span>
                </button>
              )
            })}
          </div>
        </div>
      )}

      {/* Bouton Connecter */}
      <button
        onClick={handleConnect}
        disabled={!canConnect || busy}
        className="
          group flex items-center justify-center gap-2 w-full py-3 px-4 rounded-lg
          text-sm font-semibold tracking-wide transition-all duration-200
          border border-cyan-400/50 bg-gradient-to-r from-cyan-500/20 to-fuchsia-500/20
          text-cyan-700 dark:text-cyan-200
          hover:from-cyan-500/30 hover:to-fuchsia-500/30 hover:border-cyan-300/70
          hover:text-cyan-600 dark:hover:text-white hover:shadow-neon-cyan
          disabled:opacity-30 disabled:cursor-not-allowed disabled:shadow-none
          focus:outline-none focus:ring-2 focus:ring-cyan-400/50 focus:ring-offset-2
          focus:ring-offset-transparent
        "
      >
        {busy && state === 'connecting'
          ? <><Shield className="h-4 w-4 animate-pulse" strokeWidth={1.5} /> Établissement…</>
          : <><Wifi   className="h-4 w-4" strokeWidth={1.5} /> Connecter</>
        }
      </button>

      {/* Bouton Déconnecter */}
      <button
        onClick={() => handle(onDisconnect)}
        disabled={!canDisconnect || busy}
        className="
          group flex items-center justify-center gap-2 w-full py-3 px-4 rounded-lg
          text-sm font-medium tracking-wide transition-all duration-200
          border border-slate-300 dark:border-slate-700 bg-slate-100 dark:bg-slate-800/50
          text-slate-600 dark:text-slate-400
          hover:bg-red-500/10 hover:border-red-500/40 hover:text-red-500 dark:hover:text-red-400
          disabled:opacity-30 disabled:cursor-not-allowed
          focus:outline-none focus:ring-2 focus:ring-red-500/40 focus:ring-offset-2
          focus:ring-offset-white dark:focus:ring-offset-slate-900
        "
      >
        <WifiOff className="h-4 w-4" strokeWidth={1.5} />
        Déconnecter
      </button>

      {/* Indicateur Kill-switch */}
      <div className="mt-auto pt-3 border-t border-slate-200 dark:border-slate-800 flex items-center gap-2">
        {ks.engaged
          ? <Lock     className="h-3 w-3 text-slate-500 dark:text-slate-400 shrink-0" strokeWidth={1.5} />
          : <LockOpen className="h-3 w-3 text-slate-500 dark:text-slate-400 shrink-0" strokeWidth={1.5} />
        }
        <span className="text-[10px] uppercase tracking-widest text-slate-500 dark:text-slate-400">Kill-switch</span>
        <div className="flex items-center gap-1.5 ml-auto">
          <span className={`h-1.5 w-1.5 rounded-full ${ks.dot}`} />
          <span className={`text-[10px] font-mono uppercase ${ks.color}`}>{ks.label}</span>
        </div>
      </div>
    </div>
  )
}
