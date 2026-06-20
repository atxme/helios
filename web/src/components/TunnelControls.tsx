import { Lock, Shield, ShieldOff, Wifi, WifiOff } from 'lucide-react'
import { useState } from 'react'
import type { TunnelState } from '../types'

interface Props {
  state: TunnelState
  onConnect: () => Promise<void>
  onDisconnect: () => Promise<void>
}

const KILL_SWITCH = {
  up:         { engaged: false, label: 'Kill-switch levé',   color: 'text-emerald-500', dot: 'bg-emerald-500' },
  rekeying:   { engaged: false, label: 'Kill-switch levé',   color: 'text-emerald-500', dot: 'bg-emerald-500' },
  connecting: { engaged: true,  label: 'Kill-switch actif',  color: 'text-amber-500',   dot: 'bg-amber-500 animate-pulse' },
  down:       { engaged: true,  label: 'Kill-switch engagé', color: 'text-red-500',      dot: 'bg-red-500' },
  failed:     { engaged: true,  label: 'Kill-switch engagé', color: 'text-red-500',      dot: 'bg-red-500' },
} satisfies Record<TunnelState, { engaged: boolean; label: string; color: string; dot: string }>

export function TunnelControls({ state, onConnect, onDisconnect }: Props) {
  const [loading, setLoading] = useState(false)
  const ks = KILL_SWITCH[state]

  const handle = async (action: () => Promise<void>) => {
    setLoading(true)
    try { await action() } finally { setLoading(false) }
  }

  const canConnect    = state === 'down' || state === 'failed'
  const canDisconnect = state === 'up' || state === 'rekeying'
  const busy          = state === 'connecting' || loading

  return (
    <div className="rounded-xl bg-zinc-900/60 border border-zinc-800 p-5 flex flex-col gap-4">
      <h2 className="text-[10px] font-medium uppercase tracking-[0.15em] text-zinc-500">
        Contrôles
      </h2>

      {/* Bouton Connecter */}
      <button
        onClick={() => handle(onConnect)}
        disabled={!canConnect || busy}
        className="
          group flex items-center justify-center gap-2 w-full py-3 px-4 rounded-lg
          text-sm font-medium tracking-wide transition-all duration-200
          border border-emerald-600/50 bg-emerald-600/10 text-emerald-400
          hover:bg-emerald-600/20 hover:border-emerald-500/70 hover:text-emerald-300
          disabled:opacity-30 disabled:cursor-not-allowed disabled:hover:bg-emerald-600/10
          focus:outline-none focus:ring-2 focus:ring-emerald-500/50 focus:ring-offset-2 focus:ring-offset-zinc-900
        "
      >
        {busy && state === 'connecting'
          ? <><Shield className="h-4 w-4 animate-pulse" strokeWidth={1.5} /> Établissement…</>
          : <><Wifi   className="h-4 w-4" strokeWidth={1.5} /> Connecter</>
        }
      </button>

      {/* Bouton Déconnecter / Kill-switch */}
      <button
        onClick={() => handle(onDisconnect)}
        disabled={!canDisconnect || busy}
        className="
          group flex items-center justify-center gap-2 w-full py-3 px-4 rounded-lg
          text-sm font-medium tracking-wide transition-all duration-200
          border border-zinc-700 bg-zinc-800/50 text-zinc-400
          hover:bg-red-500/10 hover:border-red-500/40 hover:text-red-400
          disabled:opacity-30 disabled:cursor-not-allowed
          focus:outline-none focus:ring-2 focus:ring-red-500/40 focus:ring-offset-2 focus:ring-offset-zinc-900
        "
      >
        <WifiOff className="h-4 w-4" strokeWidth={1.5} />
        Déconnecter
      </button>

      {/* Indicateur Kill-switch */}
      <div className="mt-auto pt-3 border-t border-zinc-800 flex items-center gap-2">
        <Lock className="h-3 w-3 text-zinc-600 shrink-0" strokeWidth={1.5} />
        <span className="text-[10px] uppercase tracking-widest text-zinc-600">Kill-switch</span>
        <div className="flex items-center gap-1.5 ml-auto">
          <span className={`h-1.5 w-1.5 rounded-full ${ks.dot}`} />
          <span className={`text-[10px] font-mono uppercase ${ks.color}`}>{ks.label}</span>
        </div>
      </div>

      {/* Badge mode simulation */}
      {state === 'up' && (
        <div className="flex items-center gap-2">
          <ShieldOff className="h-3 w-3 text-zinc-700 shrink-0" strokeWidth={1.5} />
          <span className="text-[10px] text-zinc-700 uppercase tracking-widest">
            Trafic autorisé via ESP/XFRM
          </span>
        </div>
      )}
    </div>
  )
}
