import { DoorOpen, Lock, LockOpen, Shield, Wifi, WifiOff } from 'lucide-react'
import { useState } from 'react'
import type { TunnelState } from '../types'

interface Props {
  state: TunnelState
  daemonError: boolean
  captiveGateway: string | null
  onConnect: () => Promise<void>
  onDisconnect: () => Promise<void>
  onReleaseCaptivePortal: () => Promise<void>
}

const KILL_SWITCH: Record<TunnelState, { engaged: boolean; label: string; color: string; dot: string }> = {
  up: { engaged: false, label: 'Trafic autorisé', color: 'text-emerald-600 dark:text-emerald-500', dot: 'bg-emerald-500' },
  connecting: { engaged: true, label: 'Trafic bloqué', color: 'text-amber-600 dark:text-amber-500', dot: 'bg-amber-500 animate-pulse' },
  down: { engaged: true, label: 'Trafic bloqué', color: 'text-slate-500', dot: 'bg-slate-400 dark:bg-slate-600' },
  failed: { engaged: true, label: 'Trafic bloqué', color: 'text-red-500 dark:text-red-400', dot: 'bg-red-500' },
  captive_portal: { engaged: true, label: 'Accès portail seul', color: 'text-amber-600 dark:text-amber-400', dot: 'bg-amber-500 animate-pulse' },
}

export function TunnelControls({
  state,
  daemonError,
  captiveGateway,
  onConnect,
  onDisconnect,
  onReleaseCaptivePortal,
}: Props) {
  const [loading, setLoading] = useState(false)
  const killSwitch = KILL_SWITCH[state]
  const run = async (action: () => Promise<void>) => {
    setLoading(true)
    try {
      await action()
    } catch {
      // Le bandeau global affiche l'erreur remontée par useHelios.
    } finally {
      setLoading(false)
    }
  }

  const canConnect = !daemonError && (state === 'down' || state === 'failed')
  const canDisconnect = !daemonError && state !== 'down'

  return (
    <div className="panel hud p-5 flex flex-col gap-4">
      <h2 className="hud-title">Contrôle de la gateway</h2>
      <p className="text-xs text-slate-500">
        Helios monte une interface WireGuard serveur et attend les handshakes des clients admis.
      </p>

      <button
        onClick={() => run(onConnect)}
        disabled={!canConnect || loading}
        className="flex items-center justify-center gap-2 w-full py-3 px-4 rounded-lg text-sm font-semibold border border-cyan-400/50 bg-cyan-500/10 text-cyan-700 dark:text-cyan-200 disabled:opacity-30 disabled:cursor-not-allowed"
      >
        {loading && canConnect ? <Shield className="h-4 w-4 animate-pulse" /> : <Wifi className="h-4 w-4" />}
        Monter l’interface
      </button>

      <button
        onClick={() => run(onDisconnect)}
        disabled={!canDisconnect || loading}
        className="flex items-center justify-center gap-2 w-full py-3 px-4 rounded-lg text-sm border border-slate-300 dark:border-slate-700 text-slate-600 dark:text-slate-400 hover:border-red-500/40 hover:text-red-500 disabled:opacity-30 disabled:cursor-not-allowed"
      >
        <WifiOff className="h-4 w-4" /> Arrêter l’interface
      </button>

      {state === 'captive_portal' && (
        <button
          onClick={() => run(onReleaseCaptivePortal)}
          disabled={loading}
          className="flex items-center justify-center gap-2 w-full py-2.5 px-4 rounded-lg text-xs border border-amber-500/40 bg-amber-500/10 text-amber-600 dark:text-amber-400"
        >
          <DoorOpen className="h-4 w-4" /> Portail validé{captiveGateway ? ` (${captiveGateway})` : ''}
        </button>
      )}

      <div className="mt-auto pt-3 border-t border-slate-200 dark:border-slate-800 flex items-center gap-2">
        {killSwitch.engaged ? <Lock className="h-3 w-3 text-slate-500" /> : <LockOpen className="h-3 w-3 text-slate-500" />}
        <span className="text-[10px] uppercase tracking-widest text-slate-500">Kill-switch</span>
        <div className="flex items-center gap-1.5 ml-auto">
          <span className={`h-1.5 w-1.5 rounded-full ${killSwitch.dot}`} />
          <span className={`text-[10px] font-mono uppercase ${killSwitch.color}`}>{killSwitch.label}</span>
        </div>
      </div>
    </div>
  )
}
