import { useState } from 'react'
import type { TunnelState } from '../types'

interface Props {
  state: TunnelState
  onConnect: () => Promise<void>
  onDisconnect: () => Promise<void>
}

export function TunnelControls({ state, onConnect, onDisconnect }: Props) {
  const [loading, setLoading] = useState(false)

  const handle = async (action: () => Promise<void>) => {
    setLoading(true)
    try { await action() } finally { setLoading(false) }
  }

  const isUp = state === 'up' || state === 'rekeying'
  const isTransitioning = state === 'connecting' || loading

  return (
    <div className="rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-4">
      <h2 className="text-slate-300 text-sm font-medium uppercase tracking-wider">Contrôles</h2>

      <div className="flex flex-col gap-3">
        <button
          onClick={() => handle(onConnect)}
          disabled={isUp || isTransitioning}
          className="w-full py-2.5 rounded-lg text-sm font-medium transition-colors
                     bg-emerald-600 hover:bg-emerald-500 text-white
                     disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {isTransitioning && !isUp ? 'Connexion…' : 'Connecter'}
        </button>

        <button
          onClick={() => handle(onDisconnect)}
          disabled={!isUp || isTransitioning}
          className="w-full py-2.5 rounded-lg text-sm font-medium transition-colors
                     bg-slate-700 hover:bg-slate-600 text-slate-200
                     disabled:opacity-40 disabled:cursor-not-allowed"
        >
          Déconnecter
        </button>
      </div>
    </div>
  )
}
