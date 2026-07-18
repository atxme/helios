import { useEffect, useState } from 'react'
import { LockKeyhole, ShieldCheck, ShieldOff, Wifi } from 'lucide-react'
import type { ClientProfile, TelemetrySample, TunnelState } from '../types'
import { elapsed, formatBps, stateMeta } from '../components/state'

interface Props {
  state: TunnelState
  profile: ClientProfile | null
  upSince: number | null
  telemetry: TelemetrySample | null
  backend: string
  adapterUp: boolean
  onConnect: () => void
  onDisconnect: () => void
}

export function ConnectView({
  state,
  profile,
  upSince,
  telemetry,
  backend,
  adapterUp,
  onConnect,
  onDisconnect,
}: Props) {
  const meta = stateMeta(state)
  const [now, setNow] = useState(Date.now())

  // Tick chaque seconde tant que le tunnel est monté (pour la durée).
  useEffect(() => {
    if (upSince === null) return
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [upSince])

  const duration = elapsed(upSince, now)
  const pq = profile ? Boolean(profile.preshared_key?.trim()) : false

  return (
    <div className="flex flex-col items-center gap-5 px-5 py-6">
      {/* Orbe d'état */}
      <div className={`relative grid place-items-center rounded-full ${meta.glow}`}>
        <div
          className={`grid h-28 w-28 place-items-center rounded-full border-2 transition-colors ${
            meta.transitioning ? 'animate-pulse-slow' : ''
          }`}
          style={{ borderColor: meta.color }}
        >
          {meta.active ? (
            <ShieldCheck size={44} style={{ color: meta.color }} />
          ) : (
            <ShieldOff size={44} style={{ color: meta.color }} />
          )}
        </div>
      </div>

      <div className="text-center">
        <div className="text-lg font-semibold" style={{ color: meta.color }}>
          {meta.label}
        </div>
        {profile ? (
          <div className="mt-0.5 font-mono text-xs text-slate-400">
            {profile.endpoint || '— endpoint non défini —'}
          </div>
        ) : (
          <div className="mt-0.5 text-xs text-slate-500">Aucun profil sélectionné</div>
        )}
      </div>

      {/* Détails */}
      {meta.active && (
        <div className="w-full space-y-1.5 rounded-lg bg-black/20 px-4 py-3 text-xs">
          {duration && (
            <Row label="Durée">
              <span className="font-mono">{duration}</span>
            </Row>
          )}
          <Row label="Protection">
            <span>{pq ? <span className="text-node">WireGuard · PSK PQ</span> : 'WireGuard classique'}</span>
          </Row>
          {profile?.address && <Row label="Adresse"><span className="font-mono">{profile.address}</span></Row>}
          <Row label="Débit">
            {telemetry ? (
              <span className="font-mono">
                ↓ {formatBps(telemetry.rx_bps)} &nbsp; ↑ {formatBps(telemetry.tx_bps)}
              </span>
            ) : (
              <span className="text-slate-500">en attente…</span>
            )}
          </Row>
        </div>
      )}

      {/* Bouton d'action */}
      <div className="w-full">
        {meta.active || meta.transitioning ? (
          <button
            className="btn w-full bg-red-950/70 text-red-200 hover:bg-red-900/70"
            onClick={onDisconnect}
          >
            {state === 'connecting' ? 'Annuler et démonter' : 'Déconnecter'}
          </button>
        ) : (
          <button
            className="btn w-full bg-emerald-900/60 text-emerald-200 hover:bg-emerald-800/70"
            onClick={onConnect}
            disabled={!profile || !profile.endpoint || !profile.private_key || !profile.peer_public_key}
          >
            Connecter
          </button>
        )}
      </div>

      <div className="flex items-center gap-1.5 text-[11px] text-slate-500">
        <Wifi size={12} />
        backend : <span className="font-mono text-slate-400">{backend || '—'}</span>
      </div>
      <div className={`flex items-center gap-1.5 text-[11px] ${adapterUp ? 'text-emerald-400' : 'text-slate-500'}`}>
        <LockKeyhole size={12} />
        adaptateur : <span className="font-mono">{adapterUp ? 'monté · routes capturées' : 'démonté'}</span>
      </div>
    </div>
  )
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-slate-400">{label}</span>
      {children}
    </div>
  )
}
