import { useEffect, useState } from 'react'
import { ArrowDown, ArrowUp, Info, Power, ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'
import type { ClientProfile, TelemetrySample, TunnelState } from '../types'
import { elapsed, formatBps, postureMeta, stateMeta } from '../components/state'
import { Sparkline } from '../components/Sparkline'
import { StatusOrb } from '../components/StatusOrb'

interface Props {
  state: TunnelState
  profile: ClientProfile | null
  upSince: number | null
  telemetry: TelemetrySample | null
  history: TelemetrySample[]
  backend: string
  adapterUp: boolean
  onConnect: () => void
  onDisconnect: () => void
}

const POSTURE_ICON = {
  protected: ShieldCheck,
  held: ShieldQuestion,
  exposed: ShieldAlert,
} as const

export function ConnectView({
  state,
  profile,
  upSince,
  telemetry,
  history,
  backend,
  adapterUp,
  onConnect,
  onDisconnect,
}: Props) {
  const meta = stateMeta(state)
  const posture = postureMeta(state, adapterUp)
  const [now, setNow] = useState(Date.now())

  useEffect(() => {
    if (upSince === null) return
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [upSince])

  const duration = elapsed(upSince, now)
  const pq = Boolean(profile?.preshared_key?.trim())
  const ready = Boolean(profile?.endpoint && profile.private_key && profile.peer_public_key)
  const PostureIcon = POSTURE_ICON[posture.posture]

  return (
    <div className="flex h-full flex-col gap-5 overflow-y-auto px-6 py-6">
      {/* ── Instrument principal ── */}
      <div className="flex flex-col items-center gap-4">
        <StatusOrb state={state} adapterUp={adapterUp} />

        <div className="text-center">
          <div className="text-xl font-semibold tracking-tight" style={{ color: meta.color }}>
            {meta.label}
          </div>
          <div className="mt-1 font-mono text-xs text-slate-400">
            {profile?.endpoint || (profile ? 'endpoint non défini' : 'aucun profil sélectionné')}
          </div>
          {duration && (
            <div className="mt-1 font-mono text-[11px] tabular-nums text-slate-500">{duration}</div>
          )}
        </div>
      </div>

      {/* ── Posture : ce qui protège réellement le poste (ADR-001 §3 bis) ── */}
      <div
        className="flex items-start gap-3 rounded-xl border px-4 py-3"
        style={{ borderColor: `${posture.color}44`, background: `${posture.color}0e` }}
      >
        <PostureIcon size={17} className="mt-0.5 shrink-0" style={{ color: posture.color }} />
        <div className="min-w-0">
          <div className="text-[13px] font-medium" style={{ color: posture.color }}>
            {posture.label}
          </div>
          <p className="mt-0.5 text-[11px] leading-relaxed text-slate-400">{posture.detail}</p>
        </div>
      </div>

      {/* ── Débit ── */}
      {meta.active && <Throughput telemetry={telemetry} history={history} />}

      {/* ── Caractéristiques du profil ── */}
      <div className="grid grid-cols-2 gap-2">
        <Tile
          label="Protection"
          value={pq ? 'PSK post-quantique' : 'WireGuard classique'}
          accent={pq}
          hint={
            pq
              ? 'Le secret ML-KEM-768 alimente le slot PresharedKey — un enregistrement du trafic reste illisible pour un adversaire quantique.'
              : 'Sans PSK, la confidentialité repose sur Curve25519 seul : vulnérable au « récolter maintenant, déchiffrer plus tard ».'
          }
        />
        <Tile label="Adresse virtuelle" value={profile?.address ?? 'assignée à l’enrôlement'} mono />
        <Tile label="Trafic capté" value={profile?.allowed_ips ?? '—'} mono />
        <Tile label="Backend" value={backend || '—'} mono />
      </div>

      {/* ── Action ── */}
      <div className="mt-auto flex flex-col gap-2 pt-1">
        {meta.active || meta.transitioning ? (
          <button
            className="btn flex items-center justify-center gap-2 border border-red-500/30 bg-red-950/50 text-red-200 hover:bg-red-900/60"
            onClick={onDisconnect}
          >
            <Power size={15} />
            {state === 'connecting' ? 'Annuler et démonter' : 'Déconnecter'}
          </button>
        ) : (
          <button
            className="btn flex items-center justify-center gap-2 border border-node/30 bg-node/15 text-node hover:bg-node/25"
            onClick={onConnect}
            disabled={!ready}
          >
            <Power size={15} />
            Connecter
          </button>
        )}

        {!ready && profile && (
          <p className="text-center text-[11px] text-amber-400/80">
            Profil incomplet — endpoint, clé privée et clé publique de la gateway sont requis.
          </p>
        )}

        {/* Le geste que l'invariante fail-open interdit, dit explicitement. */}
        {posture.posture === 'held' && (
          <p className="flex items-start gap-1.5 text-[11px] leading-relaxed text-slate-500">
            <Info size={12} className="mt-0.5 shrink-0" />
            Déconnecter démonte l’adaptateur et rend la route par défaut au trafic en clair. Pour
            relancer une négociation, laissez Orion réessayer.
          </p>
        )}
      </div>
    </div>
  )
}

function Throughput({
  telemetry,
  history,
}: {
  telemetry: TelemetrySample | null
  history: TelemetrySample[]
}) {
  // Échelle commune aux deux séries — voir le doc-comment de Sparkline.
  const ceiling = Math.max(1, ...history.map((s) => Math.max(s.rx_bps, s.tx_bps)))

  return (
    <div className="grid grid-cols-2 gap-2">
      <Series
        icon={ArrowDown}
        label="Réception"
        value={telemetry ? formatBps(telemetry.rx_bps) : '—'}
        points={history.map((s) => s.rx_bps)}
        ceiling={ceiling}
        color="#28e4a0"
      />
      <Series
        icon={ArrowUp}
        label="Émission"
        value={telemetry ? formatBps(telemetry.tx_bps) : '—'}
        points={history.map((s) => s.tx_bps)}
        ceiling={ceiling}
        color="#22d3ee"
      />
    </div>
  )
}

function Series({
  icon: Icon,
  label,
  value,
  points,
  ceiling,
  color,
}: {
  icon: React.ElementType
  label: string
  value: string
  points: number[]
  ceiling: number
  color: string
}) {
  return (
    <div className="rounded-xl border border-white/5 bg-black/20 px-3 pb-1 pt-2.5">
      <div className="flex items-baseline gap-1.5">
        <Icon size={11} style={{ color }} />
        <span className="text-[9px] uppercase tracking-[0.14em] text-slate-500">{label}</span>
        <span className="ml-auto font-mono text-[11px] tabular-nums" style={{ color }}>
          {value}
        </span>
      </div>
      <Sparkline points={points} ceiling={ceiling} color={color} label={label} />
    </div>
  )
}

function Tile({
  label,
  value,
  mono = false,
  accent = false,
  hint,
}: {
  label: string
  value: string
  mono?: boolean
  accent?: boolean
  hint?: string
}) {
  return (
    <div className="rounded-xl border border-white/5 bg-black/20 px-3 py-2.5" title={hint}>
      <div className="text-[9px] uppercase tracking-[0.14em] text-slate-500">{label}</div>
      <div
        className={`mt-1 truncate text-[11px] ${mono ? 'font-mono' : ''} ${
          accent ? 'text-node' : 'text-slate-300'
        }`}
      >
        {value}
      </div>
    </div>
  )
}
