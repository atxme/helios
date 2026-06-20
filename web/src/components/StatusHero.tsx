import { RefreshCw, Shield, ShieldAlert, ShieldOff } from 'lucide-react'
import type { Status, TunnelState } from '../types'

const STATE = {
  up: {
    Icon: Shield,
    label: 'TUNNEL SÉCURISÉ',
    sub: 'Trafic chiffré · Kill-switch levé · Post-quantique',
    color: 'text-emerald-400',
    iconBg: 'bg-emerald-500/10 border-emerald-500/40',
    border: 'border-emerald-500/30',
    card: 'bg-emerald-500/5 animate-glow-emerald',
    dot: 'bg-emerald-400 animate-pulse',
    iconAnim: '',
  },
  rekeying: {
    Icon: RefreshCw,
    label: 'RENOUVELLEMENT IKE',
    sub: 'Nouvelle session en cours · Trafic maintenu',
    color: 'text-amber-400',
    iconBg: 'bg-amber-500/10 border-amber-500/40',
    border: 'border-amber-500/30',
    card: 'bg-amber-500/5',
    dot: 'bg-amber-400 animate-pulse',
    iconAnim: 'animate-spin',
  },
  connecting: {
    Icon: Shield,
    label: 'ÉTABLISSEMENT',
    sub: 'Négociation IKEv2 + ML-KEM-768 en cours · Kill-switch actif',
    color: 'text-sky-400',
    iconBg: 'bg-sky-500/10 border-sky-500/40',
    border: 'border-sky-500/30',
    card: 'bg-sky-500/5',
    dot: 'bg-sky-400 animate-pulse',
    iconAnim: 'animate-pulse',
  },
  down: {
    Icon: ShieldOff,
    label: 'HORS LIGNE',
    sub: 'Kill-switch engagé · Aucun trafic autorisé',
    color: 'text-slate-500',
    iconBg: 'bg-slate-800 border-slate-700',
    border: 'border-slate-700/50',
    card: 'bg-slate-900/60',
    dot: 'bg-slate-600',
    iconAnim: '',
  },
  failed: {
    Icon: ShieldAlert,
    label: 'ÉCHEC DE CONNEXION',
    sub: 'Impossible de joindre le pair · Kill-switch engagé',
    color: 'text-red-400',
    iconBg: 'bg-red-500/10 border-red-500/40',
    border: 'border-red-500/30',
    card: 'bg-red-500/5',
    dot: 'bg-red-500',
    iconAnim: '',
  },
} satisfies Record<TunnelState, {
  Icon: React.ElementType
  label: string
  sub: string
  color: string
  iconBg: string
  border: string
  card: string
  dot: string
  iconAnim: string
}>

interface Props {
  state: TunnelState
  status: Status | null
}

export function StatusHero({ state, status }: Props) {
  const s = STATE[state]
  const { Icon } = s
  const conn = status?.connections[0]

  return (
    <div className={`rounded-xl border p-5 transition-all duration-700 ${s.border} ${s.card}`}>
      <div className="flex items-center gap-4">
        {/* Icône d'état */}
        <div className={`shrink-0 rounded-xl p-3 border ${s.iconBg}`}>
          <Icon className={`h-7 w-7 ${s.color} ${s.iconAnim}`} strokeWidth={1.5} />
        </div>

        {/* Texte principal */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <span className={`h-2 w-2 rounded-full shrink-0 ${s.dot}`} />
            <span className={`font-bold tracking-[0.12em] text-sm ${s.color}`}>
              {s.label}
            </span>
          </div>
          <p className="text-slate-500 text-xs truncate">{s.sub}</p>
        </div>

        {/* Proposition cryptographique */}
        {conn && (
          <div className="hidden md:block shrink-0 text-right border-l border-slate-800 pl-4">
            <p className="text-slate-600 text-[10px] uppercase tracking-widest mb-1.5">Chiffrement IKE</p>
            <p className="font-mono text-[11px] text-slate-400 leading-relaxed">
              {conn.ike_proposal.split('-').map((part, i) => (
                <span key={i}>
                  {i > 0 && <span className="text-slate-700"> · </span>}
                  {part}
                </span>
              ))}
            </p>
            <p className="text-slate-600 text-[10px] uppercase tracking-widest mt-1.5 mb-1">ESP</p>
            <p className="font-mono text-[11px] text-slate-500">{conn.esp_proposal}</p>
          </div>
        )}
      </div>
    </div>
  )
}
