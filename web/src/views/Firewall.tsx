import { Globe, Lock, LockOpen, Network, Server, ShieldAlert, Wifi } from 'lucide-react'
import type { Status, TunnelState } from '../types'

const KILL_SWITCH_ENGAGED: Record<TunnelState, boolean> = {
  up:         false,
  rekeying:   false,
  connecting: true,
  down:       true,
  failed:     true,
}

interface Props {
  status: Status | null
  state: TunnelState
}

function Row({ icon: Icon, label, value }: { icon: React.ElementType; label: string; value: string }) {
  return (
    <div className="flex items-center gap-3 py-2.5 border-b border-slate-800/60 last:border-0">
      <Icon className="h-3.5 w-3.5 text-slate-600 shrink-0" strokeWidth={1.5} />
      <span className="text-slate-500 text-xs w-24 shrink-0 uppercase tracking-wider">{label}</span>
      <span className="font-mono text-xs text-slate-300 truncate">{value || '—'}</span>
    </div>
  )
}

export function FirewallView({ status, state }: Props) {
  const engaged = KILL_SWITCH_ENGAGED[state]

  return (
    <div className="space-y-4 max-w-4xl">

      <div>
        <h1 className="text-sm font-semibold text-slate-200 tracking-wide">Pare-feu · Kill-switch</h1>
        <p className="text-xs text-slate-500 mt-0.5">Architecture fail-closed — DROP par défaut, trafic autorisé uniquement via ESP/XFRM</p>
      </div>

      {/* Carte kill-switch — état visuel fort */}
      <div className={`rounded-xl border p-6 transition-all duration-700 ${
        engaged
          ? 'border-red-500/30 bg-red-500/5'
          : 'border-emerald-500/30 bg-emerald-500/5 animate-glow-emerald'
      }`}>
        <div className="flex items-center gap-4">
          <div className={`shrink-0 rounded-xl p-3 border ${
            engaged ? 'bg-red-500/10 border-red-500/40' : 'bg-emerald-500/10 border-emerald-500/40'
          }`}>
            {engaged
              ? <Lock     className="h-6 w-6 text-red-400"     strokeWidth={1.5} />
              : <LockOpen className="h-6 w-6 text-emerald-400" strokeWidth={1.5} />
            }
          </div>
          <div>
            <div className={`font-bold tracking-[0.12em] text-sm mb-1 ${engaged ? 'text-red-400' : 'text-emerald-400'}`}>
              {engaged ? 'KILL-SWITCH ENGAGÉ' : 'KILL-SWITCH LEVÉ'}
            </div>
            <p className="text-slate-500 text-xs">
              {engaged
                ? 'Tout trafic est bloqué — aucune fuite réseau possible hors du tunnel ESP'
                : 'Trafic autorisé via ESP/XFRM · Chiffrement actif sur toutes les interfaces LAN'
              }
            </p>
          </div>
          <div className="ml-auto shrink-0">
            <span className={`text-[10px] font-mono uppercase tracking-widest px-2 py-1 rounded border ${
              engaged
                ? 'border-red-500/30 text-red-400 bg-red-500/5'
                : 'border-emerald-500/30 text-emerald-400 bg-emerald-500/5'
            }`}>
              {state.toUpperCase()}
            </span>
          </div>
        </div>
      </div>

      {/* Politique pare-feu */}
      <div className="rounded-xl bg-slate-900/60 border border-slate-800 p-5">
        <h2 className="text-[10px] font-medium uppercase tracking-[0.15em] text-slate-500 mb-3">
          Politique appliquée
        </h2>
        {status ? (
          <>
            <Row icon={Globe}   label="WAN"          value={status.wan_iface} />
            <Row icon={Network} label="LAN protégé"  value={status.lan_ifaces.join(', ')} />
            <Row icon={Wifi}    label="IKE peers"    value={status.ike_peers.join(', ')} />
            <Row icon={Server}  label="Connexions"   value={`${status.connections.length} IKEv2`} />
          </>
        ) : (
          <p className="text-slate-600 text-xs animate-pulse">Chargement…</p>
        )}
      </div>

      {/* Résumé des règles nftables */}
      <div className="rounded-xl bg-slate-900/60 border border-slate-800 p-5">
        <h2 className="text-[10px] font-medium uppercase tracking-[0.15em] text-slate-500 mb-3">
          Règles nftables (résumé)
        </h2>
        <div className="font-mono text-[11px] text-slate-400 space-y-1.5 leading-relaxed">
          <div><span className="text-slate-600">table inet helios_kill</span></div>
          <div className="ml-4"><span className="text-slate-600">chain forward</span> <span className="text-red-400/70">{ }policy DROP</span></div>
          <div className="ml-8 text-slate-500">ip protocol esp  <span className="text-emerald-400/70">accept</span>
            {status?.ike_peers.length ? <span className="text-slate-600"> # {status.ike_peers.join(', ')}</span> : null}
          </div>
          <div className="ml-8 text-slate-500">udp dport 500,4500 <span className="text-emerald-400/70">accept</span>   <span className="text-slate-600"># IKEv2 NAT-T</span></div>
          <div className="ml-8 text-slate-500">udp dport 53       <span className="text-emerald-400/70">accept</span>   <span className="text-slate-600"># DNS local</span></div>
          <div className="ml-8 text-slate-500"><span className="text-slate-700">/* tout le reste → DROP */</span></div>
        </div>
      </div>

      {/* Placeholder compteurs */}
      <div className="rounded-xl border border-slate-800/50 border-dashed p-5">
        <div className="flex items-center gap-2 mb-2">
          <ShieldAlert className="h-3.5 w-3.5 text-slate-700" strokeWidth={1.5} />
          <h2 className="text-[10px] font-medium uppercase tracking-[0.15em] text-slate-700">
            Compteurs de paquets rejetés
          </h2>
        </div>
        <p className="text-xs text-slate-700 italic">
          Disponible sur cible — nécessite la lecture des compteurs nftables via Netlink
        </p>
      </div>
    </div>
  )
}
