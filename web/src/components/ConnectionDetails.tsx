import { Globe, Network, RadioTower, Server, Wifi } from 'lucide-react'
import type { Status } from '../types'

function Row({ icon: Icon, label, value }: { icon: React.ElementType; label: string; value: string | string[] }) {
  const display = Array.isArray(value) ? value.join(', ') || '—' : value || '—'
  return (
    <div className="flex items-start gap-3 py-2.5 border-b border-slate-200/60 dark:border-slate-800/60 last:border-0">
      <Icon className="h-3.5 w-3.5 text-slate-500 mt-0.5 shrink-0" strokeWidth={1.5} />
      <span className="text-slate-500 text-xs w-24 shrink-0 uppercase tracking-wider">{label}</span>
      <span className="text-slate-700 dark:text-slate-300 text-xs truncate font-mono">{display}</span>
    </div>
  )
}

export function ConnectionDetails({ status }: { status: Status | null }) {
  if (!status) return <div className="panel hud p-5 text-xs text-slate-500 animate-pulse">Chargement du réseau…</div>
  return (
    <div className="panel hud p-5 space-y-1">
      <h2 className="hud-title mb-3">Réseau WireGuard</h2>
      <Row icon={Globe} label="WAN" value={status.wan_iface} />
      <Row icon={Network} label="LAN" value={status.lan_ifaces} />
      <Row icon={RadioTower} label="Interface" value={status.wg_iface} />
      <Row icon={Wifi} label="Port" value={status.wg_listen_port ? `UDP ${status.wg_listen_port}` : 'non ouvert'} />
      <Row icon={Server} label="Pairs admis" value={`${status.peers.length}`} />
      <Row icon={Network} label="Site-à-site" value={status.wg_peers} />
      {status.mss_clamp && <Row icon={Network} label="MSS clamp" value={`${status.mss_clamp} octets`} />}
    </div>
  )
}
