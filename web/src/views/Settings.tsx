import { Key, Network, Save, Server, Shield, Wifi } from 'lucide-react'
import { useEffect, useState } from 'react'
import type { Status } from '../types'

interface Props {
  status: Status | null
  onSplitTunnelChange: (cidrs: string[]) => Promise<void>
}

export function SettingsView({ status, onSplitTunnelChange }: Props) {
  const [routes, setRoutes] = useState('')
  const [saving, setSaving] = useState(false)
  const [feedback, setFeedback] = useState<string | null>(null)

  useEffect(() => {
    setRoutes(status?.split_tunnel_cidrs.join('\n') ?? '')
  }, [status?.split_tunnel_cidrs])

  if (!status) return <div className="card h-48 max-w-4xl animate-pulse" />

  const save = async () => {
    setSaving(true)
    setFeedback(null)
    const cidrs = routes.split(/[\n,]/).map(value => value.trim()).filter(Boolean)
    try {
      await onSplitTunnelChange(cidrs)
      setFeedback('Routes de split-tunnel transmises à l’orchestrateur')
    } catch {
      setFeedback('Échec de la mise à jour des routes de split-tunnel')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="space-y-4 max-w-4xl">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-sm font-semibold text-slate-900 dark:text-slate-200 tracking-wide">Paramètres</h1>
          <p className="text-xs text-slate-500 mt-0.5">Configuration résolue de la gateway WireGuard</p>
        </div>
        <span className="text-[10px] text-slate-500 font-mono">v{status.version}</span>
      </div>

      {status.dry_run && (
        <div className="rounded-xl border border-amber-500/20 bg-amber-500/10 p-4 flex items-center gap-3">
          <Key className="h-4 w-4 text-amber-500" strokeWidth={1.5} />
          <div>
            <div className="text-xs font-medium text-amber-600 dark:text-amber-400">Mode simulation</div>
            <div className="text-[11px] text-slate-500">Les backends noyau WireGuard et nftables ne sont pas utilisés.</div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="card p-5 space-y-3">
          <h2 className="hud-title">Gateway</h2>
          <Row icon={Wifi} label="Interface" value={status.wg_iface} />
          <Row icon={Network} label="Port" value={status.wg_listen_port ? `UDP ${status.wg_listen_port}` : 'non ouvert'} />
          <Row
            icon={Network}
            label="Négociation"
            value={status.key_negotiation_port ? `UDP ${status.key_negotiation_port}` : 'inactive'}
          />
          <Row icon={Server} label="Pairs admis" value={String(status.peers.length)} />
          <Row icon={Shield} label="MSS clamp" value={status.mss_clamp ? `${status.mss_clamp}` : 'automatique / absent'} />
        </div>
        <div className="card p-5 space-y-3">
          <h2 className="hud-title">Administration</h2>
          <Row icon={Network} label="WAN" value={status.wan_iface} />
          <Row icon={Network} label="LAN" value={status.lan_ifaces.join(', ') || '—'} />
          <Row icon={Shield} label="SSH autorisé" value={status.allow_ssh_from.join(', ') || 'aucun'} />
          <Row icon={Wifi} label="Portail" value={status.captive_portal_gateway ?? 'absent'} />
        </div>
      </div>

      <div className="card p-5 space-y-3">
        <div>
          <h2 className="hud-title">Split-tunneling dynamique</h2>
          <p className="text-[11px] text-slate-500 mt-1">Un CIDR par ligne. Une liste vide désactive les routes de contournement.</p>
        </div>
        <textarea
          value={routes}
          onChange={event => setRoutes(event.target.value)}
          rows={6}
          placeholder={'10.0.0.0/8\n192.168.0.0/16'}
          className="w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-transparent p-3 font-mono text-xs text-slate-700 dark:text-slate-300 focus:outline-none focus:border-cyan-500"
        />
        <div className="flex items-center gap-3">
          <button onClick={() => void save()} disabled={saving} className="flex items-center gap-2 px-3 py-2 rounded-lg border border-cyan-500/40 bg-cyan-500/10 text-xs text-cyan-700 dark:text-cyan-300 disabled:opacity-40">
            <Save className="h-3.5 w-3.5" /> {saving ? 'Envoi…' : 'Appliquer'}
          </button>
          {feedback && <span className="text-[11px] text-emerald-600 dark:text-emerald-400">{feedback}</span>}
        </div>
      </div>

      <p className="text-[11px] text-slate-500">
        Les secrets WireGuard et la liste d’admission se modifient dans <span className="font-mono">/var/lib/helios/network.toml</span> ou via l’API réseau ; ils ne sont volontairement pas affichés ici.
      </p>
    </div>
  )
}

function Row({ icon: Icon, label, value }: { icon: React.ElementType; label: string; value: string }) {
  return (
    <div className="flex items-center gap-3 py-2 border-b border-slate-200/60 dark:border-slate-800/60 last:border-0">
      <Icon className="h-3.5 w-3.5 text-slate-500" strokeWidth={1.5} />
      <span className="text-[10px] uppercase tracking-wider text-slate-500 w-24">{label}</span>
      <span className="font-mono text-xs text-slate-700 dark:text-slate-300 truncate">{value}</span>
    </div>
  )
}
