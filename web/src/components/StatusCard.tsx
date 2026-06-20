import type { Status, TunnelState } from '../types'

const STATE_STYLE: Record<TunnelState, { dot: string; badge: string; label: string }> = {
  up:         { dot: 'bg-emerald-400 animate-pulse', badge: 'bg-emerald-500/15 text-emerald-400 ring-emerald-500/30', label: 'Connecté' },
  rekeying:   { dot: 'bg-amber-400 animate-pulse',  badge: 'bg-amber-500/15  text-amber-400  ring-amber-500/30',  label: 'Renouvellement' },
  connecting: { dot: 'bg-amber-400 animate-pulse',  badge: 'bg-amber-500/15  text-amber-400  ring-amber-500/30',  label: 'Connexion...' },
  down:       { dot: 'bg-slate-500',                badge: 'bg-slate-500/15  text-slate-400  ring-slate-500/30',  label: 'Hors ligne' },
  failed:     { dot: 'bg-red-500',                  badge: 'bg-red-500/15    text-red-400    ring-red-500/30',    label: 'Erreur' },
}

interface Props {
  status: Status | null
}

export function StatusCard({ status }: Props) {
  const state = status?.state ?? 'down'
  const s = STATE_STYLE[state]

  return (
    <div className="rounded-xl bg-slate-900 border border-slate-800 p-6 space-y-5">
      <div className="flex items-center justify-between">
        <h2 className="text-slate-300 text-sm font-medium uppercase tracking-wider">Tunnel VPN</h2>
        {status?.dry_run && (
          <span className="text-xs px-2 py-0.5 rounded-full bg-violet-500/15 text-violet-400 ring-1 ring-violet-500/30">
            dry-run
          </span>
        )}
      </div>

      <div className="flex items-center gap-3">
        <span className={`h-3 w-3 rounded-full ${s.dot}`} />
        <span className={`text-sm font-semibold px-3 py-1 rounded-full ring-1 ${s.badge}`}>
          {s.label}
        </span>
      </div>

      {status && (
        <dl className="space-y-2 text-sm">
          <Row label="WAN" value={status.wan_iface} />
          <Row label="LAN" value={status.lan_ifaces.join(', ') || '—'} />
          <Row label="Pairs IKE" value={status.ike_peers.join(', ') || '—'} />
          {status.connections.map(c => (
            <Row key={c.name} label={c.name} value={c.remote_addr} />
          ))}
        </dl>
      )}

      {!status && (
        <p className="text-slate-500 text-sm">Chargement…</p>
      )}
    </div>
  )
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex justify-between gap-4">
      <dt className="text-slate-500 shrink-0">{label}</dt>
      <dd className="text-slate-300 text-right font-mono text-xs truncate">{value}</dd>
    </div>
  )
}
