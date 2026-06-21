import { Globe, Network, Server, Wifi } from 'lucide-react'
import type { Status } from '../types'

interface Props {
  status: Status | null
}

function Row({
  icon: Icon,
  label,
  value,
  mono = true,
}: {
  icon: React.ElementType
  label: string
  value: string | string[]
  mono?: boolean
}) {
  const display = Array.isArray(value) ? value.join(', ') || '—' : value || '—'
  return (
    <div className="flex items-start gap-3 py-2.5 border-b border-slate-200/60 dark:border-slate-800/60 last:border-0">
      <Icon className="h-3.5 w-3.5 text-slate-500 dark:text-slate-400 mt-0.5 shrink-0" strokeWidth={1.5} />
      <span className="text-slate-500 text-xs w-20 shrink-0 uppercase tracking-wider">{label}</span>
      <span className={`text-slate-700 dark:text-slate-300 text-xs truncate ${mono ? 'font-mono' : ''}`}>{display}</span>
    </div>
  )
}

function Skeleton() {
  return (
    <div className="panel hud p-5 space-y-3">
      <div className="h-2 w-24 rounded bg-slate-200 dark:bg-slate-800 animate-pulse" />
      {[48, 64, 40].map(w => (
        <div key={w} className="flex items-center gap-3 py-2.5 border-b border-slate-200/60 dark:border-slate-800/60">
          <div className="h-3.5 w-3.5 rounded bg-slate-200 dark:bg-slate-800 animate-pulse shrink-0" />
          <div className="h-2 w-16 rounded bg-slate-200 dark:bg-slate-800 animate-pulse" />
          <div className="h-2 rounded bg-slate-100 dark:bg-slate-800/70 animate-pulse" style={{ width: `${w}%` }} />
        </div>
      ))}
    </div>
  )
}

export function ConnectionDetails({ status }: Props) {
  if (!status) return <Skeleton />

  return (
    <div className="panel hud p-5 space-y-1">
      <h2 className="hud-title mb-3">Interfaces réseau</h2>

      <Row icon={Globe}   label="WAN"    value={status.wan_iface} />
      <Row icon={Network} label="LAN"    value={status.lan_ifaces} />
      <Row icon={Wifi}    label="Pairs"  value={status.ike_peers} />

      {status.connections.length > 0 && (
        <>
          <h2 className="text-[10px] font-medium uppercase tracking-[0.15em] text-slate-500 pt-3 mb-1">
            Connexions IPsec
          </h2>
          {status.connections.map(c => (
            <div key={c.name} className="py-2.5 border-b border-slate-200/60 dark:border-slate-800/60 last:border-0">
              <div className="flex items-center gap-3 mb-1.5">
                <Server className="h-3.5 w-3.5 text-slate-500 dark:text-slate-400 shrink-0" strokeWidth={1.5} />
                <span className="text-slate-700 dark:text-slate-300 text-xs font-medium">{c.name}</span>
                <span className="font-mono text-xs text-slate-500 ml-auto">{c.remote_addr}</span>
              </div>
              <div className="ml-6 space-y-0.5">
                {c.local_id && (
                  <p className="text-[10px] text-slate-500 dark:text-slate-400">
                    <span className="text-slate-500 dark:text-slate-400 uppercase tracking-wider">local </span>
                    <span className="font-mono text-slate-500">{c.local_id}</span>
                  </p>
                )}
                {c.remote_id && (
                  <p className="text-[10px] text-slate-500 dark:text-slate-400">
                    <span className="text-slate-500 dark:text-slate-400 uppercase tracking-wider">remote </span>
                    <span className="font-mono text-slate-500">{c.remote_id}</span>
                  </p>
                )}
              </div>
            </div>
          ))}
        </>
      )}
    </div>
  )
}
