import { KeyRound, Network, RadioTower, ShieldCheck, ShieldOff } from 'lucide-react'
import type { Status, TunnelState } from '../types'

function shortKey(key: string): string {
  if (key.length <= 20) return key
  return `${key.slice(0, 10)}…${key.slice(-8)}`
}

export function WireGuardView({ status, currentState }: { status: Status | null; currentState: TunnelState }) {
  return (
    <div className="space-y-4 max-w-4xl">
      <div>
        <h1 className="text-sm font-semibold text-slate-900 dark:text-slate-200 tracking-wide">WireGuard</h1>
        <p className="text-xs text-slate-500 mt-0.5">Interface serveur, admission des clients et protection post-quantique</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <Info icon={RadioTower} label="Interface" value={status?.wg_iface || '—'} />
        <Info icon={Network} label="Écoute" value={status?.wg_listen_port ? `UDP ${status.wg_listen_port}` : 'fermée'} />
        <Info icon={currentState === 'up' ? ShieldCheck : ShieldOff} label="État" value={currentState} />
      </div>

      <div className="card overflow-hidden">
        <div className="px-5 py-3 border-b border-slate-200/60 dark:border-slate-800/60">
          <h2 className="hud-title">Clients admis ({status?.peers.length ?? 0})</h2>
        </div>
        {!status ? (
          <p className="p-5 text-xs text-slate-500 animate-pulse">Chargement…</p>
        ) : status.peers.length === 0 ? (
          <div className="p-8 text-center text-xs text-slate-500">
            Aucun pair déclaré dans <span className="font-mono">network.toml</span>.
          </div>
        ) : (
          <div className="divide-y divide-slate-200/60 dark:divide-slate-800/60">
            {status.peers.map(peer => (
              <div key={peer.public_key} className="p-4 flex flex-wrap items-center gap-3">
                <KeyRound className="h-4 w-4 text-slate-500" strokeWidth={1.5} />
                <div className="min-w-0 flex-1">
                  <div className="text-xs font-medium text-slate-800 dark:text-slate-200">{peer.name}</div>
                  <div className="text-[10px] font-mono text-slate-500" title={peer.public_key}>{shortKey(peer.public_key)}</div>
                </div>
                <span className="text-[10px] font-mono text-slate-600 dark:text-slate-300">{peer.address}</span>
                <span className={`text-[10px] px-2 py-0.5 rounded border ${peer.post_quantum
                  ? 'border-violet-500/40 text-violet-600 dark:text-violet-400 bg-violet-500/5'
                  : 'border-slate-300 dark:border-slate-700 text-slate-500'}`}
                >
                  {peer.post_quantum ? 'PSK post-quantique' : 'WireGuard classique'}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="card overflow-hidden">
        <div className="px-5 py-3 border-b border-slate-200/60 dark:border-slate-800/60">
          <h2 className="hud-title">Enrôlement</h2>
          <p className="mt-0.5 text-[11px] text-slate-500">
            <span className="font-mono">POST /api/provision</span> — joignable uniquement à travers
            le tunnel, comme le reste de cette interface.
          </p>
        </div>

        <dl className="px-5 py-4 grid grid-cols-1 sm:grid-cols-3 gap-4">
          <Field label="Échange de clés" value="ML-KEM-768" note="Le secret alimente le slot PresharedKey de WireGuard, sans toucher au handshake." />
          <Field label="Plage d’adressage" value="100.64.0.0/10" note="VIP CGNAT dérivée de la clé publique du pair. Aucun état sur disque." />
          <Field label="Durée de vie du PSK" value="3600 s" note="Au-delà, le client redemande un PSK par un nouvel échange." />
        </dl>

        <div className="border-t border-slate-200/60 dark:border-slate-800/60 px-5 py-3.5 space-y-2.5 text-[11px] leading-relaxed text-slate-500">
          <p>
            <strong className="text-slate-600 dark:text-slate-400">L’admission reste hors bande.</strong>{' '}
            La clé publique du client doit figurer dans <span className="font-mono">network.toml</span> ;
            le provisioning n’étend jamais cette liste, il ne fait que servir les pairs déjà déclarés.
          </p>
          <p>
            <strong className="text-amber-600 dark:text-amber-400">Chantier ouvert.</strong> Le PSK est
            bien dérivé et renvoyé au client, mais son <em>installation sur le pair côté plan de données</em>{' '}
            n’est pas encore câblée — elle doit passer par l’orchestrateur. Tant que ce n’est pas fait,
            un pair marqué « PSK post-quantique » ci-dessus l’est par sa configuration statique, pas par
            un enrôlement.
          </p>
        </div>
      </div>
    </div>
  )
}

function Field({ label, value, note }: { label: string; value: string; note: string }) {
  return (
    <div>
      <dt className="text-[9px] uppercase tracking-widest text-slate-500">{label}</dt>
      <dd className="mt-1 font-mono text-xs text-slate-700 dark:text-slate-300">{value}</dd>
      <p className="mt-1.5 text-[10px] leading-relaxed text-slate-500">{note}</p>
    </div>
  )
}

function Info({ icon: Icon, label, value }: { icon: React.ElementType; label: string; value: string }) {
  return (
    <div className="card p-4 flex items-center gap-3">
      <Icon className="h-4 w-4 text-cyan-600 dark:text-cyan-400" strokeWidth={1.5} />
      <div>
        <div className="text-[9px] uppercase tracking-widest text-slate-500">{label}</div>
        <div className="text-xs font-mono text-slate-700 dark:text-slate-300">{value}</div>
      </div>
    </div>
  )
}
