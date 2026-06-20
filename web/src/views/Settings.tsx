import { Cpu, ExternalLink, Key, Server, Zap } from 'lucide-react'
import type { ConnectionSummary, ProfileSummary, Status } from '../types'

interface Props {
  status: Status | null
}

function parsePqc(proposal: string): { parts: string[]; hasPqc: boolean } {
  const parts = proposal.split('-')
  const hasPqc = parts.some(p => p.includes('mlkem') || p.includes('kyber'))
  return { parts, hasPqc }
}

function ConnectionCard({ conn, activeProfileId, profiles }: {
  conn: ConnectionSummary
  activeProfileId: string | null
  profiles: ProfileSummary[]
}) {
  const ike = parsePqc(conn.ike_proposal)
  // Defensive: profiles may be undefined if API is old
  const safeProfiles = profiles ?? []
  const matchedProfile = safeProfiles.find(p => p.id === (activeProfileId ?? ''))

  return (
    <div className="card p-5 space-y-4">
      {/* En-tête connexion */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="h-8 w-8 rounded-lg bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 flex items-center justify-center shrink-0">
            <Server className="h-4 w-4 text-slate-500 dark:text-slate-400" strokeWidth={1.5} />
          </div>
          <div>
            <div className="text-sm font-semibold text-slate-800 dark:text-slate-200">{conn.name}</div>
            <div className="font-mono text-xs text-slate-500">{conn.remote_addr}</div>
          </div>
        </div>
        {ike.hasPqc && (
          <span className="shrink-0 text-[10px] px-2 py-0.5 rounded border border-violet-500/30 bg-violet-500/8 text-violet-600 dark:text-violet-400 font-mono uppercase flex items-center gap-1">
            <Zap className="h-2.5 w-2.5" strokeWidth={2} />Post-quantique
          </span>
        )}
      </div>

      {/* Profil actif détecté */}
      {matchedProfile && (
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-emerald-500/5 border border-emerald-500/20">
          <Zap className="h-3 w-3 text-emerald-600 dark:text-emerald-400 shrink-0" strokeWidth={1.5} />
          <span className="text-[10px] uppercase tracking-widest text-slate-500">Profil actif</span>
          <span className="text-xs font-medium text-emerald-700 dark:text-emerald-400 ml-1">{matchedProfile.name}</span>
          {matchedProfile.reserved && (
            <span className="ml-auto text-[10px] text-amber-600 dark:text-amber-400 font-mono">réservé</span>
          )}
        </div>
      )}

      {/* Proposition IKE */}
      <div>
        <div className="text-[10px] uppercase tracking-widest text-slate-400 dark:text-slate-600 mb-2">Proposition IKE</div>
        <div className="flex flex-wrap gap-1.5">
          {ike.parts.map((part, i) => {
            const isPqc = part.includes('mlkem') || part.includes('kyber')
            const isKem = part.startsWith('ke') && !isPqc
            return (
              <span key={i} className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                isPqc
                  ? 'border-violet-500/40 bg-violet-500/8 text-violet-600 dark:text-violet-400'
                  : isKem
                  ? 'border-sky-500/30 bg-sky-500/8 text-sky-600 dark:text-sky-400'
                  : 'border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800/50 text-slate-600 dark:text-slate-400'
              }`}>
                {part}
              </span>
            )
          })}
        </div>
      </div>

      {/* Proposition ESP */}
      <div>
        <div className="text-[10px] uppercase tracking-widest text-slate-400 dark:text-slate-600 mb-2">Proposition ESP</div>
        <div className="flex flex-wrap gap-1.5">
          {conn.esp_proposal.split('-').map((part, i) => (
            <span key={i} className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-slate-200 dark:border-slate-700 bg-slate-100 dark:bg-slate-800/50 text-slate-600 dark:text-slate-400">
              {part}
            </span>
          ))}
        </div>
      </div>

      {/* IDs */}
      {(conn.local_id || conn.remote_id) && (
        <div className="pt-3 border-t border-slate-200 dark:border-slate-800 grid grid-cols-2 gap-3">
          {conn.local_id && (
            <div>
              <div className="text-[10px] uppercase tracking-widest text-slate-400 dark:text-slate-600 mb-1">Local ID</div>
              <div className="font-mono text-[11px] text-slate-600 dark:text-slate-400 truncate">{conn.local_id}</div>
            </div>
          )}
          {conn.remote_id && (
            <div>
              <div className="text-[10px] uppercase tracking-widest text-slate-400 dark:text-slate-600 mb-1">Remote ID</div>
              <div className="font-mono text-[11px] text-slate-600 dark:text-slate-400 truncate">{conn.remote_id}</div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export function SettingsView({ status }: Props) {
  if (!status) {
    return (
      <div className="space-y-4 max-w-4xl animate-pulse">
        {[1, 2].map(i => (
          <div key={i} className="card h-48" />
        ))}
      </div>
    )
  }

  const safeProfiles: ProfileSummary[] = status.profiles ?? []
  const hasPqc = status.connections.some(c => parsePqc(c.ike_proposal).hasPqc)

  return (
    <div className="space-y-4 max-w-4xl">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-sm font-semibold text-slate-900 dark:text-slate-200 tracking-wide">Paramètres</h1>
          <p className="text-xs text-slate-500 mt-0.5">Profils IKEv2 configurés · Lecture seule (éditez helios.toml pour modifier)</p>
        </div>
        <div className="flex items-center gap-2">
          {hasPqc && (
            <div className="flex items-center gap-1.5 text-[10px] text-violet-600 dark:text-violet-400 font-mono">
              <Cpu className="h-3 w-3" strokeWidth={1.5} />ML-KEM actif
            </div>
          )}
          <span className="text-[10px] text-slate-400 dark:text-slate-600 font-mono">v{status.version}</span>
        </div>
      </div>

      {/* Mode dry-run */}
      {status.dry_run && (
        <div className="rounded-xl border border-amber-500/20 bg-amber-500/10 backdrop-blur-md p-4 flex items-center gap-3">
          <Key className="h-4 w-4 text-amber-500 dark:text-amber-400 shrink-0" strokeWidth={1.5} />
          <div>
            <div className="text-xs font-medium text-amber-600 dark:text-amber-400">Mode simulation</div>
            <div className="text-[11px] text-slate-500 mt-0.5">
              Le daemon tourne en <span className="font-mono">dry_run = true</span> — aucune écriture kernel
            </div>
          </div>
        </div>
      )}

      {/* Connexions */}
      {status.connections.length === 0 ? (
        <div className="card border-dashed p-8 text-center">
          <ExternalLink className="h-5 w-5 text-slate-300 dark:text-slate-700 mx-auto mb-2" strokeWidth={1.5} />
          <p className="text-xs text-slate-500">Aucune connexion configurée</p>
          <p className="text-[11px] text-slate-400 dark:text-slate-600 mt-1">
            Ajoutez <span className="font-mono">[[connections]]</span> dans helios.toml
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {status.connections.map(c => (
            <ConnectionCard
              key={c.name}
              conn={c}
              activeProfileId={status.active_profile ?? null}
              profiles={safeProfiles}
            />
          ))}
        </div>
      )}

      {/* Profils disponibles */}
      {safeProfiles.length > 0 && (
        <div className="card p-5">
          <h2 className="text-[10px] font-medium uppercase tracking-[0.15em] text-slate-500 mb-3">
            Profils IKEv2 disponibles
          </h2>
          <div className="space-y-2">
            {safeProfiles.map(p => (
              <div key={p.id} className="flex items-center gap-3 py-2 border-b border-slate-200/60 dark:border-slate-800/60 last:border-0">
                <span className="font-mono text-[10px] text-slate-400 dark:text-slate-600 w-20 shrink-0">{p.id}</span>
                <span className="text-xs text-slate-700 dark:text-slate-300 font-medium">{p.name}</span>
                {p.reserved && (
                  <span className="text-[10px] font-mono text-amber-600 dark:text-amber-400 border border-amber-500/30 px-1.5 py-0.5 rounded">réservé</span>
                )}
                <span className={`ml-auto text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                  p.pqc_level === 'None'
                    ? 'border-slate-200 dark:border-slate-700 text-slate-500'
                    : p.pqc_level.includes('Strict')
                    ? 'border-fuchsia-500/40 text-fuchsia-600 dark:text-fuchsia-400 bg-fuchsia-500/5'
                    : 'border-violet-500/40 text-violet-600 dark:text-violet-400 bg-violet-500/5'
                }`}>
                  {p.pqc_level === 'None' ? 'Classique' : p.pqc_level}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
