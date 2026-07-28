import { AlertTriangle, Globe, Lock, LockOpen, Network, RefreshCw, Save, Server, ShieldAlert, Terminal, Wifi } from 'lucide-react'
import { useEffect, useState } from 'react'
import { applyFirewallRules, fetchFirewallRules } from '../api'
import type { Status, TunnelState } from '../types'

const KILL_SWITCH_ENGAGED: Record<TunnelState, boolean> = {
  up: false,
  connecting: true,
  down: true,
  failed: true,
  captive_portal: true,
}

interface Props {
  status: Status | null
  state: TunnelState
}

function Row({ icon: Icon, label, value }: { icon: React.ElementType; label: string; value: string }) {
  return (
    <div className="flex items-center gap-3 py-2.5 border-b border-slate-200/60 dark:border-slate-800/60 last:border-0">
      <Icon className="h-3.5 w-3.5 text-slate-500 dark:text-slate-400 shrink-0" strokeWidth={1.5} />
      <span className="text-slate-500 text-xs w-24 shrink-0 uppercase tracking-wider">{label}</span>
      <span className="font-mono text-xs text-slate-700 dark:text-slate-300 truncate">{value || '—'}</span>
    </div>
  )
}

function NftablesEditor({ dryRun }: { dryRun: boolean }) {
  const [rules, setRules]       = useState('')
  const [original, setOriginal] = useState('')
  const [loading, setLoading]   = useState(true)
  const [saving, setSaving]     = useState(false)
  const [feedback, setFeedback] = useState<{ ok: boolean; msg: string } | null>(null)
  const dirty = rules !== original

  useEffect(() => {
    fetchFirewallRules()
      .then(r => { setRules(r.rules); setOriginal(r.rules) })
      .catch(() => setRules('# Impossible de charger les règles'))
      .finally(() => setLoading(false))
  }, [])

  const save = async () => {
    setSaving(true); setFeedback(null)
    try {
      await applyFirewallRules(rules)
      setOriginal(rules)
      setFeedback({
        ok: true,
        msg: dryRun
          ? 'Reçu en simulation — aucune application kernel'
          : 'Commande reçue — l’application de rulesets bruts reste à câbler dans l’orchestrateur',
      })
    } catch {
      setFeedback({ ok: false, msg: 'Erreur lors de l\'envoi' })
    } finally {
      setSaving(false) }
  }

  return (
    <div className="card overflow-hidden">
      <div className="flex items-center gap-2 px-5 py-3 border-b border-slate-200/60 dark:border-slate-800/60 bg-slate-50/60 dark:bg-slate-950/40">
        <Terminal className="h-3.5 w-3.5 text-slate-500 dark:text-slate-400" strokeWidth={1.5} />
        <span className="text-[10px] font-medium uppercase tracking-[0.15em] text-slate-500">Ruleset nftables · expérimental</span>
        {dirty && (
          <span className="ml-2 text-[10px] text-amber-600 dark:text-amber-400 font-mono">● modifié</span>
        )}
        <div className="ml-auto flex gap-2">
          <button
            onClick={() => { setRules(original); setFeedback(null) }}
            disabled={!dirty || saving}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded text-[10px] border
              border-slate-300 dark:border-slate-700 text-slate-500
              hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors
              disabled:opacity-30 disabled:cursor-not-allowed"
          >
            <RefreshCw className="h-3 w-3" strokeWidth={2} />
            Réinitialiser
          </button>
          <button
            onClick={save}
            disabled={!dirty || saving}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded text-[10px] border
              border-emerald-600/50 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400
              hover:bg-emerald-500/20 transition-colors
              disabled:opacity-30 disabled:cursor-not-allowed"
          >
            <Save className="h-3 w-3" strokeWidth={2} />
            {saving ? 'Envoi…' : 'Transmettre'}
          </button>
        </div>
      </div>

      {dryRun && (
        <div className="flex items-center gap-2 px-5 py-2 border-b border-amber-500/20 bg-amber-500/5 text-xs text-amber-600 dark:text-amber-400">
          <AlertTriangle className="h-3 w-3 shrink-0" strokeWidth={1.5} />
          Mode simulation — les règles seront journalisées mais non appliquées au kernel
        </div>
      )}

      {!dryRun && (
        <div className="flex items-center gap-2 px-5 py-2 border-b border-amber-500/20 bg-amber-500/5 text-xs text-amber-600 dark:text-amber-400">
          <AlertTriangle className="h-3 w-3 shrink-0" strokeWidth={1.5} />
          Le rendu reflète la politique structurée ; l’application de texte nftables personnalisé n’est pas encore implémentée.
        </div>
      )}

      {loading ? (
        <div className="p-5">
          <div className="h-3 w-48 rounded bg-slate-200 dark:bg-slate-800 animate-pulse mb-2" />
          <div className="h-3 w-64 rounded bg-slate-200 dark:bg-slate-800 animate-pulse mb-2" />
          <div className="h-3 w-40 rounded bg-slate-200 dark:bg-slate-800 animate-pulse" />
        </div>
      ) : (
        <textarea
          value={rules}
          onChange={e => { setRules(e.target.value); setFeedback(null) }}
          className="w-full font-mono text-[11px] p-5 bg-transparent text-slate-700 dark:text-slate-300
            focus:outline-none resize-none leading-relaxed"
          rows={14}
          spellCheck={false}
        />
      )}

      {feedback && (
        <div className={`px-5 py-2.5 border-t text-xs font-mono ${
          feedback.ok
            ? 'border-emerald-500/20 bg-emerald-500/5 text-emerald-600 dark:text-emerald-400'
            : 'border-red-500/20 bg-red-500/5 text-red-500'
        }`}>
          {feedback.msg}
        </div>
      )}
    </div>
  )
}

export function FirewallView({ status, state }: Props) {
  const engaged = KILL_SWITCH_ENGAGED[state]
  const sshCidrs: string[] = status?.allow_ssh_from ?? []

  return (
    <div className="space-y-4 max-w-4xl">
      <div>
        <h1 className="text-sm font-semibold text-slate-900 dark:text-slate-200 tracking-wide">Pare-feu · Kill-switch</h1>
        <p className="text-xs text-slate-500 mt-0.5">Architecture fail-closed — DROP par défaut, trafic LAN autorisé uniquement tant qu'un handshake WireGuard date de moins de 150 s</p>
      </div>

      {/* Kill-switch card */}
      <div className={`rounded-xl border p-6 backdrop-blur-md transition-all duration-700 ${
        engaged ? 'border-red-500/30 bg-red-500/10' : 'border-emerald-500/30 bg-emerald-500/10 animate-glow-emerald'
      }`}>
        <div className="flex items-center gap-4">
          <div className={`shrink-0 rounded-xl p-3 border ${engaged ? 'bg-red-500/10 border-red-500/40' : 'bg-emerald-500/10 border-emerald-500/40'}`}>
            {engaged
              ? <Lock     className="h-6 w-6 text-red-400"     strokeWidth={1.5} />
              : <LockOpen className="h-6 w-6 text-emerald-400" strokeWidth={1.5} />
            }
          </div>
          <div>
            <div className={`font-bold tracking-[0.12em] text-sm mb-1 ${engaged ? 'text-red-500 dark:text-red-400' : 'text-emerald-600 dark:text-emerald-400'}`}>
              {engaged ? 'KILL-SWITCH ENGAGÉ' : 'KILL-SWITCH LEVÉ'}
            </div>
            <p className="text-slate-500 text-xs">
              {engaged
                ? state === 'captive_portal'
                  ? 'Kill-switch partiel — HTTP/HTTPS limité à la passerelle du portail captif'
                  : 'Trafic LAN bloqué — seuls WireGuard et les exceptions d’administration restent autorisés'
                : 'Trafic LAN autorisé à travers l’interface WireGuard'}
            </p>
          </div>
          <div className="ml-auto shrink-0">
            <span className={`text-[10px] font-mono uppercase tracking-widest px-2 py-1 rounded border ${
              engaged ? 'border-red-500/30 text-red-400 bg-red-500/5' : 'border-emerald-500/30 text-emerald-600 dark:text-emerald-400 bg-emerald-500/5'
            }`}>
              {state.toUpperCase()}
            </span>
          </div>
        </div>
      </div>

      {/* Policy + SSH grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Firewall policy */}
        <div className="card p-5">
          <h2 className="text-[10px] font-medium uppercase tracking-[0.15em] text-slate-500 mb-3">Politique appliquée</h2>
          {status ? (
            <>
              <Row icon={Globe}   label="WAN"          value={status.wan_iface} />
              <Row icon={Network} label="LAN protégé"  value={status.lan_ifaces.join(', ')} />
              <Row icon={Wifi}    label="Écoute WG"     value={status.wg_listen_port ? `UDP ${status.wg_listen_port}` : 'fermée'} />
              <Row icon={Server}  label="Pairs admis"   value={`${status.peers.length}`} />
            </>
          ) : (
            <p className="text-slate-500 dark:text-slate-400 text-xs animate-pulse">Chargement…</p>
          )}
        </div>

        {/* SSH passthrough */}
        <div className="card p-5">
          <h2 className="text-[10px] font-medium uppercase tracking-[0.15em] text-slate-500 mb-3">SSH d'administration</h2>
          {sshCidrs.length === 0 ? (
            <div className="flex items-center gap-2 py-2">
              <Lock className="h-3.5 w-3.5 text-slate-500 dark:text-slate-400 shrink-0" strokeWidth={1.5} />
              <span className="text-xs text-slate-500 italic">
                Bloqué (défaut sécurisé) — configurer <span className="font-mono not-italic">allow_ssh_from</span>
              </span>
            </div>
          ) : (
            <div className="space-y-2">
              {sshCidrs.map(cidr => (
                <div key={cidr} className="flex items-center gap-2">
                  <span className="font-mono text-xs text-slate-700 dark:text-slate-300 bg-slate-100 dark:bg-slate-800/50 px-2 py-0.5 rounded border border-slate-200 dark:border-slate-700">
                    {cidr}
                  </span>
                  <span className="text-[10px] font-mono text-slate-500 dark:text-slate-400 border border-slate-200 dark:border-slate-700 px-1.5 py-0.5 rounded">tcp/22</span>
                  <span className="text-[10px] text-amber-600 dark:text-amber-400 font-mono">toujours actif</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* nftables editor */}
      <NftablesEditor dryRun={status?.dry_run ?? true} />

      {/* Counters placeholder */}
      <div className="rounded-xl border border-slate-200/50 dark:border-slate-800/50 border-dashed p-5">
        <div className="flex items-center gap-2 mb-2">
          <ShieldAlert className="h-3.5 w-3.5 text-slate-500 dark:text-slate-500" strokeWidth={1.5} />
          <h2 className="text-[10px] font-medium uppercase tracking-[0.15em] text-slate-500 dark:text-slate-500">
            Compteurs de paquets rejetés
          </h2>
        </div>
        <p className="text-xs text-slate-500 dark:text-slate-500 italic">
          Disponible sur cible — nécessite la lecture des compteurs nftables via Netlink
        </p>
      </div>
    </div>
  )
}
