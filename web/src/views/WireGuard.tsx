import { KeyRound, Lock, Network, RadioTower, ShieldCheck, ShieldOff } from 'lucide-react'
import type { ProtectionMode, Status, TunnelState } from '../types'

function shortKey(key: string): string {
  if (key.length <= 20) return key
  return `${key.slice(0, 10)}…${key.slice(-8)}`
}

/**
 * How a floor reads on screen.
 *
 * The floor is not the mode currently in use — the gateway doesn't keep one —
 * it's what this peer can no longer fall back below. Saying "ML-KEM-768"
 * alone would suggest an observed state; the label says "minimum".
 */
const FLOOR: Record<ProtectionMode, { label: string; hint: string; tone: string }> = {
  classic: {
    label: 'plancher : aucun',
    hint: "Ce pair peut encore négocier sans PSK. Le plancher s'élèvera de lui-même à la première négociation aboutie.",
    tone: 'border-slate-300 dark:border-slate-700 text-slate-500',
  },
  static_psk: {
    label: 'plancher : PSK statique',
    hint: 'Une négociation classique est refusée pour ce pair, avant toute pose sur le plan de données.',
    tone: 'border-amber-500/40 text-amber-600 dark:text-amber-400 bg-amber-500/5',
  },
  ml_kem: {
    label: 'plancher : ML-KEM-768',
    hint: 'Ni classique ni PSK statique ne sont acceptés pour ce pair. Seule une édition locale de network.toml peut redescendre ce plancher.',
    tone: 'border-violet-500/40 text-violet-600 dark:text-violet-400 bg-violet-500/5',
  },
}

export function WireGuardView({ status, currentState }: { status: Status | null; currentState: TunnelState }) {
  const negotiation = status?.key_negotiation_port
  return (
    <div className="space-y-4 max-w-4xl">
      <div>
        <h1 className="text-sm font-semibold text-slate-900 dark:text-slate-200 tracking-wide">WireGuard</h1>
        <p className="text-xs text-slate-500 mt-0.5">Interface serveur, admission des clients et protection post-quantique</p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        <Info icon={RadioTower} label="Interface" value={status?.wg_iface || '—'} />
        <Info icon={Network} label="Écoute" value={status?.wg_listen_port ? `UDP ${status.wg_listen_port}` : 'fermée'} />
        <Info icon={Lock} label="Négociation" value={negotiation ? `UDP ${negotiation}` : 'inactive'} />
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
            {status.peers.map(peer => {
              const floor = FLOOR[peer.minimum_key_negotiation_mode] ?? FLOOR.classic
              return (
                <div key={peer.public_key} className="p-4 flex flex-wrap items-center gap-3">
                  <KeyRound className="h-4 w-4 text-slate-500" strokeWidth={1.5} />
                  <div className="min-w-0 flex-1">
                    <div className="text-xs font-medium text-slate-800 dark:text-slate-200">{peer.name}</div>
                    <div className="text-[10px] font-mono text-slate-500" title={peer.public_key}>{shortKey(peer.public_key)}</div>
                  </div>
                  <span className="text-[10px] font-mono text-slate-600 dark:text-slate-300">{peer.address}</span>
                  <span className={`text-[10px] px-2 py-0.5 rounded border ${floor.tone}`} title={floor.hint}>
                    {floor.label}
                  </span>
                  <span className={`text-[10px] px-2 py-0.5 rounded border ${peer.post_quantum
                    ? 'border-violet-500/40 text-violet-600 dark:text-violet-400 bg-violet-500/5'
                    : 'border-slate-300 dark:border-slate-700 text-slate-500'}`}
                    title={peer.post_quantum
                      ? 'Un secret occupe le slot PresharedKey de ce pair. Sa valeur n’est jamais exposée.'
                      : 'Aucun PSK posé : la confidentialité repose sur Curve25519 seul.'}
                  >
                    {peer.post_quantum ? 'slot PSK occupé' : 'slot PSK vide'}
                  </span>
                </div>
              )
            })}
          </div>
        )}
      </div>

      <div className="card overflow-hidden">
        <div className="px-5 py-3 border-b border-slate-200/60 dark:border-slate-800/60">
          <h2 className="hud-title">Négociation de clé</h2>
          <p className="mt-0.5 text-[11px] text-slate-500">
            Port public {negotiation ? <span className="font-mono">UDP {negotiation}</span> : 'non ouvert'} — il ne
            transporte aucun trafic utilisateur, il prépare le slot PSK du <em>premier</em> handshake WireGuard.
          </p>
        </div>

        <dl className="px-5 py-4 grid grid-cols-1 sm:grid-cols-3 gap-4">
          <Field
            label="Ancre d’authentification"
            value="ML-DSA-65"
            note="Requête, réponse, confirmation et commit sont signés. TLS 1.3 mutuel reste le transport QUIC, il n’est plus l’ancre : casser ECDSA ne permet ni de substituer kpub, ni de modifier le ciphertext."
          />
          <Field
            label="Établissement du secret"
            value="ML-KEM-768"
            note="Orion génère la paire éphémère, Helios encapsule. HKDF lie le PSK à la version, au mode, à la transaction, aux deux nonces et aux deux identités WireGuard."
          />
          <Field
            label="Ordre de pose"
            value="poser puis annoncer"
            note="Le slot est posé sur le plan de données avant la réponse. Sans handshake frais puis confirmation signée, Helios restaure le slot précédent."
          />
        </dl>

        <div className="border-t border-slate-200/60 dark:border-slate-800/60 px-5 py-3.5">
          <h3 className="text-[9px] uppercase tracking-widest text-slate-500">Modes acceptés</h3>
          <div className="mt-2 grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px]">
            <Mode name="classic" detail="Slot PSK vidé. Aucune protection contre « récolter maintenant, déchiffrer plus tard »." />
            <Mode name="static_psk" detail="PSK déjà configuré, retrouvé par comparaison d’empreinte. Il ne tourne jamais." />
            <Mode name="ml_kem" detail="PSK frais dérivé à chaque connexion, jamais écrit sur disque." />
          </div>
        </div>

        <div className="border-t border-slate-200/60 dark:border-slate-800/60 px-5 py-3.5 space-y-2.5 text-[11px] leading-relaxed text-slate-500">
          <p>
            <strong className="text-slate-600 dark:text-slate-400">La sécurité ne redescend jamais.</strong>{' '}
            Chaque pair porte un plancher, montré ci-dessus. Une demande située en dessous est refusée
            <em> avant</em> toute modification du plan de données, et chaque négociation aboutie élève le
            plancher au mode utilisé — y compris après redémarrage. Aucun message réseau ni aucune
            renégociation ne peut l’abaisser : seule une édition locale de{' '}
            <span className="font-mono">network.toml</span> le peut.
          </p>
          <p>
            <strong className="text-slate-600 dark:text-slate-400">Deux ports à rediriger.</strong>{' '}
            <span className="font-mono">UDP {status?.wg_listen_port ?? 51820}</span> pour WireGuard et{' '}
            <span className="font-mono">UDP {negotiation ?? 51821}</span> pour la négociation. Sans le second,
            les clients retombent sur l’ancien chemin : tunnel classique d’abord, PSK ensuite — son
            premier handshake n’est alors pas protégé.
          </p>
          <p>
            <strong className="text-slate-600 dark:text-slate-400">Admission hors bande.</strong>{' '}
            L’empreinte du certificat PQ du client est déclarée à l’admission
            (<span className="font-mono">helios-ctl peer add</span>) ; le port de négociation n’étend jamais
            la liste des pairs, il ne sert que ceux déjà admis. Sa présence choisit à elle seule un
            plancher <span className="font-mono">ml_kem</span>.
          </p>
        </div>
      </div>

      <div className="card overflow-hidden">
        <div className="px-5 py-3 border-b border-slate-200/60 dark:border-slate-800/60">
          <h2 className="hud-title">Enrôlement hérité</h2>
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
            <strong className="text-slate-600 dark:text-slate-400">Chemin de compatibilité, plus le chemin nominal.</strong>{' '}
            Ce provisioning exige un tunnel déjà monté : il ne peut donc pas protéger le premier
            handshake, celui qu’un adversaire enregistre aujourd’hui pour le déchiffrer plus tard. Il
            reste servi pour les profils Orion dépourvus de bloc de négociation.
          </p>
          <p>
            <strong className="text-slate-600 dark:text-slate-400">Provisioning post-quantique.</strong>{' '}
            Le PSK est dérivé par ML-KEM-768 puis posé sur le pair <em>avant</em> d’être annoncé au
            client : un PSK présent d’un seul côté ferait échouer tous les handshakes. En cas d’échec,
            la demande est refusée et le tunnel reste classique.
          </p>
        </div>
      </div>
    </div>
  )
}

function Mode({ name, detail }: { name: string; detail: string }) {
  return (
    <div className="rounded border border-slate-200/60 dark:border-slate-800/60 px-3 py-2">
      <div className="font-mono text-[10px] text-slate-700 dark:text-slate-300">{name}</div>
      <p className="mt-1 text-[10px] leading-relaxed text-slate-500">{detail}</p>
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
