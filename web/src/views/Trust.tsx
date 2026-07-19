import { AlertTriangle, Check, Fingerprint, Lock, ScrollText, X } from 'lucide-react'
import { useEffect, useState } from 'react'
import { fetchTrust } from '../api'
import type { Trust } from '../types'

/** Libellés lisibles des algorithmes exigés, avec ce que chacun apporte. */
const ALG_LABEL: Record<string, { name: string; note: string }> = {
  ed25519: {
    name: 'Ed25519',
    note: 'Signature classique, éprouvée. Tient tant qu’aucun calculateur quantique pertinent n’existe.',
  },
  'ml-dsa-65': {
    name: 'ML-DSA-65',
    note: 'Signature post-quantique (FIPS 204). Couvre la durée de vie du matériel déployé.',
  },
}

export function TrustView() {
  const [trust, setTrust] = useState<Trust | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchTrust()
      .then(setTrust)
      .catch(() => setError('Ancre de confiance illisible — heliosd ne répond pas sur /api/trust'))
  }, [])

  return (
    <div className="space-y-4 max-w-4xl">
      <div>
        <h1 className="text-sm font-semibold text-slate-900 dark:text-slate-200 tracking-wide">
          Ancre de confiance
        </h1>
        <p className="text-xs text-slate-500 mt-0.5">
          Ce que ce binaire exige d’un artefact éditeur avant de l’accepter — billet de rescellement
          TPM, et à terme manifestes OTA.
        </p>
      </div>

      {error && (
        <div className="card border border-red-500/30 bg-red-500/10 px-4 py-3 text-xs text-red-500 dark:text-red-400">
          {error}
        </div>
      )}

      {!trust && !error && <p className="text-xs text-slate-500 animate-pulse">Chargement…</p>}

      {trust && (
        <>
          {/* Le signal opérationnel qui prime sur tout le reste. */}
          {trust.development_keys && <DevelopmentKeysBanner />}

          <Section
            icon={Lock}
            title={`Signatures exigées (${trust.required_algs.length})`}
            subtitle="Toutes valides, sinon rejet. Jamais « au moins une »."
          >
            <div className="divide-y divide-slate-200/60 dark:divide-slate-800/60">
              {trust.required_algs.map(alg => {
                const meta = ALG_LABEL[alg]
                return (
                  <div key={alg} className="flex items-start gap-3 px-5 py-3.5">
                    <Check
                      className="h-3.5 w-3.5 mt-0.5 shrink-0 text-emerald-600 dark:text-emerald-400"
                      strokeWidth={2.5}
                    />
                    <div className="min-w-0">
                      <div className="text-xs font-medium text-slate-800 dark:text-slate-200">
                        {meta?.name ?? alg}
                        <span className="ml-2 font-mono text-[10px] text-slate-500">{alg}</span>
                      </div>
                      {meta && <p className="mt-1 text-[11px] leading-relaxed text-slate-500">{meta.note}</p>}
                    </div>
                  </div>
                )
              })}
            </div>

            {/* La règle qui fait tout le travail : elle mérite d'être écrite noir sur blanc. */}
            <div className="border-t border-slate-200/60 dark:border-slate-800/60 px-5 py-3.5 space-y-2">
              <Rule ok>Un algorithme exigé sans signature valide → rejet.</Rule>
              <Rule ok>Une signature présente mais invalide → rejet, même si les autres passent.</Rule>
              <Rule ok={false}>
                Un algorithme <em>inconnu</em> en supplément → ignoré, pour la compatibilité avant.
              </Rule>
            </div>
          </Section>

          <Section
            icon={Fingerprint}
            title={`Trousseau éditeur (${trust.publisher_keys.length})`}
            subtitle="Compilé dans le binaire. Une rotation de clé éditeur exige une mise à jour firmware."
          >
            <div className="divide-y divide-slate-200/60 dark:divide-slate-800/60">
              {trust.publisher_keys.map(key => (
                <div key={key.key_epoch} className="flex flex-wrap items-center gap-3 px-5 py-3.5">
                  <span className="text-[10px] px-2 py-0.5 rounded border border-cyan-500/40 bg-cyan-500/5 font-mono text-cyan-700 dark:text-cyan-400">
                    époque {key.key_epoch}
                  </span>
                  <span
                    className="font-mono text-[11px] text-slate-600 dark:text-slate-300 break-all"
                    title="SHA-256(ed25519 ‖ ml-dsa-65), tronqué à 128 bits"
                  >
                    {groupFingerprint(key.fingerprint)}
                  </span>
                </div>
              ))}
            </div>
            <p className="border-t border-slate-200/60 dark:border-slate-800/60 px-5 py-3 text-[11px] leading-relaxed text-slate-500">
              L’empreinte couvre les <strong>deux</strong> clés de l’époque hachées ensemble : un trousseau
              dont seule la moitié Ed25519 serait la bonne ne produirait pas la même valeur.
            </p>
          </Section>

          <Section
            icon={ScrollText}
            title="Séparation de domaine"
            subtitle="Une signature de billet ne peut pas être rejouée comme signature d’un autre artefact."
          >
            <dl className="px-5 py-3.5 grid grid-cols-1 sm:grid-cols-2 gap-3">
              <Field label="Domaine du billet de rescellement" value={trust.reseal_domain} />
              <Field label="Version de format" value={String(trust.reseal_format_version)} />
            </dl>
            <p className="border-t border-slate-200/60 dark:border-slate-800/60 px-5 py-3 font-mono text-[10px] leading-relaxed text-slate-500">
              octets_signés = domaine ‖ version_format ‖ key_epoch ‖ payload_canonique
            </p>
          </Section>
        </>
      )}
    </div>
  )
}

function DevelopmentKeysBanner() {
  return (
    <div className="card border border-amber-500/40 bg-amber-500/10 px-5 py-4 flex items-start gap-3">
      <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0 text-amber-600 dark:text-amber-400" strokeWidth={1.75} />
      <div className="min-w-0">
        <div className="text-xs font-semibold text-amber-700 dark:text-amber-300">
          Trousseau de développement
        </div>
        <p className="mt-1 text-[11px] leading-relaxed text-amber-800/80 dark:text-amber-200/70">
          Ce binaire accepte des artefacts signés par les clés de test publiées dans le dépôt —
          n’importe qui peut en forger. C’est normal en développement, jamais sur un équipement
          déployé. Un build <span className="font-mono">release</span> exige{' '}
          <span className="font-mono">HELIOS_PUBLISHER_KEYRING_PATH</span> et échoue sans lui.
        </p>
      </div>
    </div>
  )
}

function Rule({ ok, children }: { ok: boolean; children: React.ReactNode }) {
  const Icon = ok ? X : Check
  return (
    <div className="flex items-start gap-2.5">
      <Icon
        className={`h-3 w-3 mt-0.5 shrink-0 ${ok ? 'text-red-500' : 'text-slate-400'}`}
        strokeWidth={2.5}
      />
      <span className="text-[11px] leading-relaxed text-slate-600 dark:text-slate-400">{children}</span>
    </div>
  )
}

function Section({
  icon: Icon,
  title,
  subtitle,
  children,
}: {
  icon: React.ElementType
  title: string
  subtitle: string
  children: React.ReactNode
}) {
  return (
    <div className="card overflow-hidden">
      <div className="px-5 py-3 border-b border-slate-200/60 dark:border-slate-800/60 flex items-start gap-3">
        <Icon className="h-4 w-4 mt-0.5 shrink-0 text-cyan-600 dark:text-cyan-400" strokeWidth={1.5} />
        <div className="min-w-0">
          <h2 className="hud-title">{title}</h2>
          <p className="mt-0.5 text-[11px] text-slate-500">{subtitle}</p>
        </div>
      </div>
      {children}
    </div>
  )
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-[9px] uppercase tracking-widest text-slate-500">{label}</dt>
      <dd className="mt-1 font-mono text-[11px] text-slate-700 dark:text-slate-300 break-all">{value}</dd>
    </div>
  )
}

/** Découpe l'empreinte en groupes de 4 — comparable à l'œil, comme une empreinte SSH. */
function groupFingerprint(fingerprint: string): string {
  return (fingerprint.match(/.{1,4}/g) ?? [fingerprint]).join(' ')
}
