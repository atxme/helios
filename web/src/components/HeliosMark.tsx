/**
 * Marque Helios — la gateway.
 *
 * Grammaire commune aux deux marques du projet (cf. `OrionMark` côté client) :
 * un anneau de confinement, un centre plein, une trajectoire elliptique qui
 * passe *derrière* ce centre. Registre institutionnel aérospatial : monoline,
 * symétrique, aucune fioriture — la marque doit rester lisible à 20 px dans une
 * barre latérale comme à 400 px sur un écran de supervision.
 *
 * Ici le centre est le disque solaire et sa couronne : Helios est la source,
 * le point fixe autour duquel les clients gravitent.
 */

const RAYS = 12
/** Un rai sur trois est long — donne un rythme au lieu d'une roue dentée uniforme. */
const RAY_INNER = 11.5
const RAY_LONG = 18
const RAY_SHORT = 15.25

function rays() {
  return Array.from({ length: RAYS }, (_, index) => {
    const angle = (index * 2 * Math.PI) / RAYS
    const outer = index % 3 === 0 ? RAY_LONG : RAY_SHORT
    const cos = Math.cos(angle)
    const sin = Math.sin(angle)
    return (
      <line
        key={index}
        x1={24 + RAY_INNER * cos}
        y1={24 + RAY_INNER * sin}
        x2={24 + outer * cos}
        y2={24 + outer * sin}
      />
    )
  })
}

interface Props {
  className?: string
  /** Masque la trajectoire orbitale — version compacte pour les très petites tailles. */
  compact?: boolean
  title?: string
}

export function HeliosMark({ className = '', compact = false, title }: Props) {
  return (
    <svg
      viewBox="0 0 48 48"
      fill="none"
      className={className}
      role={title ? 'img' : undefined}
      aria-hidden={title ? undefined : true}
      aria-label={title}
    >
      {title && <title>{title}</title>}

      {/* Anneau de confinement — le cadre « sceau » institutionnel. */}
      <circle cx="24" cy="24" r="22.25" stroke="currentColor" strokeOpacity="0.22" strokeWidth="1" />

      {/* Couronne. */}
      <g stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeOpacity="0.9">
        {rays()}
      </g>

      {/* Trajectoire — inclinée, elle traverse la couronne et disparaît sous le disque. */}
      {!compact && (
        <ellipse
          cx="24"
          cy="24"
          rx="20.5"
          ry="7.25"
          transform="rotate(-27 24 24)"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeOpacity="0.55"
        />
      )}

      {/* Disque solaire — dessiné en dernier : il occulte la trajectoire, qui passe derrière. */}
      <circle cx="24" cy="24" r="8.75" fill="currentColor" />
    </svg>
  )
}

/** Marque + typographie, pour un en-tête. */
export function HeliosLockup({ className = '' }: { className?: string }) {
  return (
    <div className={`flex items-center gap-3 ${className}`}>
      <HeliosMark className="h-8 w-8 shrink-0 text-amber-500 dark:text-amber-400" title="Helios" />
      <div className="min-w-0 leading-none">
        <div className="font-bold tracking-[0.28em] text-[13px] text-amber-600 dark:text-amber-300">
          HELIOS
        </div>
        <div className="mt-1 text-[9px] uppercase tracking-[0.16em] text-cyan-700/75 dark:text-cyan-500/70 font-mono">
          WireGuard · PQ Gateway
        </div>
      </div>
    </div>
  )
}
