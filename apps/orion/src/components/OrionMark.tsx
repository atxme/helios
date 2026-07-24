import type { CSSProperties } from 'react'

/**
 * Marque Orion — le client.
 *
 * Même grammaire que la marque Helios (anneau de confinement, centre plein,
 * trajectoire elliptique passant derrière le centre), pour que les deux se
 * lisent comme une seule famille. Deux différences portent la distinction :
 *
 * - le centre n'est pas une source mais **la Ceinture d'Orion** — trois étoiles
 *   alignées. Le client est une constellation de postes, pas un point fixe ;
 * - la trajectoire est inclinée dans l'autre sens (+27° contre −27°) : les deux
 *   marques côte à côte forment une paire miroir.
 */

/** La ceinture, sur la diagonale du cadre. L'étoile centrale occupe le centre exact. */
const BELT = [
  { x: 15.5, y: 30.5, r: 2.4 },
  { x: 24, y: 24, r: 4.5 },
  { x: 32.5, y: 17.5, r: 2.4 },
]

/** Deux étoiles hors ceinture — suffisent à faire lire la figure, pas la carte du ciel. */
const OUTLIERS = [
  { x: 13.25, y: 16.5, r: 1.35 },
  { x: 34.75, y: 31.5, r: 1.35 },
]

interface Props {
  className?: string
  style?: CSSProperties
  /** Masque la trajectoire orbitale — version compacte pour les très petites tailles. */
  compact?: boolean
  title?: string
}

export function OrionMark({ className = '', style, compact = false, title }: Props) {
  return (
    <svg
      viewBox="0 0 48 48"
      fill="none"
      className={className}
      style={style}
      role={title ? 'img' : undefined}
      aria-hidden={title ? undefined : true}
      aria-label={title}
    >
      {title && <title>{title}</title>}

      {/* Anneau de confinement — identique à Helios. */}
      <circle cx="24" cy="24" r="22.25" stroke="currentColor" strokeOpacity="0.22" strokeWidth="1" />

      {/* Trajectoire — passera derrière les étoiles, dessinées après. */}
      {!compact && (
        <ellipse
          cx="24"
          cy="24"
          rx="20.5"
          ry="7.25"
          transform="rotate(27 24 24)"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeOpacity="0.55"
        />
      )}

      {/* Lignes de constellation — tracé faible, comme sur une carte céleste. */}
      <g stroke="currentColor" strokeWidth="1.1" strokeOpacity="0.4" strokeLinecap="round">
        <line x1={BELT[0].x} y1={BELT[0].y} x2={BELT[2].x} y2={BELT[2].y} />
        <line x1={OUTLIERS[0].x} y1={OUTLIERS[0].y} x2={BELT[1].x} y2={BELT[1].y} />
        <line x1={OUTLIERS[1].x} y1={OUTLIERS[1].y} x2={BELT[1].x} y2={BELT[1].y} />
      </g>

      {/* Étoiles. La centrale est le « centre plein » de la grammaire commune. */}
      <g fill="currentColor">
        {OUTLIERS.map(star => (
          <circle key={`o-${star.x}`} cx={star.x} cy={star.y} r={star.r} fillOpacity="0.55" />
        ))}
        {BELT.map(star => (
          <circle key={`b-${star.x}`} cx={star.x} cy={star.y} r={star.r} />
        ))}
      </g>
    </svg>
  )
}

