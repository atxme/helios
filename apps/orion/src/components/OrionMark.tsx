import type { CSSProperties } from 'react'

/**
 * Orion mark — the client.
 *
 * Same grammar as the Helios mark (containment ring, solid center, elliptical
 * trajectory passing behind the center), so the two read as a single family.
 * Two differences carry the distinction:
 *
 * - the center is not a source but **Orion's Belt** — three aligned stars.
 *   The client is a constellation of machines, not a fixed point;
 * - the trajectory is tilted the other way (+27° versus −27°): the two marks
 *   side by side form a mirror pair.
 */

/** The belt, on the frame's diagonal. The central star occupies the exact center. */
const BELT = [
  { x: 15.5, y: 30.5, r: 2.4 },
  { x: 24, y: 24, r: 4.5 },
  { x: 32.5, y: 17.5, r: 2.4 },
]

/** Two stars outside the belt — enough to read the figure, not a star chart. */
const OUTLIERS = [
  { x: 13.25, y: 16.5, r: 1.35 },
  { x: 34.75, y: 31.5, r: 1.35 },
]

interface Props {
  className?: string
  style?: CSSProperties
  /** Hides the orbital trajectory — compact version for very small sizes. */
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

      {/* Containment ring — identical to Helios. */}
      <circle cx="24" cy="24" r="22.25" stroke="currentColor" strokeOpacity="0.22" strokeWidth="1" />

      {/* Trajectory — will pass behind the stars, drawn afterward. */}
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

      {/* Constellation lines — faint stroke, like on a star chart. */}
      <g stroke="currentColor" strokeWidth="1.1" strokeOpacity="0.4" strokeLinecap="round">
        <line x1={BELT[0].x} y1={BELT[0].y} x2={BELT[2].x} y2={BELT[2].y} />
        <line x1={OUTLIERS[0].x} y1={OUTLIERS[0].y} x2={BELT[1].x} y2={BELT[1].y} />
        <line x1={OUTLIERS[1].x} y1={OUTLIERS[1].y} x2={BELT[1].x} y2={BELT[1].y} />
      </g>

      {/* Stars. The central one is the "solid center" of the shared grammar. */}
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

