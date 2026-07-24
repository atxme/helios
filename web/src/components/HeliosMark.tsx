/**
 * Helios mark — the gateway.
 *
 * Grammar shared by the project's two marks (cf. `OrionMark` on the client
 * side): a containment ring, a solid center, an elliptical trajectory that
 * passes *behind* that center. Institutional aerospace register: monoline,
 * symmetric, no frills — the mark must stay legible at 20 px in a sidebar
 * as well as at 400 px on a supervision screen.
 *
 * Here the center is the solar disk and its corona: Helios is the source,
 * the fixed point around which clients orbit.
 */

const RAYS = 12
/** Every third ray is long — gives a rhythm instead of a uniform cogwheel. */
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
  /** Hides the orbital trajectory — compact version for very small sizes. */
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

      {/* Containment ring — the institutional "seal" frame. */}
      <circle cx="24" cy="24" r="22.25" stroke="currentColor" strokeOpacity="0.22" strokeWidth="1" />

      {/* Corona. */}
      <g stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeOpacity="0.9">
        {rays()}
      </g>

      {/* Trajectory — tilted, it crosses the corona and disappears under the disk. */}
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

      {/* Solar disk — drawn last: it occults the trajectory, which passes behind. */}
      <circle cx="24" cy="24" r="8.75" fill="currentColor" />
    </svg>
  )
}

/** Mark + typography, for a header. */
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
