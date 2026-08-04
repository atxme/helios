import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'

/**
 * Helios mark — the gateway.
 *
 * Grammar shared by the project's two marks (cf. `OrionMark` on the client
 * side): a containment ring, a solid center, an elliptical trajectory that
 * passes *behind* that center. Institutional aerospace register: monoline,
 * symmetric, no frills — the mark must stay legible at 20 px in a navigation
 * rail as well as at 400 px on a supervision screen.
 *
 * Here the center is the solar disk and its corona: Helios is the source, the
 * fixed point around which clients orbit.
 *
 * The mark draws itself in `currentColor`, so a parent decides its color the
 * MUI way — `sx={{ color: 'primary.main' }}` — and it follows the color
 * scheme without knowing one exists.
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
  size?: number
  /** Hides the orbital trajectory — compact version for very small sizes. */
  compact?: boolean
  title?: string
}

export function HeliosMark({ size = 32, compact = false, title }: Props) {
  return (
    <svg
      viewBox="0 0 48 48"
      width={size}
      height={size}
      fill="none"
      role={title ? 'img' : undefined}
      aria-hidden={title ? undefined : true}
      aria-label={title}
      style={{ display: 'block', flexShrink: 0 }}
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

/**
 * Mark and wordmark, stacked — the head of the navigation rail.
 *
 * Colored from the `rail` tokens rather than the page's, because the rail
 * holds its night in both schemes: `text.secondary` would vanish into it as
 * soon as the light scheme is selected.
 */
export function HeliosLockup() {
  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 0.75 }}>
      <Box
        sx={{
          color: 'primary.main',
          filter: 'drop-shadow(0 0 10px color-mix(in srgb, var(--mui-palette-primary-main) 45%, transparent))',
        }}
      >
        <HeliosMark size={32} title="Helios" />
      </Box>
      <Typography
        variant="overline"
        sx={{ color: 'rail.text', letterSpacing: '0.2em', lineHeight: 1, fontSize: '0.625rem' }}
      >
        Helios
      </Typography>
    </Box>
  )
}
