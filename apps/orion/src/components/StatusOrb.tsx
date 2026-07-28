import Box from '@mui/material/Box'
import { keyframes } from '@mui/material/styles'
import type { TunnelState } from '../types'
import { postureMeta, stateMeta } from './state'

/**
 * Centerpiece of the Connect view.
 *
 * Reuses `OrionMark`'s grammar — ring, belt, trajectory — but turns it into
 * an instrument rather than a logo: each element encodes a fact.
 *
 * - **the outer ring** carries the color of the *posture* (what actually
 *   protects the machine), not that of the tunnel state;
 * - **two trajectories rotate in opposite directions**, brisk and dashed
 *   during negotiation, slow and solid once connected. Color separates them:
 *   amber as long as nothing is secured, green as soon as traffic flows. We
 *   don't confuse "it's working" with "it's good";
 * - **a satellite** travels along the main trajectory: it gives the reading
 *   of direction and speed;
 * - **the belt's three stars** light up one by one with progress — reachable
 *   endpoint → handshake → traffic — and twinkle slightly, staggered, once
 *   the tunnel is established.
 *
 * **Cost.** All these animations only touch `transform` and `opacity`, on
 * promoted layers: the GPU composites them without repainting. It's not
 * their number that costs, it's their nature — the original halo alone
 * stuttered because it animated a `filter: blur()`, re-rasterized every frame.
 */

interface Props {
  state: TunnelState
  adapterUp: boolean
  /** Diameter in pixels. */
  size?: number
}

/** How many belt stars are lit, in mounting order. */
function litStars(state: TunnelState, adapterUp: boolean): number {
  if (state === 'up') return 3
  if (state === 'connecting' || state === 'captive_portal') return 2
  if (adapterUp) return 1
  return 0
}

const BELT = [
  { x: 15.5, y: 30.5, r: 2.4 },
  { x: 24, y: 24, r: 4.5 },
  { x: 32.5, y: 17.5, r: 2.4 },
]

const pulse = keyframes`
  0%, 100% { opacity: 0.5; }
  50% { opacity: 1; }
`

const orbit = keyframes`
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
`

/** Opposite direction: two crossing planes read better than one. */
const counterOrbit = keyframes`
  from { transform: rotate(360deg); }
  to { transform: rotate(0deg); }
`

const twinkle = keyframes`
  0%, 100% { opacity: 0.62; }
  50% { opacity: 1; }
`

/** Star not yet crossed — a paper gray, not a dark-screen gray. */
const UNLIT = '#CBD5D1'

/** Trajectory point at rest, before the 27° tilt. */
const SATELLITE_X = 44.5

export function StatusOrb({ state, adapterUp, size = 168 }: Props) {
  const meta = stateMeta(state)
  const posture = postureMeta(state, adapterUp)
  const lit = litStars(state, adapterUp)

  // Two regimes, two readings. Connected rotates slowly: a fast rotation
  // would suggest a negotiation still in progress.
  const settled = state === 'up'
  const spinning = meta.transitioning || settled
  const mainPeriod = settled ? '22s' : '8s'
  const counterPeriod = settled ? '34s' : '13s'

  return (
    <Box sx={{ position: 'relative', display: 'grid', width: size, height: size, placeItems: 'center' }}>
      {posture.posture === 'protected' && (
        <Box
          aria-hidden
          sx={{
            position: 'absolute',
            inset: 0,
            borderRadius: '50%',
            // "Already blurred" halo rather than `filter: blur()`. CSS blur is
            // the most expensive filter, and animating it forces a
            // re-rasterization every frame: on WebView2 the halo stuttered the
            // whole UI as soon as the connection was established. Alpha steps
            // give the same softness for zero cost.
            background: `radial-gradient(circle, ${posture.accent}3D 0%, ${posture.accent}1F 38%, transparent 72%)`,
            pointerEvents: 'none',
            willChange: 'opacity',
            animation: `${pulse} 2.4s ease-in-out infinite`,
            '@media (prefers-reduced-motion: reduce)': {
              animation: 'none',
              opacity: 0.32,
            },
          }}
        />
      )}

      <svg
        viewBox="0 0 48 48"
        fill="none"
        style={{ position: 'relative', width: size, height: size }}
        role="img"
        aria-label={`${meta.label} — ${posture.label}`}
      >
        {/* Posture ring: the color that matters for the machine's security. */}
        <circle
          cx="24"
          cy="24"
          r="22.25"
          stroke={posture.color}
          strokeOpacity="0.7"
          strokeWidth="0.7"
        />
        {/* Trajectory background track. */}
        <ellipse
          cx="24"
          cy="24"
          rx="20.5"
          ry="7.25"
          transform="rotate(27 24 24)"
          stroke={posture.color}
          strokeOpacity="0.14"
          strokeWidth="0.8"
        />

        {/* Background layer, opposite direction — gives depth without noise. */}
        {spinning && (
          <Box
            component="g"
            sx={{
              transformOrigin: '24px 24px',
              willChange: 'transform',
              animation: `${counterOrbit} ${counterPeriod} linear infinite`,
              '@media (prefers-reduced-motion: reduce)': { animation: 'none' },
            }}
          >
            <ellipse
              cx="24"
              cy="24"
              rx="20.5"
              ry="7.25"
              transform="rotate(-27 24 24)"
              stroke={meta.accent}
              strokeOpacity="0.3"
              strokeWidth="0.7"
            />
          </Box>
        )}

        {/* Main trajectory, with its satellite. */}
        <Box
          component="g"
          sx={{
            transformOrigin: '24px 24px',
            willChange: spinning ? 'transform' : undefined,
            animation: spinning ? `${orbit} ${mainPeriod} linear infinite` : undefined,
            '@media (prefers-reduced-motion: reduce)': { animation: 'none' },
          }}
        >
          <ellipse
            cx="24"
            cy="24"
            rx="20.5"
            ry="7.25"
            transform="rotate(27 24 24)"
            stroke={meta.accent}
            strokeOpacity={meta.active ? 0.95 : 0.75}
            strokeWidth={settled ? 1.1 : 0.9}
            strokeDasharray={meta.transitioning ? '5 9' : undefined}
            strokeLinecap="round"
          />
          {spinning && (
            <g transform="rotate(27 24 24)">
              <circle cx={SATELLITE_X} cy="24" r="1.6" fill={meta.accent} />
            </g>
          )}
        </Box>

        {/* Constellation lines. */}
        <g stroke={meta.color} strokeWidth="0.75" strokeOpacity="0.22" strokeLinecap="round">
          <line x1={BELT[0].x} y1={BELT[0].y} x2={BELT[2].x} y2={BELT[2].y} />
        </g>

        {/* Belt — one star per step crossed. */}
        <g>
          {BELT.map((star, index) => {
            const on = index < lit
            return (
              <Box
                component="circle"
                key={star.x}
                cx={star.x}
                cy={star.y}
                r={star.r}
                fill={on ? meta.accent : UNLIT}
                sx={{
                  transition: 'fill 400ms ease',
                  // Staggered twinkle: three stars pulsing together would
                  // make a blinker, not a constellation.
                  animation:
                    on && settled
                      ? `${twinkle} ${2.8 + index * 0.6}s ease-in-out ${index * 0.35}s infinite`
                      : undefined,
                  '@media (prefers-reduced-motion: reduce)': { animation: 'none' },
                }}
              />
            )
          })}
        </g>
      </svg>
    </Box>
  )
}
