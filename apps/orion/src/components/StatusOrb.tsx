import Box from '@mui/material/Box'
import { keyframes } from '@mui/material/styles'
import type { TunnelState } from '../types'
import { postureMeta, stateMeta } from './state'

/**
 * Pièce maîtresse de la vue Connexion.
 *
 * Reprend la grammaire de `OrionMark` — anneau, ceinture, trajectoire — mais en
 * fait un instrument plutôt qu’un logo : chaque élément encode un fait.
 *
 * - **l’anneau extérieur** porte la couleur de la *posture* (ce qui protège
 *   réellement le poste), pas celle de l’état du tunnel ;
 * - **deux trajectoires tournent en sens inverse**, vives et pointillées pendant
 *   la négociation, lentes et pleines une fois connecté. La couleur les sépare :
 *   ambre tant que rien n’est acquis, vert dès que le trafic passe. On ne
 *   confond pas « ça travaille » avec « c’est bon » ;
 * - **un satellite** parcourt la trajectoire principale : c’est lui qui donne la
 *   lecture du sens et de la vitesse ;
 * - **les trois étoiles de la ceinture** s’allument une à une avec la
 *   progression — endpoint joignable → handshake → trafic — et scintillent
 *   légèrement, en décalé, une fois le tunnel établi.
 *
 * **Coût.** Toutes ces animations ne touchent que `transform` et `opacity`, sur
 * des calques promus : le GPU les compose sans repeindre. Ce n’est pas leur
 * nombre qui coûte, c’est leur nature — le halo d’origine saccadait à lui seul
 * parce qu’il animait un `filter: blur()`, re-rastérisé à chaque frame.
 */

interface Props {
  state: TunnelState
  adapterUp: boolean
  /** Diamètre en pixels. */
  size?: number
}

/** Combien d’étoiles de la ceinture sont allumées, dans l’ordre du montage. */
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

/** Sens inverse : deux plans qui se croisent lisent mieux qu’un seul. */
const counterOrbit = keyframes`
  from { transform: rotate(360deg); }
  to { transform: rotate(0deg); }
`

const twinkle = keyframes`
  0%, 100% { opacity: 0.62; }
  50% { opacity: 1; }
`

/** Étoile non encore franchie — un gris papier, pas un gris d’écran sombre. */
const UNLIT = '#CBD5D1'

/** Point de la trajectoire au repos, avant l’inclinaison de 27°. */
const SATELLITE_X = 44.5

export function StatusOrb({ state, adapterUp, size = 168 }: Props) {
  const meta = stateMeta(state)
  const posture = postureMeta(state, adapterUp)
  const lit = litStars(state, adapterUp)

  // Deux régimes, deux lectures. Le connecté tourne lentement : une rotation
  // rapide y suggérerait une négociation encore en cours.
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
            // Halo « déjà dégradé » plutôt que `filter: blur()`. Le flou CSS est
            // le filtre le plus coûteux, et l'animer force une re-rastérisation
            // à chaque frame : sur WebView2 le halo saccadait toute l'IHM dès la
            // connexion établie. Des paliers alpha donnent la même douceur pour
            // un coût nul.
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
        {/* Anneau de posture : la couleur qui compte pour la sécurité du poste. */}
        <circle
          cx="24"
          cy="24"
          r="22.25"
          stroke={posture.color}
          strokeOpacity="0.7"
          strokeWidth="0.7"
        />
        {/* Piste de fond de la trajectoire. */}
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

        {/* Second plan, en sens inverse — donne la profondeur sans bruit. */}
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

        {/* Trajectoire principale, avec son satellite. */}
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

        {/* Lignes de constellation. */}
        <g stroke={meta.color} strokeWidth="0.75" strokeOpacity="0.22" strokeLinecap="round">
          <line x1={BELT[0].x} y1={BELT[0].y} x2={BELT[2].x} y2={BELT[2].y} />
        </g>

        {/* Ceinture — une étoile par étape franchie. */}
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
                  // Scintillement décalé : trois étoiles qui pulseraient
                  // ensemble feraient un clignotant, pas une constellation.
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
