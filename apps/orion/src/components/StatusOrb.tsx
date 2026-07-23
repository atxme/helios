import Box from '@mui/material/Box'
import { keyframes } from '@mui/material/styles'
import type { TunnelState } from '../types'
import { postureMeta, stateMeta } from './state'

/**
 * Pièce maîtresse de la vue Connexion.
 *
 * Reprend la grammaire de `OrionMark` — anneau, ceinture, trajectoire — mais en
 * fait un instrument plutôt qu'un logo : chaque élément encode un fait.
 *
 * - **l'anneau extérieur** porte la couleur de la *posture* (ce qui protège
 *   réellement le poste), pas celle de l'état du tunnel ;
 * - **la trajectoire** tourne pendant `connecting` et s'immobilise sinon ;
 * - **les trois étoiles de la ceinture** s'allument une à une avec la
 *   progression : endpoint joignable → handshake → trafic. C'est la seule
 *   lecture séquentielle du montage, et elle est vraie.
 *
 * Les deux couleurs sont volontairement dissociables : un tunnel en échec sur un
 * adaptateur monté donne un centre éteint dans un anneau *bleu* — retenu, pas
 * exposé. Un seul anneau orange signifie qu'on fuit.
 */

interface Props {
  state: TunnelState
  adapterUp: boolean
  /** Diamètre en pixels. */
  size?: number
}

/** Combien d'étoiles de la ceinture sont allumées, dans l'ordre du montage. */
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
  0%, 100% { opacity: 0.22; }
  50% { opacity: 0.42; }
`

const orbit = keyframes`
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
`

export function StatusOrb({ state, adapterUp, size = 168 }: Props) {
  const meta = stateMeta(state)
  const posture = postureMeta(state, adapterUp)
  const lit = litStars(state, adapterUp)

  return (
    <Box sx={{ position: 'relative', display: 'grid', width: size, height: size, placeItems: 'center' }}>
      {posture.posture === 'protected' && (
        <Box
          aria-hidden
          sx={{
            position: 'absolute',
            inset: 0,
            borderRadius: '50%',
            background: `radial-gradient(circle, ${posture.color} 0%, transparent 65%)`,
            filter: 'blur(20px)',
            pointerEvents: 'none',
            animation: `${pulse} 2.4s ease-in-out infinite`,
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
          strokeOpacity="0.75"
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
          strokeOpacity="0.12"
          strokeWidth="0.8"
        />

        {/* Trajectoire active — tourne pendant la négociation, fixe autrement. */}
        <g style={{ transformOrigin: '24px 24px', animation: meta.transitioning ? `${orbit} 9s linear infinite` : undefined }}>
          <ellipse
            cx="24"
            cy="24"
            rx="20.5"
            ry="7.25"
            transform="rotate(27 24 24)"
            stroke={meta.color}
            strokeOpacity={meta.active ? 0.6 : 0.35}
            strokeWidth="0.9"
            strokeDasharray={meta.transitioning ? '5 9' : undefined}
            strokeLinecap="round"
          />
        </g>

        {/* Lignes de constellation. */}
        <g stroke={meta.color} strokeWidth="0.75" strokeOpacity="0.22" strokeLinecap="round">
          <line x1={BELT[0].x} y1={BELT[0].y} x2={BELT[2].x} y2={BELT[2].y} />
        </g>

        {/* Ceinture — une étoile par étape franchie. */}
        <g>
          {BELT.map((star, index) => {
            const on = index < lit
            return (
              <circle
                key={star.x}
                cx={star.x}
                cy={star.y}
                r={star.r}
                fill={on ? meta.color : '#334155'}
                fillOpacity={on ? 1 : 0.45}
                style={{ transition: 'fill-opacity 400ms ease, fill 400ms ease' }}
              />
            )
          })}
        </g>
      </svg>
    </Box>
  )
}
