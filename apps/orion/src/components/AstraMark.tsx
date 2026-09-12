import { forwardRef } from 'react'
import type { LucideProps } from 'lucide-react'

/**
 * Astra mark — the authority.
 *
 * # Why not the padlock it replaces
 *
 * The tab carried a padlock ringed with rays. The padlock said «security»,
 * which every tab of this application could claim, and said it with the shape
 * a dozen other products use for a password field; the rays said «Helios»,
 * whose corona they were borrowed from. Neither said what Astra *is*.
 *
 * # The grammar
 *
 * Two things, both taken from the Helios and Orion marks so the three read as
 * one family:
 *
 * - **the containment ring**, at the same faint opacity, saying «a domain»;
 * - **a solid centre**, which is where the three marks differ. Helios has a
 *   source, Orion has a constellation — a client is many machines — and Astra
 *   has a single star. *Astra*: the authority is the fixed point the others
 *   take their bearing from.
 *
 * And one deliberate omission: no trajectory. Helios and Orion both carry an
 * orbit; the anchor of a trust domain does not move, and a mark that showed it
 * orbiting would say the opposite of what an anchor is for.
 *
 * # Why this grid, and why the star is filled
 *
 * Drawn on the 24-unit grid of the surrounding icon set rather than the
 * 48-unit grid of the application marks: this one sits in a navigation rail at
 * 18 px, beside icons whose weight it has to match. At that size a star drawn
 * in outline collapses into a lozenge, so the star is solid and only the ring
 * is stroked — which is also what keeps the two shapes apart.
 */

/** Four points, concave flanks, so the star stays a star and not a cross. */
const STAR =
  'M12 4.4 Q13.05 10.95 19.6 12 Q13.05 13.05 12 19.6 ' +
  'Q10.95 13.05 4.4 12 Q10.95 10.95 12 4.4 Z'

/**
 * Shaped as one of the surrounding icon set's components — same props, same
 * ref — so the navigation rail keeps one type for its whole row. A slot typed
 * to accept «either theirs or ours» would make our own drawing the exception.
 */
export const AstraMark = forwardRef<SVGSVGElement, LucideProps>(function AstraMark(
  { size = 18, ...rest },
  ref,
) {
  return (
    <svg
      ref={ref}
      viewBox="0 0 24 24"
      width={size}
      height={size}
      fill="none"
      {...rest}
    >
      {/* The domain this authority anchors. Same faint weight as the ring of
          the Helios and Orion marks, thinned for the smaller grid. */}
      <circle
        cx="12"
        cy="12"
        r="10.25"
        stroke="currentColor"
        strokeOpacity="0.3"
        strokeWidth="1.3"
      />
      <path d={STAR} fill="currentColor" />
    </svg>
  )
})
