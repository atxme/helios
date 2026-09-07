import { forwardRef } from 'react'
import type { LucideProps } from 'lucide-react'

/**
 * Astra mark — the authority.
 *
 * # Why not the key it replaces
 *
 * The tab used a padlock-key glyph borrowed from the icon set. It said
 * «security», which every tab of this application could claim, and it said it
 * with the same shape a dozen other products use for a password field. What it
 * did not say is what Astra *is*.
 *
 * # The grammar
 *
 * Two things, and both are borrowed from the Helios and Orion marks so the
 * three read as one family:
 *
 * - **the containment ring**, at the same faint opacity, saying «a domain»;
 * - **a solid centre**, which is where the three marks differ. Helios has a
 *   source, Orion has a constellation — a client is many machines — and Astra
 *   has a single star. *Astra*: the authority is the fixed point the others
 *   are measured against.
 *
 * And one deliberate omission: no trajectory. Helios and Orion both carry an
 * orbit; the anchor of a trust domain does not move, and a mark that showed it
 * orbiting would be saying the opposite of what the anchor is for.
 *
 * Drawn on the 24-unit grid of the surrounding icon set rather than the
 * 48-unit grid of the application marks: this one sits in a navigation rail,
 * beside icons whose weight it has to match.
 */

/** A four-pointed star with concave flanks: legible down to 16 px. */
const STAR =
  'M12 4.25 C12.75 8.6 11.4 11.25 19.75 12 C11.4 12.75 12.75 15.4 12 19.75 ' +
  'C11.25 15.4 12.6 12.75 4.25 12 C12.6 11.25 11.25 8.6 12 4.25 Z'

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
          the Helios and Orion marks. */}
      <circle
        cx="12"
        cy="12"
        r="10.25"
        stroke="currentColor"
        strokeOpacity="0.3"
        strokeWidth="1.5"
      />
      <path d={STAR} fill="currentColor" />
    </svg>
  )
})
