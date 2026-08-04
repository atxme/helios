/**
 * A rolling curve, sized by its container.
 *
 * Everything is drawn in `currentColor`, so the caller picks the hue the MUI
 * way — `sx={{ color: 'tertiary.main' }}` on the wrapper — and the curve
 * follows the color scheme without ever naming a CSS variable.
 *
 * The scale is relative to the window on screen, not absolute: this answers
 * "is traffic moving, and is it steady", which is what a supervision glance
 * asks. The figure printed next to it carries the magnitude.
 */

interface Props {
  values: number[]
  height?: number
  /** Read by screen readers in place of the curve. */
  label: string
}

const VIEWBOX_WIDTH = 240
const PADDING = 3

export function Sparkline({ values, height = 44, label }: Props) {
  if (values.length < 2) {
    return (
      <svg
        width="100%"
        height={height}
        role="img"
        aria-label={`${label} — en attente de mesures`}
        style={{ display: 'block' }}
      />
    )
  }

  const max = Math.max(...values, 1)
  const step = (VIEWBOX_WIDTH - PADDING * 2) / (values.length - 1)
  const y = (value: number) => height - PADDING - (value / max) * (height - PADDING * 2)

  const points = values.map((value, index) => `${PADDING + index * step},${y(value)}`)
  const area = [`${PADDING},${height - PADDING}`, ...points, `${PADDING + (values.length - 1) * step},${height - PADDING}`]

  return (
    <svg
      width="100%"
      height={height}
      viewBox={`0 0 ${VIEWBOX_WIDTH} ${height}`}
      preserveAspectRatio="none"
      role="img"
      aria-label={label}
      style={{ display: 'block', overflow: 'visible' }}
    >
      <polygon points={area.join(' ')} fill="currentColor" fillOpacity="0.14" />
      <polyline
        points={points.join(' ')}
        fill="none"
        stroke="currentColor"
        strokeWidth="1.75"
        strokeLinecap="round"
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
      />
      {/*
        No marker on the latest point. The viewBox is stretched horizontally to
        fill its container (`preserveAspectRatio="none"`), which turns any
        circle into a lozenge — the stroke escapes this only through
        `vector-effect`, which has no equivalent for shapes. The reading next to
        the label already names the current value.
      */}
    </svg>
  )
}
