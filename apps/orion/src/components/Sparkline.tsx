import Box from '@mui/material/Box'
import Typography from '@mui/material/Typography'

/**
 * Throughput curve — an area, a line, an accented end point.
 *
 * The two series (↓ and ↑) share the same vertical scale, computed from the
 * max of both: otherwise a 2 kB/s spike in transmission would have the same
 * height as a 20 MB/s spike in reception, which would be misleading.
 */

interface Props {
  /** History, from oldest to most recent. */
  points: number[]
  /** Ceiling shared by the compared series. */
  ceiling: number
  color: string
  /** Trace height in viewBox units. */
  height?: number
  label: string
  /**
   * Joins the points with a curve rather than segments.
   *
   * For a series sampled four times a second — the speedtest's live rate — the
   * segments are visible as corners, and a line that changes direction at every
   * sample reads as an unstable link when it is only a coarsely sampled one.
   * The connection log keeps the segments: there, each corner *is* a second.
   */
  smooth?: boolean
}

const WIDTH = 100

/**
 * A Catmull-Rom spline written as cubic Béziers.
 *
 * The curve passes through every sample — nothing is smoothed away, only the
 * joins between the samples are. Control points are a sixth of the span
 * between the neighbours, the standard tension: more overshoots below zero on
 * a fall, which on a throughput curve would draw a rate the line never had.
 */
function curve(points: [number, number][]): string {
  const at = (index: number) => points[Math.min(points.length - 1, Math.max(0, index))]
  let path = `M ${points[0][0].toFixed(2)},${points[0][1].toFixed(2)}`
  for (let index = 0; index < points.length - 1; index += 1) {
    const [x0, y0] = at(index - 1)
    const [x1, y1] = at(index)
    const [x2, y2] = at(index + 1)
    const [x3, y3] = at(index + 2)
    const c1 = [x1 + (x2 - x0) / 6, y1 + (y2 - y0) / 6]
    const c2 = [x2 - (x3 - x1) / 6, y2 - (y3 - y1) / 6]
    path += ` C ${c1[0].toFixed(2)},${c1[1].toFixed(2)} ${c2[0].toFixed(2)},${c2[1].toFixed(2)} ${x2.toFixed(2)},${y2.toFixed(2)}`
  }
  return path
}

export function Sparkline({ points, ceiling, color, height = 26, label, smooth = false }: Props) {
  if (points.length < 2) {
    return (
      <Box sx={{ display: 'grid', height: height * 1.4, placeItems: 'center' }}>
        <Typography color="text.disabled" sx={{ fontSize: 10 }}>
          mesure en cours…
        </Typography>
      </Box>
    )
  }

  const max = Math.max(ceiling, 1)
  const step = WIDTH / (points.length - 1)
  const y = (value: number) => height - Math.min(value / max, 1) * (height - 1.5)

  const coordinates: [number, number][] = points.map((value, index) => [index * step, y(value)])
  const line = coordinates.map(([x, pointY]) => `${x},${pointY}`).join(' ')
  const area = `0,${height} ${line} ${WIDTH},${height}`
  const path = smooth ? curve(coordinates) : ''
  const last = points[points.length - 1]
  const gradientId = `spark-${label.replace(/\W/g, '')}`

  return (
    <svg
      viewBox={`0 0 ${WIDTH} ${height}`}
      preserveAspectRatio="none"
      style={{ display: 'block', width: '100%', height: `${height * 1.4}px` }}
      role="img"
      aria-label={`Évolution du débit en ${label.toLocaleLowerCase('fr')}`}
    >
      <defs>
        <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.32" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>

      {smooth ? (
        <>
          <path d={`${path} L ${WIDTH},${height} L 0,${height} Z`} fill={`url(#${gradientId})`} />
          <path
            d={path}
            fill="none"
            stroke={color}
            strokeWidth="1.6"
            strokeLinejoin="round"
            strokeLinecap="round"
            vectorEffect="non-scaling-stroke"
          />
        </>
      ) : (
        <>
          <polygon points={area} fill={`url(#${gradientId})`} />
          <polyline
            points={line}
            fill="none"
            stroke={color}
            strokeWidth="1.1"
            strokeLinejoin="round"
            strokeLinecap="round"
            vectorEffect="non-scaling-stroke"
          />
        </>
      )}
      <circle
        cx={WIDTH}
        cy={y(last)}
        r={smooth ? '2.4' : '1.6'}
        fill={color}
        vectorEffect="non-scaling-stroke"
        style={smooth ? { transition: 'cy 240ms ease-out' } : undefined}
      />
    </svg>
  )
}
