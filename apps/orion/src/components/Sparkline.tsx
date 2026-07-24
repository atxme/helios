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
}

const WIDTH = 100

export function Sparkline({ points, ceiling, color, height = 26, label }: Props) {
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

  const line = points.map((value, index) => `${index * step},${y(value)}`).join(' ')
  const area = `0,${height} ${line} ${WIDTH},${height}`
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
      <circle cx={WIDTH} cy={y(last)} r="1.6" fill={color} vectorEffect="non-scaling-stroke" />
    </svg>
  )
}
