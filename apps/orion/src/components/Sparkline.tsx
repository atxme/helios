/**
 * Courbe de débit — une aire, une ligne, un point terminal accentué.
 *
 * Les deux séries (↓ et ↑) partagent la **même** échelle verticale, calculée sur
 * le maximum des deux : sinon un pic de 2 kB/s en émission aurait la même
 * hauteur qu'un pic de 20 MB/s en réception, ce qui est un mensonge visuel.
 */

interface Props {
  /** Historique, du plus ancien au plus récent. */
  points: number[]
  /** Plafond commun aux séries comparées. */
  ceiling: number
  color: string
  /** Hauteur du tracé en unités de viewBox. */
  height?: number
  label: string
}

const WIDTH = 100

export function Sparkline({ points, ceiling, color, height = 26, label }: Props) {
  if (points.length < 2) {
    return (
      <div
        className="grid place-items-center text-[10px] text-slate-600"
        style={{ height: `${height * 1.4}px` }}
      >
        mesure en cours…
      </div>
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
      className="w-full"
      style={{ height: `${height * 1.4}px` }}
      role="img"
      aria-label={label}
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
      {/* Point terminal — repère la valeur courante dans le tracé. */}
      <circle cx={WIDTH} cy={y(last)} r="1.6" fill={color} vectorEffect="non-scaling-stroke" />
    </svg>
  )
}
