import { useSyncExternalStore } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { ArrowDown, ArrowUp, Gauge } from 'lucide-react'

import * as store from '../speedtest-store'
import { EMERALD, GUTTER, INK, PINE, RULE, SLATE } from '../theme'
import type {
  ClientProfile,
  SpeedTestMode,
  SpeedTestPhase,
  SpeedTestProgress,
  SpeedTestResult,
  TunnelState,
} from '../types'

/**
 * Speedtest — one number, two directions, three qualities.
 *
 * # Why the transport is no longer a question
 *
 * The screen used to open on a TCP / UDP / TCP+UDP toggle. WireGuard carries
 * **UDP only** on the wire: whatever the in-tunnel sockets speak, the datagrams
 * that leave the machine are UDP either way. Asking the user to pick made them
 * answer a question about the measurement harness in order to learn their line
 * rate — and the wrong answer silently doubled the run.
 *
 * So the transport is decided here, once, and never surfaces. The run does
 * both: TCP finds the rate, then two short UDP legs paced just under it report
 * loss and jitter. The phases are named by **direction** — «Réception»,
 * «Émission», «Qualité» — and no screen says TCP or UDP. See `MODE` for why
 * the honest answer to «WireGuard, c'est de l'UDP» is not to measure with it.
 *
 * # The dial says what it is measuring against
 *
 * The face carries a **graduated scale**: five printed rates around the arc,
 * subdivided, and an index that crosses the band at the measurement. Without
 * them the arc stated a proportion of a ceiling the screen never named, so a
 * dial half full could equally be 5 Mb/s or 500 — which is the reading a
 * speedometer exists to make impossible, and the one this screen could not
 * give.
 *
 * The scale is not decoration on top of the old face: it replaces the
 * drop shadow and radial gradient that were removed for stating nothing. The
 * ticks are numbered off `CEILINGS`, so every rung of the ladder prints round
 * figures. The unit is the one the engine produces — megabits,
 * `bytes * 8 / s / 1e6`; an older caption said `MB/S` over the same number,
 * off by a factor of eight.
 *
 * # No captions
 *
 * Values, not prose: the headline, the paragraph about raw sockets and the
 * fixed-duration badge are gone. What the measurement is worth belongs to the
 * numbers it prints.
 */

interface Props {
  state: TunnelState
  profile: ClientProfile | null
}

/**
 * What the run measures, fixed.
 *
 * Not a default the user may override — the choice is gone from the UI, and
 * this constant is the whole of it.
 *
 * # Why it is not `udp`
 *
 * «WireGuard ne transporte que de l'UDP» is true of the wire and says nothing
 * about the payload: the tunnel carries whatever it is given, and what real
 * usage gives it is TCP. It matters here because **throughput needs
 * congestion control to be measured at all**. A UDP sender has none: driven
 * flat out it reports the speed of its own syscall loop and drops the rest,
 * which is how this screen came to show ~80 % loss on a healthy link.
 *
 * So TCP finds the rate, and the UDP legs — paced just under it — report loss
 * and jitter. Both run, the user is asked nothing, and no screen says «TCP».
 */
const MODE: SpeedTestMode = 'full'

const DIAL_BOX = 200
const DIAL_CENTER = DIAL_BOX / 2
const DIAL_RADIUS = 84
const DIAL_STROKE = 10
/** Arc opening, in degrees: a 270° sweep leaves the gap at the bottom. */
const DIAL_START = 135
const DIAL_SWEEP = 270

/**
 * The graduated scale, drawn inside the arc.
 *
 * `TICK_MAJOR` divisions carry a printed rate; each is subdivided
 * `TICK_MINOR` times. Five divisions is what makes every rung of `CEILINGS`
 * land on a round number — 10 reads 0/2/4/6/8/10, 2 500 reads
 * 0/500/1k/1,5k/2k/2,5k — so the scale never prints a figure nobody would
 * choose to write.
 */
const TICK_MAJOR = 5
const TICK_MINOR = 5
const TICK_OUTER = 75
const TICK_MAJOR_INNER = 67
const TICK_MINOR_INNER = 71
/** Radius the printed rates sit on: inside the ticks, outside the readout. */
const LABEL_RADIUS = 58
/** The index, crossing the arc band at the measured rate. */
const INDEX_INNER = 70
const INDEX_OUTER = 93

/**
 * Ceilings the dial is allowed to adopt, in Mb/s.
 *
 * A ladder rather than `ceil(rate / 100) * 100`: that rounding gave every
 * domestic line the same 0–100 scale, so a 12 Mb/s uplink filled a tenth of
 * the arc and looked broken. The ladder keeps a slow line legible and still
 * has room for a gigabit one.
 */
const CEILINGS = [10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000]

function ceilingFor(rate: number): number {
  if (!Number.isFinite(rate) || rate <= 0) return CEILINGS[0]
  return CEILINGS.find((step) => rate <= step) ?? CEILINGS[CEILINGS.length - 1]
}

function decimal(value: number, digits = 1): string {
  return value.toLocaleString('fr-FR', {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  })
}

function milliseconds(value: number): string {
  return value < 10 ? `${decimal(value)} ms` : `${Math.round(value)} ms`
}

/**
 * What the run is doing, said by direction.
 *
 * The engine's own `message` is deliberately ignored: it names the transport
 * («TCP descendant · flux continus», «Mesure de la latence UDP»), which is
 * exactly the vocabulary this screen no longer puts in front of the user.
 */
function phaseLabel(phase: SpeedTestPhase): string {
  switch (phase) {
    case 'preparing':
      return 'Préparation'
    case 'latency':
      return 'Latence'
    case 'tcp_download':
      return 'Réception'
    case 'tcp_upload':
      return 'Émission'
    // The two quality legs are one step to the user: they re-run both
    // directions at a fixed rate to observe loss, not to find a speed.
    case 'udp_download':
    case 'udp_upload':
      return 'Qualité'
    case 'complete':
      return 'Terminé'
  }
}

/**
 * Phases whose live rate is a throughput figure.
 *
 * The quality legs are deliberately excluded. They run *just under* the rate
 * TCP just found, so feeding their progress into the direction rows would
 * walk a 500 Mb/s reading down to 425 and then snap it back when the result
 * lands — the screen would look like it lost its own measurement.
 */
function isThroughputPhase(phase: SpeedTestPhase): boolean {
  return phase === 'tcp_download' || phase === 'tcp_upload'
}

function isDownloadPhase(phase: SpeedTestPhase): boolean {
  return phase === 'tcp_download'
}

function isUploadPhase(phase: SpeedTestPhase): boolean {
  return phase === 'tcp_upload'
}

/**
 * Share of the whole run already behind us.
 *
 * The engine reports a fraction **per phase**, so a bar driven by it alone
 * would fill five times over.
 */
function overallFraction(progress: SpeedTestProgress | null): number {
  if (!progress) return 0
  const within = Math.min(1, Math.max(0, progress.fraction))
  // Weights follow the legs' real durations — two throughput legs of 10 s and
  // two quality legs of 5 s — so the bar advances at a steady pace instead of
  // stalling on the long ones and leaping through the short ones.
  switch (progress.phase) {
    case 'preparing':
      return 0
    case 'latency':
      return 0.01 + within * 0.02
    case 'tcp_download':
      return 0.03 + within * 0.32
    case 'tcp_upload':
      return 0.35 + within * 0.32
    case 'udp_download':
      return 0.67 + within * 0.16
    case 'udp_upload':
      return 0.83 + within * 0.16
    case 'complete':
      return 1
  }
}

/**
 * Throughput of one direction — the TCP figure whenever there is one.
 *
 * The UDP fallbacks are a paced quality rate, not a capacity: they are worth
 * showing only when no TCP leg ran at all.
 */
function resultRate(result: SpeedTestResult, direction: 'download' | 'upload'): number {
  if (direction === 'download') {
    return result.tcp_download_mbps ?? result.udp_download_mbps ?? result.download_mbps
  }
  return result.tcp_upload_mbps ?? result.udp_upload_mbps ?? result.upload_mbps
}

function polar(angle: number, radius: number): [number, number] {
  const radians = (angle * Math.PI) / 180
  return [DIAL_CENTER + Math.cos(radians) * radius, DIAL_CENTER + Math.sin(radians) * radius]
}

/** The 270° track, drawn once: neither end moves. */
const DIAL_PATH = (() => {
  const [startX, startY] = polar(DIAL_START, DIAL_RADIUS)
  const [endX, endY] = polar(DIAL_START + DIAL_SWEEP, DIAL_RADIUS)
  return `M ${startX} ${startY} A ${DIAL_RADIUS} ${DIAL_RADIUS} 0 1 1 ${endX} ${endY}`
})()

/**
 * A printed rate, short enough to sit on the dial.
 *
 * Thousands are abbreviated because a gigabit line would otherwise print
 * «1 000» five times around a 200 px face and leave no room for the reading
 * it is there to qualify.
 */
/**
 * Type size for the reading, so a gigabit figure stays inside its own dial.
 *
 * A fixed size fitted «63,7» and ran «1 287,4» straight through the printed
 * rates on either side — the two things the face has to show at once, drawn
 * on top of each other exactly when the line is fast enough to be interesting.
 */
function readingSize(reading: string): number {
  if (reading.length <= 5) return 36
  if (reading.length === 6) return 32
  return reading.length === 7 ? 27 : 24
}

function scaleLabel(rate: number): string {
  if (rate < 1_000) return String(rate)
  const thousands = rate / 1_000
  return Number.isInteger(thousands)
    ? `${thousands}k`
    : `${thousands.toLocaleString('fr-FR', { maximumFractionDigits: 1 })}k`
}

/** Angle, in degrees, at which a rate sits on the scale. */
function angleFor(rate: number, ceiling: number): number {
  const fraction = Math.min(1, Math.max(0, rate / ceiling))
  return DIAL_START + fraction * DIAL_SWEEP
}

/**
 * The graduation the dial is read against.
 *
 * Recomputed from the ceiling rather than fixed: the ladder in `CEILINGS`
 * changes the scale as a run finds its rate, and ticks that kept their old
 * values would number a face they no longer describe.
 */
function graduations(ceiling: number) {
  const steps = TICK_MAJOR * TICK_MINOR
  return Array.from({ length: steps + 1 }, (_, index) => {
    const angle = DIAL_START + (index / steps) * DIAL_SWEEP
    const major = index % TICK_MINOR === 0
    const [outerX, outerY] = polar(angle, TICK_OUTER)
    const [innerX, innerY] = polar(angle, major ? TICK_MAJOR_INNER : TICK_MINOR_INNER)
    const rate = (index / steps) * ceiling
    return { angle, major, index, rate, outerX, outerY, innerX, innerY }
  })
}

function Dial({
  rate,
  ceiling,
  caption,
  idle,
}: {
  rate: number
  ceiling: number
  caption: string
  idle: boolean
}) {
  const fraction = Math.min(1, Math.max(0, rate / ceiling))
  // A round cap draws a dot even at nothing, so an empty arc is removed
  // rather than drawn at length zero: the dial at rest showed a bead of
  // colour parked at «0» that read as a measurement.
  const drawn = !idle && fraction > 0.002
  const ticks = graduations(ceiling)
  const reading = decimal(rate)

  return (
    <Box
      role="img"
      aria-label={`${caption} : ${decimal(rate)} mégabits par seconde, sur une échelle de 0 à ${ceiling}`}
      sx={{ position: 'relative', width: DIAL_BOX, height: DIAL_BOX, mx: 'auto' }}
    >
      <svg viewBox={`0 0 ${DIAL_BOX} ${DIAL_BOX}`} width="100%" height="100%" aria-hidden="true">
        <defs>
          <linearGradient id="speedtest-arc" x1="0" y1="1" x2="1" y2="0">
            <stop offset="0%" stopColor={PINE} />
            <stop offset="100%" stopColor={EMERALD} />
          </linearGradient>
        </defs>

        <path
          d={DIAL_PATH}
          fill="none"
          stroke={RULE}
          strokeWidth={DIAL_STROKE}
          strokeLinecap="round"
          pathLength="100"
        />
        {drawn && (
          <path
            d={DIAL_PATH}
            fill="none"
            stroke="url(#speedtest-arc)"
            strokeWidth={DIAL_STROKE}
            strokeLinecap="round"
            pathLength="100"
            strokeDasharray={`${fraction * 100} 100`}
            style={{ transition: 'stroke-dasharray 320ms ease-out' }}
          />
        )}

        {/* The scale. Without it the arc states a proportion of a ceiling the
            screen never names, so a half-filled dial could be 5 Mb/s or 500. */}
        {ticks.map((tick) => (
          <line
            key={tick.index}
            x1={tick.outerX}
            y1={tick.outerY}
            x2={tick.innerX}
            y2={tick.innerY}
            stroke={tick.major ? SLATE : RULE}
            strokeWidth={tick.major ? 1.8 : 1}
            strokeLinecap="round"
          />
        ))}
        {ticks
          .filter((tick) => tick.major)
          .map((tick) => {
            const [x, y] = polar(tick.angle, LABEL_RADIUS)
            return (
              <text
                key={`label-${tick.index}`}
                x={x}
                y={y}
                textAnchor="middle"
                dominantBaseline="central"
                fill={SLATE}
                fontSize={9}
                fontWeight={650}
                style={{ fontVariantNumeric: 'tabular-nums' }}
              >
                {scaleLabel(tick.rate)}
              </text>
            )
          })}

        {/* The index. A filled arc says how far along the scale the rate is;
            this says where on it the rate is, which is the reading a dial is
            for. */}
        {drawn && (
          <line
            x1={polar(angleFor(rate, ceiling), INDEX_INNER)[0]}
            y1={polar(angleFor(rate, ceiling), INDEX_INNER)[1]}
            x2={polar(angleFor(rate, ceiling), INDEX_OUTER)[0]}
            y2={polar(angleFor(rate, ceiling), INDEX_OUTER)[1]}
            stroke={INK}
            strokeWidth={2.5}
            strokeLinecap="round"
          />
        )}
      </svg>

      <Box
        sx={{
          position: 'absolute',
          inset: 0,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          pointerEvents: 'none',
        }}
      >
        {/* Caption above the figure, not below it: the printed rates now
            occupy the bottom of the face, where the caption used to sit. */}
        <Typography color="text.secondary" sx={{ mb: 0.75, fontSize: 11.5, fontWeight: 650 }}>
          {caption}
        </Typography>
        <Typography
          sx={{
            color: idle ? 'text.disabled' : INK,
            fontSize: readingSize(reading),
            fontWeight: 760,
            letterSpacing: '-0.05em',
            lineHeight: 1,
            fontVariantNumeric: 'tabular-nums',
          }}
        >
          {idle ? '—' : reading}
        </Typography>
        <Typography
          sx={{ mt: 0.5, color: PINE, fontSize: 10.5, fontWeight: 750, letterSpacing: '0.1em' }}
        >
          Mb/s
        </Typography>
      </Box>
    </Box>
  )
}

/**
 * One direction, with its bar.
 *
 * Both bars share a scale — the faster of the two — so their lengths compare.
 * Scaling each to its own maximum would draw a 4 Mb/s uplink and a 400 Mb/s
 * downlink as two identical bars.
 */
function DirectionRow({
  direction,
  value,
  ceiling,
  active,
}: {
  direction: 'download' | 'upload'
  value: number | null
  ceiling: number
  active: boolean
}) {
  const download = direction === 'download'
  const filled = value === null ? 0 : Math.min(1, Math.max(0, value / ceiling))

  return (
    <Box sx={{ minWidth: 0 }}>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
        {download ? (
          <ArrowDown size={14} aria-hidden style={{ color: active ? EMERALD : PINE }} />
        ) : (
          <ArrowUp size={14} aria-hidden style={{ color: active ? EMERALD : PINE }} />
        )}
        <Typography
          sx={{ fontSize: 12, fontWeight: active ? 700 : 600, color: active ? INK : 'text.secondary' }}
        >
          {download ? 'Réception' : 'Émission'}
        </Typography>
        <Typography
          sx={{
            ml: 'auto',
            color: value === null ? 'text.disabled' : INK,
            fontSize: 15,
            fontWeight: 720,
            fontVariantNumeric: 'tabular-nums',
          }}
        >
          {value === null ? '—' : `${decimal(value)} Mb/s`}
        </Typography>
      </Box>
      <Box
        aria-hidden
        sx={{
          mt: 0.6,
          height: 5,
          borderRadius: 3,
          bgcolor: RULE,
          overflow: 'hidden',
        }}
      >
        <Box
          sx={{
            width: `${filled * 100}%`,
            height: '100%',
            borderRadius: 3,
            background: `linear-gradient(90deg, ${PINE}, ${EMERALD})`,
            transition: 'width 320ms ease-out',
          }}
        />
      </Box>
    </Box>
  )
}

function Quality({ label, value }: { label: string; value: string }) {
  return (
    <Box sx={{ flex: '1 1 0', minWidth: 0, textAlign: 'center' }}>
      <Typography variant="overline" color="text.disabled" sx={{ display: 'block', fontSize: 9 }}>
        {label}
      </Typography>
      <Typography
        sx={{ mt: 0.2, fontSize: 15, fontWeight: 700, fontVariantNumeric: 'tabular-nums' }}
      >
        {value}
      </Typography>
    </Box>
  )
}

/** The hour a run finished, which is all that dates it usefully. */
function clock(at: number): string {
  return new Date(at).toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' })
}

/**
 * The last runs, oldest on the right.
 *
 * One line each, and the same three figures the dial shows: a history whose
 * rows carried different values than the live screen would be a second way of
 * reading the same measurement, and the two would disagree the first time one
 * of them changed.
 *
 * The current result is **excluded** — it is already the dial, right above.
 * Repeating it as the first row would make an unchanged line look like two
 * identical measurements.
 */
function History({ records }: { records: store.SpeedTestRecord[] }) {
  if (records.length === 0) return null
  return (
    <Box>
      <Typography variant="overline" color="text.disabled" sx={{ display: 'block', fontSize: 9 }}>
        Mesures précédentes
      </Typography>
      <Stack sx={{ mt: 0.5, borderTop: `1px solid ${RULE}` }}>
        {records.map((record) => (
          <Box
            key={record.id}
            sx={{
              display: 'flex',
              alignItems: 'baseline',
              gap: 1,
              py: 0.6,
              borderBottom: `1px solid ${RULE}`,
              fontVariantNumeric: 'tabular-nums',
            }}
          >
            <Typography color="text.disabled" sx={{ fontSize: 11, width: 44, flexShrink: 0 }}>
              {clock(record.at)}
            </Typography>
            <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 0.4, flex: '1 1 0' }}>
              <ArrowDown size={11} aria-hidden style={{ color: EMERALD }} />
              <Typography sx={{ fontSize: 12, fontWeight: 700 }}>
                {decimal(resultRate(record.result, 'download'))}
              </Typography>
              <Typography color="text.disabled" sx={{ fontSize: 10 }}>
                Mb/s
              </Typography>
            </Box>
            <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 0.4, flex: '1 1 0' }}>
              <ArrowUp size={11} aria-hidden style={{ color: PINE }} />
              <Typography sx={{ fontSize: 12, fontWeight: 700 }}>
                {decimal(resultRate(record.result, 'upload'))}
              </Typography>
              <Typography color="text.disabled" sx={{ fontSize: 10 }}>
                Mb/s
              </Typography>
            </Box>
            <Typography color="text.disabled" sx={{ fontSize: 11, width: 56, textAlign: 'right' }}>
              {milliseconds(record.result.latency_ms)}
            </Typography>
          </Box>
        ))}
      </Stack>
    </Box>
  )
}

/** Measures the established WireGuard data plane with direct UDP traffic. */
export function SpeedTestView({ state, profile }: Props) {
  // The run lives above this component: leaving the screen mid-measurement
  // used to unmount it and lose forty seconds of work, silently. See
  // `speedtest-store`.
  const { running, result, progress, error, live, history } = useSyncExternalStore(
    store.subscribe,
    store.getSnapshot,
  )

  /**
   * Dial scale for the run in progress — it only ever grows.
   *
   * Recomputing it from the current rate made the arc lurch backwards each
   * time the measurement crossed a rung of the ladder: the same throughput
   * would suddenly occupy less of the dial.
   *
   * Derived rather than stored: the store carries measurements, and a scale is
   * a property of this screen. Deriving it also makes it correct on re-entry —
   * a run joined halfway shows the arc at the size its rates deserve, instead
   * of restarting at the lowest rung.
   */
  const ceiling = Math.max(
    ceilingFor(live.down ?? 0),
    ceilingFor(live.up ?? 0),
    result ? ceilingFor(Math.max(resultRate(result, 'download'), resultRate(result, 'upload'))) : CEILINGS[0],
  )

  const connected = state === 'up'
  const available = connected && profile !== null

  const run = () => void store.start(MODE)

  const phase = progress?.phase ?? 'preparing'
  const downRate = result ? resultRate(result, 'download') : live.down
  const upRate = result ? resultRate(result, 'upload') : live.up

  // The dial carries the live rate while a throughput leg runs, and holds the
  // reception figure through the quality legs and at rest — the number a line
  // is usually judged by.
  const dialRate =
    running && isThroughputPhase(phase) ? (progress?.current_mbps ?? 0) : (downRate ?? 0)
  const idle = !running && result === null
  const caption = running ? phaseLabel(phase) : result ? 'Réception' : 'Prêt'
  const barCeiling = Math.max(downRate ?? 0, upRate ?? 0, 1)
  const fraction = running ? overallFraction(progress) : 0

  return (
    <Box sx={{ height: '100%', overflowY: 'auto', px: GUTTER, py: 1.5 }}>
      <Stack spacing={2} sx={{ maxWidth: 460, mx: 'auto', pb: 1 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Gauge size={18} aria-hidden style={{ color: PINE }} />
          <Typography component="h2" sx={{ fontSize: 13, fontWeight: 700 }}>
            Speedtest
          </Typography>
        </Box>

        <Box>
          <Dial rate={dialRate} ceiling={ceiling} caption={caption} idle={idle} />
          {/* Progress of the whole run, not of the current phase: a bar that
              refills at each direction tells the user nothing about how long
              is left. */}
          <Box
            aria-hidden
            sx={{
              mt: 0.5,
              mx: 'auto',
              width: DIAL_BOX,
              height: 3,
              borderRadius: 2,
              bgcolor: RULE,
              opacity: running ? 1 : 0,
              transition: 'opacity 200ms ease',
              overflow: 'hidden',
            }}
          >
            <Box
              sx={{
                width: `${fraction * 100}%`,
                height: '100%',
                borderRadius: 2,
                bgcolor: EMERALD,
                transition: 'width 320ms linear',
              }}
            />
          </Box>
        </Box>

        <Stack spacing={1.25} aria-live="polite">
          <DirectionRow
            direction="download"
            value={downRate}
            ceiling={barCeiling}
            active={running && isDownloadPhase(phase)}
          />
          <DirectionRow
            direction="upload"
            value={upRate}
            ceiling={barCeiling}
            active={running && isUploadPhase(phase)}
          />
        </Stack>

        {result && (
          <Box
            aria-live="polite"
            sx={{
              display: 'flex',
              gap: 1,
              py: 1.25,
              borderTop: `1px solid ${RULE}`,
              borderBottom: `1px solid ${RULE}`,
            }}
          >
            <Quality label="Latence" value={milliseconds(result.latency_ms)} />
            <Quality label="Gigue" value={milliseconds(result.jitter_ms)} />
            <Quality
              label="Perte"
              value={result.udp_loss_pct === null ? '—' : `${decimal(result.udp_loss_pct)} %`}
            />
          </Box>
        )}

        <Button
          variant="contained"
          startIcon={<Gauge size={17} aria-hidden />}
          onClick={() => void run()}
          disabled={running || !available}
          aria-busy={running}
          sx={{ alignSelf: 'center', minWidth: 220, minHeight: 44, borderRadius: 2.5 }}
        >
          {running ? 'Mesure en cours…' : result ? 'Relancer le speedtest' : 'Lancer le speedtest'}
        </Button>

        {!profile && (
          <Typography color="text.secondary" sx={{ fontSize: 12, textAlign: 'center' }}>
            Aucun profil sélectionné.
          </Typography>
        )}
        {profile && !connected && (
          <Typography color="text.secondary" sx={{ fontSize: 12, textAlign: 'center' }}>
            Connectez le profil « {profile.name} » avant de lancer le test.
          </Typography>
        )}

        {error && (
          <Typography role="alert" color="error.main" sx={{ fontSize: 12, lineHeight: 1.5, textAlign: 'center' }}>
            Speedtest impossible : {error}
          </Typography>
        )}

        {/* The current result is the dial; these are the ones before it. */}
        <History records={result ? history.slice(1) : history} />
      </Stack>
    </Box>
  )
}
