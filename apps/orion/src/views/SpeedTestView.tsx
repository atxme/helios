import { useEffect, useState } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { ArrowDown, ArrowUp, Gauge } from 'lucide-react'

import * as api from '../api'
import { EMERALD, GUTTER, INK, PINE, RULE } from '../theme'
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
 * So the transport is decided here, once, and never surfaces: the run is UDP,
 * and the phases are named by **direction** rather than by protocol. The other
 * two modes stay in `orion-core` — `helios-ctl` still reaches them, and a
 * transport comparison is a diagnostic, not a client feature.
 *
 * # The dial lost its needle
 *
 * A needle, nine ticks, a drop shadow and a radial gradient stated one scalar.
 * What remains is the arc that fills, because it is the part that reads at a
 * glance, and the value at its centre in the unit the engine actually
 * produces — megabits, `bytes * 8 / s / 1e6`. The old caption said `MB/S` over
 * that same number, off by a factor of eight.
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
 * The transport this screen measures, fixed.
 *
 * Not a default the user may override — the choice is gone from the UI, and
 * this constant is the whole of it.
 */
const MODE: SpeedTestMode = 'udp'

const DIAL_BOX = 200
const DIAL_CENTER = DIAL_BOX / 2
const DIAL_RADIUS = 84
const DIAL_STROKE = 13
/** Arc opening, in degrees: a 270° sweep leaves the gap at the bottom. */
const DIAL_START = 135
const DIAL_SWEEP = 270

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
    case 'udp_download':
      return 'Réception'
    case 'tcp_upload':
    case 'udp_upload':
      return 'Émission'
    case 'complete':
      return 'Terminé'
  }
}

function isUploadPhase(phase: SpeedTestPhase): boolean {
  return phase === 'tcp_upload' || phase === 'udp_upload'
}

function isDownloadPhase(phase: SpeedTestPhase): boolean {
  return phase === 'tcp_download' || phase === 'udp_download'
}

/**
 * Share of the whole run already behind us.
 *
 * The engine reports a fraction **per phase**, so a bar driven by it alone
 * would fill three times. Latency is given a thin slice because it is short;
 * the two transfers split the rest evenly, since they run for the same fixed
 * interval.
 */
function overallFraction(progress: SpeedTestProgress | null): number {
  if (!progress) return 0
  const within = Math.min(1, Math.max(0, progress.fraction))
  switch (progress.phase) {
    case 'preparing':
      return 0
    case 'latency':
      return 0.02 + within * 0.06
    case 'tcp_download':
    case 'udp_download':
      return 0.08 + within * 0.46
    case 'tcp_upload':
    case 'udp_upload':
      return 0.54 + within * 0.46
    case 'complete':
      return 1
  }
}

function resultRate(result: SpeedTestResult, direction: 'download' | 'upload'): number {
  if (direction === 'download') {
    return result.udp_download_mbps ?? result.tcp_download_mbps ?? result.download_mbps
  }
  return result.udp_upload_mbps ?? result.tcp_upload_mbps ?? result.upload_mbps
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

  return (
    <Box
      role="img"
      aria-label={`${caption} : ${decimal(rate)} mégabits par seconde`}
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
        <path
          d={DIAL_PATH}
          fill="none"
          stroke="url(#speedtest-arc)"
          strokeWidth={DIAL_STROKE}
          strokeLinecap="round"
          pathLength="100"
          strokeDasharray="100"
          strokeDashoffset={100 - fraction * 100}
          style={{
            transition: 'stroke-dashoffset 320ms ease-out',
            opacity: idle ? 0 : 1,
          }}
        />
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
        <Typography
          sx={{
            color: idle ? 'text.disabled' : INK,
            fontSize: 40,
            fontWeight: 760,
            letterSpacing: '-0.05em',
            lineHeight: 1,
            fontVariantNumeric: 'tabular-nums',
          }}
        >
          {idle ? '—' : decimal(rate)}
        </Typography>
        <Typography
          sx={{ mt: 0.5, color: PINE, fontSize: 11, fontWeight: 750, letterSpacing: '0.1em' }}
        >
          Mb/s
        </Typography>
        <Typography color="text.secondary" sx={{ mt: 1, fontSize: 11.5, fontWeight: 650 }}>
          {caption}
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

/** Measures the established WireGuard data plane with direct UDP traffic. */
export function SpeedTestView({ state, profile }: Props) {
  const [result, setResult] = useState<SpeedTestResult | null>(null)
  const [progress, setProgress] = useState<SpeedTestProgress | null>(null)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  /**
   * Last rate seen in each direction while the run is under way.
   *
   * Kept here rather than read off `progress`: the reception figure has to
   * stay on screen once emission takes over, otherwise the row the user was
   * just watching blanks out halfway through the run.
   */
  const [live, setLive] = useState<{ down: number | null; up: number | null }>({
    down: null,
    up: null,
  })
  /**
   * Dial scale for the run in progress — it only ever grows.
   *
   * Recomputing it from the current rate made the arc lurch backwards each
   * time the measurement crossed a rung of the ladder: the same throughput
   * would suddenly occupy less of the dial.
   */
  const [ceiling, setCeiling] = useState(CEILINGS[0])

  const connected = state === 'up'
  const available = connected && profile !== null

  useEffect(() => {
    const unlisten = api.onSpeedTestProgress((update) => {
      setProgress(update)
      if (isDownloadPhase(update.phase)) {
        setLive((seen) => ({ ...seen, down: update.current_mbps }))
      } else if (isUploadPhase(update.phase)) {
        setLive((seen) => ({ ...seen, up: update.current_mbps }))
      }
      setCeiling((seen) => Math.max(seen, ceilingFor(update.current_mbps)))
    })
    return () => {
      unlisten.then((remove) => remove())
    }
  }, [])

  const run = async () => {
    setRunning(true)
    setError(null)
    setResult(null)
    setProgress(null)
    setLive({ down: null, up: null })
    setCeiling(CEILINGS[0])
    try {
      const measured = await api.runSpeedTest(MODE)
      setResult(measured)
      setCeiling((seen) =>
        Math.max(seen, ceilingFor(Math.max(resultRate(measured, 'download'), resultRate(measured, 'upload')))),
      )
    } catch (cause) {
      setError(String(cause))
      // The dial falls back to «—» on failure; leaving the rows on the last
      // frames received would have the screen state a rate it just disowned.
      setLive({ down: null, up: null })
      setProgress(null)
    } finally {
      setRunning(false)
    }
  }

  const phase = progress?.phase ?? 'preparing'
  const downRate = result ? resultRate(result, 'download') : live.down
  const upRate = result ? resultRate(result, 'upload') : live.up

  // The dial carries the live rate while measuring, then rests on reception —
  // the figure a line is usually judged by.
  const dialRate = running ? (progress?.current_mbps ?? 0) : (downRate ?? 0)
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
      </Stack>
    </Box>
  )
}
