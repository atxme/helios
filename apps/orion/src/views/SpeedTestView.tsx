import { useEffect, useRef, useState, useSyncExternalStore } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import CircularProgress from '@mui/material/CircularProgress'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import {
  Activity,
  AlertTriangle,
  ArrowDown,
  ArrowLeftRight,
  ArrowUp,
  CircleCheck,
  Clock,
  Gauge,
  Percent,
  Play,
  RefreshCw,
} from 'lucide-react'

import { Sparkline } from '../components/Sparkline'
import * as store from '../speedtest-store'
import { EMERALD, GUTTER, INK, PINE, RULE, VIOLET } from '../theme'
import type {
  ClientProfile,
  SpeedTestMode,
  SpeedTestPhase,
  SpeedTestProgress,
  SpeedTestResult,
  TunnelState,
} from '../types'

/**
 * Speedtest — one screen, one state at a time.
 *
 * # Why the screen shows one thing
 *
 * The view used to draw everything at once: a dial, two direction rows, three
 * quality figures and a history, all present whether or not they had a value.
 * At rest that is four placeholders and a « — » per figure; during a run it is
 * a screen where the part that is moving has to be found among the parts that
 * are not.
 *
 * It now has four states and shows exactly one:
 *
 * * **au repos** — what the test does, and the button that starts it;
 * * **en cours** — the leg being measured, its rate, its curve, and the
 *   figures already acquired;
 * * **terminé** — the two directions, the three qualities, and the runs before;
 * * **erreur** — why it could not run, and the way to try again.
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
 * loss and jitter. The steps are named by **direction** — «réception»,
 * «émission», «qualité» — and no screen says TCP or UDP. See `MODE` for why
 * the honest answer to «WireGuard, c'est de l'UDP» is not to measure with it.
 *
 * # Why a curve rather than a dial
 *
 * A dial states one scalar, and the scalar was already written under it. What
 * a run has to answer is whether the line is **steady**, which only the shape
 * of the ten seconds shows: the same 500 Mb/s average is a good link when it
 * is flat and a bad one when it is a sawtooth.
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

/** How many steps the run is presented as — reception, emission, quality. */
const STEPS = 3

/**
 * Ceilings the curve is allowed to adopt, in Mb/s.
 *
 * A ladder rather than `ceil(rate / 100) * 100`: that rounding gave every
 * domestic line the same 0–100 scale, so a 12 Mb/s uplink filled a tenth of
 * the height and looked broken. The ladder keeps a slow line legible and still
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

/** A latency, without its unit: the cards print the unit themselves. */
function milliseconds(value: number): string {
  return value < 10 ? decimal(value) : String(Math.round(value))
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
      return 'Mesure de la latence'
    case 'tcp_download':
      return 'Test de réception'
    case 'tcp_upload':
      return "Test d'émission"
    // The two quality legs are one step to the user: they re-run both
    // directions at a fixed rate to observe loss, not to find a speed.
    case 'udp_download':
    case 'udp_upload':
      return 'Mesure de la qualité'
    case 'complete':
      return 'Test terminé'
  }
}

/** Which of the three steps a phase belongs to, for «Étape n/3». */
function phaseStep(phase: SpeedTestPhase): number {
  switch (phase) {
    case 'preparing':
    case 'latency':
    case 'tcp_download':
      return 1
    case 'tcp_upload':
      return 2
    case 'udp_download':
    case 'udp_upload':
    case 'complete':
      return 3
  }
}

/**
 * Phases whose live rate is a throughput figure.
 *
 * The quality legs are deliberately excluded. They run *just under* the rate
 * TCP just found, so feeding their progress into the headline would walk a
 * 500 Mb/s reading down to 425 and then snap it back when the result lands —
 * the screen would look like it lost its own measurement.
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
 * The engine reports a fraction **per phase**, so a ring driven by it alone
 * would fill five times over.
 */
function overallFraction(progress: SpeedTestProgress | null): number {
  if (!progress) return 0
  const within = Math.min(1, Math.max(0, progress.fraction))
  // Weights follow the legs' real durations — two throughput legs of 10 s and
  // two quality legs of 5 s — so the ring advances at a steady pace instead of
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

/** The hour a run finished, which is all that dates it within a session. */
function clock(at: number): string {
  return new Date(at).toLocaleTimeString('fr-FR', {
    hour: '2-digit',
    minute: '2-digit',
    timeZone: 'Europe/Paris',
  })
}

/** Day and hour, for a row that may be older than the current session. */
function stamp(at: number): string {
  const date = new Date(at).toLocaleDateString('fr-FR', {
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    timeZone: 'Europe/Paris',
  })
  return `${date} · ${clock(at)}`
}

/**
 * The colour of a direction.
 *
 * Reception is the brand's green; emission is the one hue outside it. Two
 * shades of the same green made the pair readable only by its labels — see
 * `VIOLET` in the theme.
 */
function accentFor(direction: 'download' | 'upload'): string {
  return direction === 'download' ? EMERALD : VIOLET
}

/** Entrance of the block that changes when the run moves to the next step. */
const RISE = {
  animation: 'speedtest-rise 320ms cubic-bezier(0.22, 1, 0.36, 1)',
  '@keyframes speedtest-rise': {
    from: { opacity: 0, transform: 'translateY(6px)' },
    to: { opacity: 1, transform: 'none' },
  },
} as const

/** Whether the machine has been asked to keep motion to a minimum. */
function reducedMotion(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  )
}

/**
 * A number that walks to its target instead of jumping to it.
 *
 * The engine emits a rate about four times a second. Printed as it arrives, a
 * 50 px headline snaps between distant values — the figure is unreadable while
 * it moves and the screen looks like it is struggling, which is precisely the
 * thing being measured. Interpolating between frames costs no accuracy: every
 * target is reached before the next one arrives, and the last frame of a leg
 * is the figure the result confirms.
 *
 * Honoured motion preference: with `prefers-reduced-motion`, the value is
 * adopted as it comes.
 */
function useSmoothed(target: number | null, duration = 400): number | null {
  const [shown, setShown] = useState<number | null>(target)
  const current = useRef<number | null>(target)
  const frame = useRef<number | null>(null)

  useEffect(() => {
    if (frame.current !== null) {
      cancelAnimationFrame(frame.current)
      frame.current = null
    }
    if (target === null || reducedMotion()) {
      current.current = target
      setShown(target)
      return
    }
    const from = current.current
    if (from === null || from === target) {
      current.current = target
      setShown(target)
      return
    }
    const started = performance.now()
    const step = (now: number) => {
      const share = Math.min(1, (now - started) / duration)
      // Ease-out: the value arrives quickly and settles, so the figure is
      // legible for most of the interval rather than racing through it.
      const eased = 1 - (1 - share) ** 3
      const value = share >= 1 ? target : from + (target - from) * eased
      current.current = value
      setShown(value)
      frame.current = share >= 1 ? null : requestAnimationFrame(step)
    }
    frame.current = requestAnimationFrame(step)

    return () => {
      if (frame.current !== null) {
        cancelAnimationFrame(frame.current)
        frame.current = null
      }
    }
  }, [target, duration])

  return shown
}

/** Header of every state: the mark, the title, and what the run is doing. */
function Header({ subtitle, done, right }: { subtitle?: string; done?: boolean; right?: React.ReactNode }) {
  return (
    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.25 }}>
      <Box
        aria-hidden
        sx={{
          width: 32,
          height: 32,
          flexShrink: 0,
          borderRadius: '50%',
          border: `1px solid ${RULE}`,
          color: PINE,
          display: 'grid',
          placeItems: 'center',
        }}
      >
        <Gauge size={17} />
      </Box>
      <Box sx={{ minWidth: 0 }}>
        <Typography component="h2" sx={{ fontSize: 16, fontWeight: 750, letterSpacing: '-0.01em' }}>
          Speedtest
        </Typography>
        {subtitle && (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            <Typography color="text.secondary" sx={{ fontSize: 11.5 }}>
              {subtitle}
            </Typography>
            {done && <CircleCheck size={12} aria-hidden style={{ color: PINE }} />}
          </Box>
        )}
      </Box>
      {right && <Box sx={{ ml: 'auto', flexShrink: 0 }}>{right}</Box>}
    </Box>
  )
}

/**
 * One acquired figure, in a card.
 *
 * The same card serves the run in progress and the finished result: the three
 * boxes a user watches fill are the three boxes they read afterwards, in the
 * same order and the same places. Highlighting is reserved for the leg being
 * measured — a card that is merely filled stays neutral.
 */
function MetricCard({
  icon,
  label,
  value,
  unit,
  accent,
  active = false,
}: {
  icon: React.ReactNode
  label: string
  value: string
  unit: string
  accent: string
  active?: boolean
}) {
  return (
    <Paper
      variant="outlined"
      sx={{
        flex: '1 1 0',
        minWidth: 0,
        px: 1.1,
        py: 0.9,
        borderRadius: 2,
        borderColor: active ? accent : RULE,
        bgcolor: active ? `${accent}12` : 'background.paper',
        transition: 'background-color 200ms ease, border-color 200ms ease',
      }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, minWidth: 0 }}>
        <Box aria-hidden sx={{ display: 'flex', color: active ? accent : 'text.disabled' }}>
          {icon}
        </Box>
        <Typography
          noWrap
          sx={{ fontSize: 11, fontWeight: 650, color: active ? INK : 'text.secondary' }}
        >
          {label}
        </Typography>
      </Box>
      <Typography
        sx={{
          mt: 0.3,
          transition: 'color 200ms ease',
          fontSize: 19,
          fontWeight: 760,
          lineHeight: 1.1,
          color: value === '—' ? 'text.disabled' : INK,
          fontVariantNumeric: 'tabular-nums',
        }}
      >
        {value}
      </Typography>
      <Typography color="text.disabled" sx={{ fontSize: 10.5, fontWeight: 600 }}>
        {unit}
      </Typography>
    </Paper>
  )
}

/** One direction of a finished run, at the size the figure deserves. */
function ResultCard({ direction, value }: { direction: 'download' | 'upload'; value: number }) {
  const download = direction === 'download'
  const accent = accentFor(direction)
  const Arrow = download ? ArrowDown : ArrowUp

  return (
    <Paper
      variant="outlined"
      sx={{
        flex: '1 1 0',
        minWidth: 0,
        px: 1.5,
        py: 1.4,
        borderRadius: 2.5,
        borderColor: `${accent}55`,
        bgcolor: `${accent}0F`,
      }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
        <Arrow size={15} aria-hidden style={{ color: accent }} />
        <Typography sx={{ fontSize: 12.5, fontWeight: 700 }}>
          {download ? 'Réception' : 'Émission'}
        </Typography>
      </Box>
      <Typography
        sx={{
          mt: 0.4,
          fontSize: 34,
          fontWeight: 780,
          lineHeight: 1.05,
          letterSpacing: '-0.03em',
          // The direction is carried by the figure itself, not only by the
          // arrow above it: the two numbers are read side by side.
          color: download ? INK : VIOLET,
          fontVariantNumeric: 'tabular-nums',
        }}
      >
        {decimal(value)}
      </Typography>
      <Typography color="text.secondary" sx={{ fontSize: 11, fontWeight: 700 }}>
        Mb/s
      </Typography>
    </Paper>
  )
}

/**
 * The curve of the leg under way, with the scale it is drawn against.
 *
 * The ticks are on the right, where the last point is: a value is read from
 * the end of the line, so the ruler belongs there rather than at the origin.
 */
function LiveChart({ points, ceiling, color, label }: { points: number[]; ceiling: number; color: string; label: string }) {
  const ticks = [1, 0.75, 0.5, 0.25, 0].map((share) => Math.round(ceiling * share))

  return (
    <Box sx={{ display: 'flex', gap: 1, alignItems: 'stretch' }}>
      <Box sx={{ flex: '1 1 0', minWidth: 0, display: 'flex', alignItems: 'flex-end' }}>
        <Box sx={{ width: '100%', borderBottom: `1px solid ${RULE}` }}>
          <Sparkline points={points} ceiling={ceiling} color={color} height={46} label={label} smooth />
        </Box>
      </Box>
      <Box
        aria-hidden
        sx={{
          width: 36,
          flexShrink: 0,
          pl: 0.75,
          borderLeft: `1px solid ${RULE}`,
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
        }}
      >
        {ticks.map((tick, index) => (
          <Typography
            key={index}
            color="text.disabled"
            sx={{ fontSize: 9.5, lineHeight: 1, fontVariantNumeric: 'tabular-nums' }}
          >
            {tick}
          </Typography>
        ))}
      </Box>
    </Box>
  )
}

/**
 * The runs before this one, most recent first.
 *
 * One line each, and the same figures the cards above show: a history whose
 * rows carried different values than the live screen would be a second way of
 * reading the same measurement, and the two would disagree the first time one
 * of them changed.
 *
 * The current result is **excluded** — it is already the two cards, right
 * above. Repeating it as the first row would make an unchanged line look like
 * two identical measurements.
 */
function History({ records }: { records: store.SpeedTestRecord[] }) {
  if (records.length === 0) return null
  return (
    <Box>
      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.6 }}>
        <Clock size={12} aria-hidden style={{ color: PINE }} />
        <Typography sx={{ fontSize: 11.5, fontWeight: 700 }}>Historique récent</Typography>
      </Box>
      <Stack sx={{ mt: 0.5 }}>
        {records.map((record) => (
          <Box
            key={record.id}
            sx={{
              display: 'flex',
              alignItems: 'baseline',
              gap: 1,
              py: 0.7,
              borderTop: `1px solid ${RULE}`,
              fontVariantNumeric: 'tabular-nums',
            }}
          >
            <Typography color="text.secondary" sx={{ fontSize: 11, flex: '1 1 0', minWidth: 0 }} noWrap>
              {stamp(record.at)}
            </Typography>
            <Typography sx={{ fontSize: 11.5, fontWeight: 650 }}>
              {decimal(resultRate(record.result, 'download'))} / {decimal(resultRate(record.result, 'upload'))} Mb/s
            </Typography>
            <Typography color="text.secondary" sx={{ fontSize: 11, width: 52, textAlign: 'right' }}>
              {milliseconds(record.result.latency_ms)} ms
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
  const { running, result, progress, error, live, samples, history } = useSyncExternalStore(
    store.subscribe,
    store.getSnapshot,
  )

  const connected = state === 'up'
  const available = connected && profile !== null
  const run = () => void store.start(MODE)

  const phase = progress?.phase ?? 'preparing'
  const downRate = result ? resultRate(result, 'download') : live.down
  const upRate = result ? resultRate(result, 'upload') : live.up

  /**
   * Curve scale for the run in progress — it only ever grows.
   *
   * Recomputing it from the current rate made the line lurch downwards each
   * time the measurement crossed a rung of the ladder: the same throughput
   * would suddenly occupy less of the height.
   *
   * Derived rather than stored: the store carries measurements, and a scale is
   * a property of this screen. Deriving it also makes it correct on re-entry —
   * a run joined halfway shows the curve at the size its rates deserve,
   * instead of restarting at the lowest rung.
   */
  const ceiling = Math.max(ceilingFor(downRate ?? 0), ceilingFor(upRate ?? 0))

  // The headline carries the live rate while a throughput leg runs, and holds
  // the reception figure through the quality legs — the number a line is
  // usually judged by.
  const headline =
    running && isThroughputPhase(phase) ? (progress?.current_mbps ?? 0) : downRate
  const smoothHeadline = useSmoothed(headline)
  const upload = isUploadPhase(phase)
  const accent = accentFor(upload ? 'upload' : 'download')
  const latency = result ? milliseconds(result.latency_ms) : '—'

  /**
   * The launch, wherever the state puts it.
   *
   * There is no «Mesure en cours…» button: while the run works, the screen is
   * the run — the step, the rate and the curve — and a disabled button under
   * it would be one more thing to read that says what the header already says.
   */
  const startButton = (label: string, icon: React.ReactNode, fullWidth = false) => (
    <Button
      variant="contained"
      startIcon={icon}
      onClick={() => void run()}
      disabled={!available}
      fullWidth={fullWidth}
      sx={{ alignSelf: 'center', minWidth: 220, minHeight: 44, borderRadius: 2.5 }}
    >
      {label}
    </Button>
  )

  const availability = (
    <>
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
    </>
  )

  return (
    <Box sx={{ height: '100%', overflowY: 'auto', px: GUTTER, py: 1.5 }}>
      <Stack spacing={1.75} sx={{ maxWidth: 460, mx: 'auto', pb: 1 }}>
        {error && !running ? (
          <>
            <Header
              right={
                <Box
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 0.5,
                    px: 1,
                    py: 0.3,
                    borderRadius: 2,
                    bgcolor: 'rgba(155, 44, 44, 0.10)',
                    color: 'error.main',
                  }}
                >
                  <AlertTriangle size={12} aria-hidden />
                  <Typography sx={{ fontSize: 11, fontWeight: 700, color: 'inherit' }}>
                    Erreur
                  </Typography>
                </Box>
              }
            />
            <Stack spacing={1.25} sx={{ alignItems: 'center', py: 2, textAlign: 'center' }}>
              <Box
                aria-hidden
                sx={{
                  width: 92,
                  height: 92,
                  borderRadius: '50%',
                  bgcolor: 'rgba(155, 44, 44, 0.08)',
                  display: 'grid',
                  placeItems: 'center',
                  color: 'error.main',
                }}
              >
                <AlertTriangle size={38} />
              </Box>
              <Typography sx={{ fontSize: 15.5, fontWeight: 700 }}>
                Impossible de réaliser le test
              </Typography>
              <Typography
                role="alert"
                color="text.secondary"
                sx={{ fontSize: 12, lineHeight: 1.5, maxWidth: 340 }}
              >
                Speedtest impossible : {error}
              </Typography>
              {startButton('Réessayer', <RefreshCw size={16} aria-hidden />)}
              {availability}
            </Stack>
          </>
        ) : running ? (
          <>
            <Header
              subtitle="Test en cours…"
              right={
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.75 }}>
                  <Typography color="text.secondary" sx={{ fontSize: 11 }}>
                    Étape {phaseStep(phase)}/{STEPS}
                  </Typography>
                  <CircularProgress
                    variant="determinate"
                    value={overallFraction(progress) * 100}
                    size={18}
                    thickness={4.5}
                    aria-hidden
                  />
                </Box>
              }
            />

            <Stack spacing={0.25} aria-live="polite" sx={{ alignItems: 'center', pt: 0.5 }}>
              {/* Keyed on the step: the title and its arrow are replaced when
                  the run changes direction, and the replacement is seen. */}
              <Box
                key={phaseStep(phase)}
                sx={{ display: 'flex', alignItems: 'center', gap: 0.75, ...RISE }}
              >
                {isDownloadPhase(phase) ? (
                  <ArrowDown size={16} aria-hidden style={{ color: EMERALD }} />
                ) : upload ? (
                  <ArrowUp size={16} aria-hidden style={{ color: VIOLET }} />
                ) : (
                  <Activity size={16} aria-hidden style={{ color: PINE }} />
                )}
                <Typography sx={{ fontSize: 13.5, fontWeight: 700, color: upload ? VIOLET : INK }}>
                  {phaseLabel(phase)}
                </Typography>
              </Box>
              <Typography
                sx={{
                  fontSize: 50,
                  fontWeight: 780,
                  lineHeight: 1.05,
                  letterSpacing: '-0.045em',
                  color:
                    smoothHeadline === null ? 'text.disabled' : upload ? VIOLET : INK,
                  transition: 'color 240ms ease',
                  fontVariantNumeric: 'tabular-nums',
                }}
              >
                {smoothHeadline === null ? '—' : decimal(smoothHeadline)}
              </Typography>
              <Typography color="text.secondary" sx={{ fontSize: 12, fontWeight: 650 }}>
                Mb/s
              </Typography>
            </Stack>

            {/* Keyed on the direction too: the emission curve starts empty,
                and fading it in reads as a new measurement rather than as the
                reception curve collapsing. */}
            <Box key={upload ? 'up' : 'down'} sx={RISE}>
              <LiveChart points={upload ? samples.up : samples.down} ceiling={ceiling} color={accent} label={upload ? 'Émission' : 'Réception'} />
            </Box>

            <Box sx={{ display: 'flex', gap: 1 }}>
              <MetricCard
                icon={<ArrowDown size={13} />}
                label="Réception"
                value={downRate === null ? '—' : decimal(downRate)}
                unit="Mb/s"
                accent={EMERALD}
                active={isDownloadPhase(phase)}
              />
              <MetricCard
                icon={<ArrowUp size={13} />}
                label="Émission"
                value={upRate === null ? '—' : decimal(upRate)}
                unit="Mb/s"
                accent={VIOLET}
                active={upload}
              />
              <MetricCard
                icon={<ArrowLeftRight size={13} />}
                label="Ping"
                value={latency}
                unit="ms"
                accent={PINE}
              />
            </Box>
          </>
        ) : result ? (
          <>
            <Header
              subtitle="Test terminé"
              done
              right={
                <Typography color="text.secondary" sx={{ fontSize: 11 }}>
                  {history.length > 0 ? stamp(history[0].at) : ''}
                </Typography>
              }
            />

            <Box sx={{ display: 'flex', gap: 1 }} aria-live="polite">
              <ResultCard direction="download" value={resultRate(result, 'download')} />
              <ResultCard direction="upload" value={resultRate(result, 'upload')} />
            </Box>

            <Box sx={{ display: 'flex', gap: 1 }}>
              <MetricCard
                icon={<ArrowLeftRight size={13} />}
                label="Ping"
                value={latency}
                unit="ms"
                accent={PINE}
              />
              <MetricCard
                icon={<Activity size={13} />}
                label="Gigue"
                value={milliseconds(result.jitter_ms)}
                unit="ms"
                accent={PINE}
              />
              <MetricCard
                icon={<Percent size={13} />}
                label="Perte de paquets"
                value={result.udp_loss_pct === null ? '—' : decimal(result.udp_loss_pct)}
                unit="%"
                accent={PINE}
              />
            </Box>

            {startButton('Relancer le test', <RefreshCw size={16} aria-hidden />, true)}
            {availability}

            {/* The current result is the two cards above; these are the ones
                before it. */}
            <History records={history.slice(1)} />
          </>
        ) : (
          <>
            <Header subtitle="Mesurez la qualité de votre connexion réseau" />

            <Stack spacing={1.25} sx={{ alignItems: 'center', py: 1, textAlign: 'center' }}>
              <Box
                aria-hidden
                sx={{
                  width: 104,
                  height: 104,
                  borderRadius: '50%',
                  bgcolor: `${EMERALD}14`,
                  display: 'grid',
                  placeItems: 'center',
                  color: PINE,
                }}
              >
                <Gauge size={44} />
              </Box>
              <Typography sx={{ fontSize: 15.5, fontWeight: 700 }}>
                Prêt à tester votre connexion
              </Typography>
              <Typography color="text.secondary" sx={{ fontSize: 12, lineHeight: 1.5, maxWidth: 330 }}>
                Ce test mesure votre débit en réception, en émission ainsi que la latence de votre
                connexion.
              </Typography>
              {startButton('Lancer le test', <Play size={16} aria-hidden />)}
              {availability}
            </Stack>

            <Box
              sx={{
                display: 'flex',
                justifyContent: 'center',
                gap: 2.5,
                flexWrap: 'wrap',
                pt: 0.5,
                borderTop: `1px solid ${RULE}`,
              }}
            >
              {[
                { icon: <ArrowDown size={13} />, label: 'Débit descendant' },
                { icon: <ArrowUp size={13} />, label: 'Débit montant' },
                { icon: <ArrowLeftRight size={13} />, label: 'Latence' },
              ].map((hint) => (
                <Box key={hint.label} sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                  <Box aria-hidden sx={{ display: 'flex', color: 'text.disabled' }}>
                    {hint.icon}
                  </Box>
                  <Typography color="text.secondary" sx={{ fontSize: 11 }}>
                    {hint.label}
                  </Typography>
                </Box>
              ))}
            </Box>

            {/* A first launch shows nothing here; a session that has already
                measured keeps its runs in view instead of hiding them behind a
                new one. */}
            <History records={history} />
          </>
        )}
      </Stack>
    </Box>
  )
}
