import { useEffect, useState } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import ToggleButton from '@mui/material/ToggleButton'
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup'
import Typography from '@mui/material/Typography'
import { ArrowDown, ArrowUp, Gauge, RotateCcw, Timer } from 'lucide-react'

import * as api from '../api'
import { EMERALD, GUTTER, INK, MINT, PINE, RULE, SLATE } from '../theme'
import type {
  ClientProfile,
  SpeedTestMode,
  SpeedTestPhase,
  SpeedTestProgress,
  SpeedTestResult,
  TunnelState,
} from '../types'

interface Props {
  state: TunnelState
  profile: ClientProfile | null
}

const TEST_DURATION_SECS = 20
const DIAL_CENTER = 150
const DIAL_RADIUS = 112

function decimal(value: number, digits = 1): string {
  return value.toLocaleString('fr-FR', {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  })
}

function duration(milliseconds: number): string {
  if (milliseconds < 1_000) return `${Math.max(1, Math.round(milliseconds))} ms`
  return `${decimal(milliseconds / 1_000)} s`
}

function bytes(value: number): string {
  if (value < 1_024 * 1_024) return `${decimal(value / 1_024)} Ko`
  return `${decimal(value / (1_024 * 1_024))} Mo`
}

function phaseLabel(phase: SpeedTestPhase): string {
  switch (phase) {
    case 'preparing':
      return 'Préparation'
    case 'latency':
      return 'Latence'
    case 'tcp_download':
      return 'TCP descendant'
    case 'tcp_upload':
      return 'TCP montant'
    case 'udp_download':
      return 'UDP descendant'
    case 'udp_upload':
      return 'UDP montant'
    case 'complete':
      return 'Terminé'
  }
}

function modeDescription(mode: SpeedTestMode): string {
  if (mode === 'tcp') return 'Débit brut principal · quatre flux persistants'
  if (mode === 'udp') return 'Débit, perte de paquets et jitter'
  return 'TCP principal puis qualification UDP'
}

function resultRate(result: SpeedTestResult, direction: 'download' | 'upload'): number {
  if (direction === 'download') {
    return result.tcp_download_mbps ?? result.udp_download_mbps ?? result.download_mbps
  }
  return result.tcp_upload_mbps ?? result.udp_upload_mbps ?? result.upload_mbps
}

function gaugeScale(rate: number): number {
  if (!Number.isFinite(rate) || rate <= 0) return 100
  return Math.max(100, Math.ceil(rate / 100) * 100)
}

function gaugeFraction(rate: number): number {
  const scale = gaugeScale(rate)
  return Math.min(1, Math.max(0, rate / scale))
}

function point(angle: number, radius: number): [number, number] {
  const radians = (angle * Math.PI) / 180
  return [DIAL_CENTER + Math.cos(radians) * radius, DIAL_CENTER + Math.sin(radians) * radius]
}

function arcPath(): string {
  const [startX, startY] = point(135, DIAL_RADIUS)
  const [endX, endY] = point(405, DIAL_RADIUS)
  return `M ${startX} ${startY} A ${DIAL_RADIUS} ${DIAL_RADIUS} 0 1 1 ${endX} ${endY}`
}

const DIAL_PATH = arcPath()

function Dial({ rate, label, running }: { rate: number; label: string; running: boolean }) {
  const fraction = gaugeFraction(rate)
  const pointerRotation = 225 + fraction * 270
  const scale = gaugeScale(rate)
  const ticks = Array.from({ length: 9 }, (_, index) => {
    const angle = 135 + (index / 8) * 270
    const [x1, y1] = point(angle, 92)
    const [x2, y2] = point(angle, index === 0 || index === 8 ? 101 : 98)
    return { x1, y1, x2, y2 }
  })

  return (
    <Box
      role="img"
      aria-label={`${label} : ${decimal(rate)} mégabits par seconde`}
      sx={{ position: 'relative', width: 'min(100%, 370px)', aspectRatio: '1', mx: 'auto' }}
    >
      <svg viewBox="0 0 300 300" width="100%" height="100%" aria-hidden="true">
        <defs>
          <linearGradient id="speedtest-dial-gradient" x1="0" y1="1" x2="1" y2="0">
            <stop offset="0%" stopColor={PINE} />
            <stop offset="100%" stopColor={EMERALD} />
          </linearGradient>
          <filter id="speedtest-dial-shadow" x="-30%" y="-30%" width="160%" height="160%">
            <feDropShadow dx="0" dy="4" stdDeviation="5" floodColor={PINE} floodOpacity="0.16" />
          </filter>
        </defs>

        <circle cx={DIAL_CENTER} cy={DIAL_CENTER} r="125" fill="#FFFFFF" opacity="0.74" />
        <path
          d={DIAL_PATH}
          fill="none"
          stroke={RULE}
          strokeWidth="14"
          strokeLinecap="round"
          pathLength="100"
        />
        <path
          d={DIAL_PATH}
          fill="none"
          stroke="url(#speedtest-dial-gradient)"
          strokeWidth="14"
          strokeLinecap="round"
          pathLength="100"
          strokeDasharray="100"
          strokeDashoffset={100 - fraction * 100}
          style={{ transition: 'stroke-dashoffset 320ms ease-out' }}
        />
        {ticks.map((tick, index) => (
          <line
            key={index}
            x1={tick.x1}
            y1={tick.y1}
            x2={tick.x2}
            y2={tick.y2}
            stroke={index === 0 || index === 8 ? PINE : SLATE}
            strokeWidth={index === 0 || index === 8 ? 2.5 : 1.5}
            strokeLinecap="round"
          />
        ))}
        <line
          x1={DIAL_CENTER}
          y1={DIAL_CENTER}
          x2={DIAL_CENTER}
          y2="66"
          stroke={PINE}
          strokeWidth="4"
          strokeLinecap="round"
          filter="url(#speedtest-dial-shadow)"
          style={{
            transformOrigin: `${DIAL_CENTER}px ${DIAL_CENTER}px`,
            transform: `rotate(${pointerRotation}deg)`,
            transition: 'transform 320ms ease-out',
          }}
        />
        <circle cx={DIAL_CENTER} cy={DIAL_CENTER} r="11" fill={PINE} />
        <circle cx={DIAL_CENTER} cy={DIAL_CENTER} r="4" fill="#FFFFFF" />
      </svg>

      <Box
        sx={{
          position: 'absolute',
          inset: '38% 0 auto',
          textAlign: 'center',
          pointerEvents: 'none',
        }}
      >
        <Typography
          sx={{
            color: INK,
            fontSize: { xs: 34, sm: 42 },
            fontWeight: 760,
            letterSpacing: '-0.055em',
            lineHeight: 1,
            fontVariantNumeric: 'tabular-nums',
          }}
        >
          {decimal(rate)}
        </Typography>
        <Typography sx={{ mt: 0.45, color: PINE, fontSize: 11, fontWeight: 750, letterSpacing: '0.12em' }}>
          MB/S
        </Typography>
        <Typography color="text.secondary" sx={{ mt: 1.25, fontSize: 11, fontWeight: 650 }}>
          {running ? label : rate > 0 ? label : 'Prêt à mesurer'}
        </Typography>
      </Box>

      <Typography
        color="text.disabled"
        sx={{
          position: 'absolute',
          left: 0,
          right: 0,
          bottom: '6%',
          textAlign: 'center',
          fontSize: 10,
          fontFamily: 'monospace',
        }}
      >
        0 — {decimal(scale, 0)} Mb/s
      </Typography>
    </Box>
  )
}

function ResultMetric({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <Paper
      variant="outlined"
      sx={{
        p: 1.5,
        flex: '1 1 165px',
        minWidth: 0,
        borderRadius: 2,
        backgroundColor: '#FFFFFFB8',
      }}
    >
      <Typography variant="overline" color="text.secondary">
        {label}
      </Typography>
      <Typography sx={{ mt: 0.5, fontSize: 21, fontWeight: 720, fontVariantNumeric: 'tabular-nums' }}>
        {value}
      </Typography>
      <Typography color="text.secondary" sx={{ mt: 0.25, fontSize: 11 }}>
        {detail}
      </Typography>
    </Paper>
  )
}

function DirectionMetric({
  direction,
  value,
  active,
}: {
  direction: 'download' | 'upload'
  value: number | null
  active: boolean
}) {
  const download = direction === 'download'
  return (
    <Box
      sx={{
        display: 'flex',
        alignItems: 'center',
        gap: 1,
        flex: '1 1 145px',
        minWidth: 0,
        opacity: active || value !== null ? 1 : 0.48,
      }}
    >
      <Box
        sx={{
          display: 'grid',
          placeItems: 'center',
          width: 30,
          height: 30,
          flexShrink: 0,
          borderRadius: '50%',
          color: PINE,
          backgroundColor: MINT,
        }}
      >
        {download ? <ArrowDown size={16} aria-hidden /> : <ArrowUp size={16} aria-hidden />}
      </Box>
      <Box sx={{ minWidth: 0 }}>
        <Typography color="text.secondary" sx={{ fontSize: 10, fontWeight: 700, letterSpacing: '0.08em' }}>
          {download ? 'DESCENDANT' : 'MONTANT'}
        </Typography>
        <Typography sx={{ fontSize: 18, fontWeight: 720, fontVariantNumeric: 'tabular-nums' }}>
          {value === null ? '—' : `${decimal(value)} Mb/s`}
        </Typography>
      </Box>
    </Box>
  )
}

/** Measures the established WireGuard data plane with direct socket traffic. */
export function SpeedTestView({ state, profile }: Props) {
  const [result, setResult] = useState<SpeedTestResult | null>(null)
  const [progress, setProgress] = useState<SpeedTestProgress | null>(null)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [mode, setMode] = useState<SpeedTestMode>('tcp')
  const connected = state === 'up'
  const available = connected && profile !== null

  useEffect(() => {
    const unlisten = api.onSpeedTestProgress(setProgress)
    return () => {
      unlisten.then((remove) => remove())
    }
  }, [])

  const run = async () => {
    setRunning(true)
    setError(null)
    setResult(null)
    setProgress(null)
    try {
      setResult(await api.runSpeedTest(mode))
    } catch (cause) {
      setError(String(cause))
    } finally {
      setRunning(false)
    }
  }

  const activeRate = running && progress ? progress.current_mbps : result ? resultRate(result, 'download') : 0
  const activeLabel = running && progress ? phaseLabel(progress.phase) : result ? 'Débit descendant' : 'Prêt à mesurer'
  const activePhase = progress?.phase ?? 'preparing'
  const isUpload = activePhase.endsWith('upload')
  const downloadRate = result ? resultRate(result, 'download') : null
  const uploadRate = result ? resultRate(result, 'upload') : null

  return (
    <Box sx={{ height: '100%', overflowY: 'auto', px: GUTTER, py: 1.5 }}>
      <Stack spacing={1.75} sx={{ maxWidth: 820, mx: 'auto', pb: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Gauge size={18} aria-hidden style={{ color: PINE }} />
          <Typography component="h2" sx={{ fontSize: 13, fontWeight: 700 }}>
            Speedtest réseau
          </Typography>
          {result && (
            <Button
              size="small"
              variant="text"
              color="inherit"
              startIcon={<RotateCcw size={14} aria-hidden />}
              onClick={() => void run()}
              disabled={running || !available}
              sx={{ ml: 'auto', color: 'text.secondary', fontSize: 11 }}
            >
              Refaire
            </Button>
          )}
        </Box>

        <Paper
          variant="outlined"
          sx={{
            overflow: 'hidden',
            borderRadius: 3,
            background: `radial-gradient(circle at 50% 38%, ${MINT} 0%, #FFFFFF 56%)`,
          }}
        >
          <Box sx={{ px: { xs: 1.5, sm: 3 }, pt: { xs: 2, sm: 2.5 } }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', gap: 2, alignItems: 'flex-start' }}>
              <Box>
                <Typography component="h3" sx={{ fontSize: { xs: 19, sm: 22 }, fontWeight: 750, letterSpacing: '-0.03em' }}>
                  La ligne WireGuard, au ras du réseau
                </Typography>
                <Typography color="text.secondary" sx={{ mt: 0.65, maxWidth: 590, fontSize: 11.5, lineHeight: 1.5 }}>
                  Flux TCP et UDP directs entre Orion et Helios. Aucun HTTP, aucun header, aucune requête répétée.
                </Typography>
              </Box>
              <Box
                sx={{
                  display: { xs: 'none', sm: 'flex' },
                  alignItems: 'center',
                  gap: 0.75,
                  flexShrink: 0,
                  px: 1.25,
                  py: 0.75,
                  border: `1px solid ${RULE}`,
                  borderRadius: 2,
                  backgroundColor: '#FFFFFFA8',
                }}
              >
                <Timer size={14} aria-hidden style={{ color: PINE }} />
                <Typography sx={{ color: PINE, fontSize: 11, fontWeight: 750 }}>20 s / direction</Typography>
              </Box>
            </Box>

            <Dial rate={activeRate} label={activeLabel} running={running} />

            <Box
              sx={{
                display: 'flex',
                gap: { xs: 1.5, sm: 4 },
                px: { xs: 1, sm: 5 },
                pb: 2,
                justifyContent: 'center',
              }}
            >
              <DirectionMetric direction="download" value={downloadRate} active={running && !isUpload} />
              <DirectionMetric direction="upload" value={uploadRate} active={running && isUpload} />
            </Box>
          </Box>

          <Box sx={{ borderTop: `1px solid ${RULE}`, px: { xs: 1.5, sm: 3 }, py: 1.5 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', gap: 1, alignItems: 'center', mb: 1 }}>
              <Typography sx={{ fontSize: 11, fontWeight: 750 }}>Mode de mesure</Typography>
              <Typography color="text.secondary" sx={{ fontSize: 10.5 }}>
                {modeDescription(mode)}
              </Typography>
            </Box>
            <ToggleButtonGroup
              exclusive
              fullWidth
              size="small"
              value={mode}
              onChange={(_, value: SpeedTestMode | null) => value && setMode(value)}
              aria-label="Méthode du speedtest"
              disabled={running}
              sx={{
                '& .MuiToggleButton-root': { py: 0.8, fontSize: 11, borderColor: RULE },
                '& .Mui-selected': { color: `${PINE} !important`, backgroundColor: `${MINT} !important`, fontWeight: 750 },
              }}
            >
              <ToggleButton value="tcp">TCP brut</ToggleButton>
              <ToggleButton value="udp">UDP brut</ToggleButton>
              <ToggleButton value="full">TCP + UDP</ToggleButton>
            </ToggleButtonGroup>
            <Typography color="text.disabled" sx={{ display: { xs: 'block', sm: 'none' }, mt: 1, fontSize: 10 }}>
              Durée fixe : {TEST_DURATION_SECS} secondes par direction
            </Typography>
          </Box>
        </Paper>

        {!profile && (
          <Typography color="text.secondary" sx={{ fontSize: 12 }}>
            Aucun profil sélectionné.
          </Typography>
        )}
        {profile && !connected && (
          <Typography color="text.secondary" sx={{ fontSize: 12 }}>
            Connectez le profil « {profile.name} » avant de lancer le test.
          </Typography>
        )}

        {running && progress && (
          <Box
            aria-live="polite"
            sx={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 1,
              px: 1.5,
              py: 1,
              borderRadius: 2,
              color: PINE,
              backgroundColor: MINT,
            }}
          >
            <Typography sx={{ fontSize: 11, fontWeight: 750 }}>{progress.message}</Typography>
            <Typography sx={{ flexShrink: 0, fontSize: 10.5, fontFamily: 'monospace' }}>
              {decimal(progress.current_mbps)} Mb/s · {duration(progress.elapsed_ms)}
            </Typography>
          </Box>
        )}

        <Button
          variant="contained"
          startIcon={<Gauge size={17} aria-hidden />}
          onClick={() => void run()}
          disabled={running || !available}
          aria-busy={running}
          sx={{ alignSelf: 'center', minWidth: 230, minHeight: 44, borderRadius: 2.5 }}
        >
          {running ? 'Mesure directe en cours…' : result ? 'Relancer le speedtest' : 'Lancer le speedtest'}
        </Button>

        {error && (
          <Typography role="alert" color="error.main" sx={{ fontSize: 12, lineHeight: 1.5, textAlign: 'center' }}>
            Speedtest impossible : {error}
          </Typography>
        )}

        {result && (
          <Box aria-live="polite" aria-label="Résultats détaillés du speedtest">
            <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap' }}>
              <ResultMetric
                label="Latence WireGuard"
                value={duration(result.latency_ms)}
                detail={`jitter ${decimal(result.jitter_ms)} ms · p95 ${decimal(result.latency_p95_ms)} ms`}
              />
              {result.udp_loss_pct !== null && (
                <ResultMetric
                  label="Qualité UDP"
                  value={`${decimal(result.udp_loss_pct)} % perdu`}
                  detail={`jitter ${result.udp_jitter_ms === null ? 'n/d' : `${decimal(result.udp_jitter_ms)} ms`}`}
                />
              )}
              <ResultMetric label="Durée" value={`${TEST_DURATION_SECS} s / sens`} detail="intervalle fixé" />
            </Stack>
            <Typography color="text.disabled" sx={{ mt: 1, fontSize: 10.5, fontFamily: 'monospace', textAlign: 'center' }}>
              {bytes(result.download_bytes)} reçus · {bytes(result.upload_bytes)} envoyés · {result.mode.toUpperCase()}
            </Typography>
          </Box>
        )}
      </Stack>
    </Box>
  )
}
