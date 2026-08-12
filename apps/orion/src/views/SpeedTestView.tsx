import { useEffect, useState } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import LinearProgress from '@mui/material/LinearProgress'
import Paper from '@mui/material/Paper'
import Slider from '@mui/material/Slider'
import Stack from '@mui/material/Stack'
import ToggleButton from '@mui/material/ToggleButton'
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup'
import Typography from '@mui/material/Typography'
import { Gauge, RotateCcw } from 'lucide-react'

import * as api from '../api'
import { GUTTER, PINE } from '../theme'
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

function ResultMetric({ label, value, detail }: { label: string; value: string; detail: string }) {
  return (
    <Paper variant="outlined" sx={{ p: 1.5, flex: '1 1 150px', minWidth: 0 }}>
      <Typography variant="overline" color="text.secondary">
        {label}
      </Typography>
      <Typography sx={{ mt: 0.5, fontSize: 22, fontWeight: 700, fontVariantNumeric: 'tabular-nums' }}>
        {value}
      </Typography>
      <Typography color="text.secondary" sx={{ mt: 0.25, fontSize: 11 }}>
        {detail}
      </Typography>
    </Paper>
  )
}

function modeDescription(mode: SpeedTestMode): string {
  if (mode === 'tcp') return 'Débit brut principal, avec quatre flux TCP persistants.'
  if (mode === 'udp') return 'Capacité UDP, perte de paquets et variation d’arrivée.'
  return 'TCP principal puis UDP pour qualifier la capacité et la perte.'
}

/** Measures the established WireGuard data plane with direct socket traffic. */
export function SpeedTestView({ state, profile }: Props) {
  const [result, setResult] = useState<SpeedTestResult | null>(null)
  const [progress, setProgress] = useState<SpeedTestProgress | null>(null)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [mode, setMode] = useState<SpeedTestMode>('tcp')
  const [durationSecs, setDurationSecs] = useState(8)
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
      setResult(await api.runSpeedTest(mode, durationSecs))
    } catch (cause) {
      setError(String(cause))
    } finally {
      setRunning(false)
    }
  }

  return (
    <Box sx={{ height: '100%', overflowY: 'auto', px: GUTTER, py: 1.5 }}>
      <Stack spacing={2} sx={{ maxWidth: 760, mx: 'auto' }}>
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

        <Box>
          <Typography component="h3" sx={{ fontSize: 20, fontWeight: 700, letterSpacing: '-0.02em' }}>
            La ligne WireGuard, au ras du réseau
          </Typography>
          <Typography color="text.secondary" sx={{ mt: 0.75, fontSize: 12, lineHeight: 1.55 }}>
            Le test envoie des flux TCP ou UDP directs entre Orion et Helios. Il ne passe pas par
            HTTP : pas de headers, pas de parsing de réponse, pas de requêtes répétées. Le TCP
            utilise des flux persistants et une fenêtre assez longue pour atteindre son régime.
          </Typography>
        </Box>

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

        <Paper variant="outlined" sx={{ p: 1.5 }}>
          <Stack spacing={1.25}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', gap: 1, alignItems: 'baseline' }}>
              <Typography sx={{ fontSize: 12, fontWeight: 700 }}>Méthode</Typography>
              <Typography color="text.secondary" sx={{ fontSize: 11 }}>
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
            >
              <ToggleButton value="tcp">TCP brut</ToggleButton>
              <ToggleButton value="udp">UDP brut</ToggleButton>
              <ToggleButton value="full">TCP + UDP</ToggleButton>
            </ToggleButtonGroup>
            <Box sx={{ px: 1 }}>
              <Typography color="text.secondary" sx={{ fontSize: 11 }}>
                Durée par direction : <strong>{durationSecs} s</strong>
              </Typography>
              <Slider
                aria-label="Durée par direction"
                min={5}
                max={20}
                step={1}
                value={durationSecs}
                onChange={(_, value) => setDurationSecs(value as number)}
                disabled={running}
                valueLabelDisplay="auto"
                sx={{ color: PINE }}
              />
            </Box>
          </Stack>
        </Paper>

        {running && progress && (
          <Paper variant="outlined" sx={{ p: 1.5 }} aria-live="polite">
            <Box sx={{ display: 'flex', justifyContent: 'space-between', gap: 1, mb: 0.75 }}>
              <Typography sx={{ fontSize: 12, fontWeight: 700 }}>{phaseLabel(progress.phase)}</Typography>
              <Typography color="text.secondary" sx={{ fontSize: 11 }}>
                {decimal(progress.current_mbps)} Mb/s · {bytes(progress.bytes)}
              </Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={progress.fraction * 100}
              aria-label="Progression du speedtest"
              sx={{ height: 7, borderRadius: 4, '& .MuiLinearProgress-bar': { backgroundColor: PINE } }}
            />
            <Typography color="text.secondary" sx={{ mt: 0.75, fontSize: 11 }}>
              {progress.message} · temps écoulé {duration(progress.elapsed_ms)}
            </Typography>
          </Paper>
        )}

        <Button
          variant="contained"
          startIcon={<Gauge size={17} aria-hidden />}
          onClick={() => void run()}
          disabled={running || !available}
          aria-busy={running}
          sx={{ alignSelf: 'flex-start' }}
        >
          {running ? 'Mesure directe en cours…' : result ? 'Relancer le speedtest' : 'Lancer le speedtest'}
        </Button>

        {error && (
          <Typography role="alert" color="error.main" sx={{ fontSize: 12, lineHeight: 1.5 }}>
            Speedtest impossible : {error}
          </Typography>
        )}

        {result && (
          <Box aria-live="polite" aria-label="Résultats du speedtest">
            <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap' }}>
              <ResultMetric
                label="Latence WireGuard"
                value={duration(result.latency_ms)}
                detail={`jitter ${decimal(result.jitter_ms)} ms · p95 ${decimal(result.latency_p95_ms)} ms`}
              />
              {result.tcp_download_mbps !== null && (
                <ResultMetric
                  label="TCP descendant"
                  value={`${decimal(result.tcp_download_mbps)} Mb/s`}
                  detail={`${result.tcp_streams} flux persistants · Helios → Orion`}
                />
              )}
              {result.tcp_upload_mbps !== null && (
                <ResultMetric
                  label="TCP montant"
                  value={`${decimal(result.tcp_upload_mbps)} Mb/s`}
                  detail={`${result.tcp_streams} flux persistants · Orion → Helios`}
                />
              )}
              {result.udp_download_mbps !== null && (
                <ResultMetric
                  label="UDP descendant"
                  value={`${decimal(result.udp_download_mbps)} Mb/s`}
                  detail="débit socket · Helios → Orion"
                />
              )}
              {result.udp_upload_mbps !== null && (
                <ResultMetric
                  label="UDP montant"
                  value={`${decimal(result.udp_upload_mbps)} Mb/s`}
                  detail="débit socket · Orion → Helios"
                />
              )}
              {result.udp_loss_pct !== null && (
                <ResultMetric
                  label="Qualité UDP"
                  value={`${decimal(result.udp_loss_pct)} % perdu`}
                  detail={`jitter ${result.udp_jitter_ms === null ? 'n/d' : `${decimal(result.udp_jitter_ms)} ms`}`}
                />
              )}
              <ResultMetric label="Durée totale" value={duration(result.duration_ms)} detail="mesure complète" />
            </Stack>
            <Typography color="text.disabled" sx={{ mt: 1, fontSize: 10.5, fontFamily: 'monospace' }}>
              {bytes(result.download_bytes)} reçus · {bytes(result.upload_bytes)} envoyés ·{' '}
              {result.mode.toUpperCase()} · {result.test_duration_secs} s par direction
            </Typography>
          </Box>
        )}
      </Stack>
    </Box>
  )
}
