import { useState } from 'react'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { Gauge, RotateCcw } from 'lucide-react'

import * as api from '../api'
import { GUTTER, PINE } from '../theme'
import type { ClientProfile, SpeedTestResult, TunnelState } from '../types'

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

/**
 * Measures the path that carries the user's traffic, rather than an internet
 * server reached outside the tunnel.
 */
export function SpeedTestView({ state, profile }: Props) {
  const [result, setResult] = useState<SpeedTestResult | null>(null)
  const [running, setRunning] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const connected = state === 'up'
  const available = connected && Boolean(profile?.heliosd_url)

  const run = async () => {
    setRunning(true)
    setError(null)
    try {
      setResult(await api.runSpeedTest())
    } catch (cause) {
      setError(String(cause))
    } finally {
      setRunning(false)
    }
  }

  return (
    <Box sx={{ height: '100%', overflowY: 'auto', px: GUTTER, py: 1.5 }}>
      <Stack spacing={2} sx={{ maxWidth: 720, mx: 'auto' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <Gauge size={18} aria-hidden style={{ color: PINE }} />
          <Typography component="h2" sx={{ fontSize: 13, fontWeight: 700 }}>
            Speedtest
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
            Les performances du tunnel
          </Typography>
          <Typography color="text.secondary" sx={{ mt: 0.75, fontSize: 12, lineHeight: 1.55 }}>
            Mesure le chemin WireGuard entre ce client et la gateway du profil connecté.
            Le moteur adapte le volume, préchauffe quatre flux et retient la médiane de trois
            fenêtres. Il ne mesure pas votre débit Internet général.
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
        {profile && connected && !profile.heliosd_url && (
          <Typography color="text.secondary" sx={{ fontSize: 12 }}>
            Ce profil ne fournit pas d’URL interne Helios pour effectuer la mesure.
          </Typography>
        )}

        <Button
          variant="contained"
          startIcon={<Gauge size={17} aria-hidden />}
          onClick={() => void run()}
          disabled={running || !available}
          aria-busy={running}
          sx={{ alignSelf: 'flex-start' }}
        >
          {running ? 'Mesure en cours…' : result ? 'Relancer le speedtest' : 'Lancer le speedtest'}
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
                label="Latence"
                value={duration(result.latency_ms)}
                detail={`jitter ${decimal(result.jitter_ms)} ms · p95 ${decimal(result.latency_p95_ms)} ms`}
              />
              <ResultMetric
                label="Descendant"
                value={`${decimal(result.download_mbps)} Mb/s`}
                detail={`gateway → Orion · variation ${decimal(result.download_variation_pct)} %`}
              />
              <ResultMetric
                label="Montant"
                value={`${decimal(result.upload_mbps)} Mb/s`}
                detail={`Orion → gateway · variation ${decimal(result.upload_variation_pct)} %`}
              />
              <ResultMetric label="Durée" value={duration(result.duration_ms)} detail="mesure complète" />
            </Stack>
            <Typography color="text.disabled" sx={{ mt: 1, fontSize: 10.5, fontFamily: 'monospace' }}>
              {result.download_bytes.toLocaleString('fr-FR')} octets reçus ·{' '}
              {result.upload_bytes.toLocaleString('fr-FR')} octets envoyés ·{' '}
              {result.parallel_streams} flux × {result.measurement_rounds} fenêtres
            </Typography>
          </Box>
        )}
      </Stack>
    </Box>
  )
}
