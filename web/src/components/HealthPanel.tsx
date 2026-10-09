import Box from '@mui/material/Box'
import LinearProgress from '@mui/material/LinearProgress'
import Skeleton from '@mui/material/Skeleton'
import Stack from '@mui/material/Stack'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { Cpu, HardDrive, ShieldCheck, Thermometer, Timer } from 'lucide-react'
import { useEffect, useState } from 'react'
import { fetchHealth } from '../api'
import { formatBytes } from '../format'
import type { Health, TpmSummary } from '../types'
import { KnownLimit } from './KnownLimit'
import { SectionCard } from './SectionCard'

/**
 * The health of the box carrying the gateway.
 *
 * Until this existed the console could say everything about the tunnel and
 * nothing about the machine: an operator watching handshakes fail could not
 * tell an overloaded CPU from a thermally throttled board without opening an
 * SSH session.
 *
 * Every reading is independently optional. A field the kernel does not publish
 * renders as absent, never as zero — a temperature of 0 °C would read as a
 * measurement.
 */

/** How each sealing decision reads, and whether it is good news. */
const TPM_KIND: Record<TpmSummary['kind'], { label: string; detail: string }> = {
  disabled: {
    label: 'Validation désactivée',
    detail: 'tpm.enabled = false. Aucun secret n’est scellé — développement uniquement.',
  },
  bypassed: {
    label: 'Échec ignoré',
    detail: 'enforce = false : la validation a échoué et le démarrage a continué quand même.',
  },
  unsealed: {
    label: 'Descellement nominal',
    detail: 'Intégrité confirmée, secret existant récupéré. Les coffres s’ouvrent.',
  },
  provisioned: {
    label: 'Premier démarrage',
    detail: 'Secret provisionné (TOFU). Les identifiants doivent être rechiffrés.',
  },
  resealed: {
    label: 'Rescellement subi',
    detail: 'Nouveau secret après changement de PCR. Les coffres ne s’ouvrent plus.',
  },
  window_resealed: {
    label: 'Fenêtre de mise à jour',
    detail:
      'Le même secret a traversé le redémarrage planifié et a été rescellé. Aucun client n’est affecté.',
  },
}

function Reading({
  icon: Icon,
  label,
  value,
  hint,
}: {
  icon: typeof Cpu
  label: string
  value: string
  hint?: string
}) {
  const body = (
    <Stack direction="row" spacing={1.5} sx={{ alignItems: 'center', minWidth: 0 }}>
      <Box sx={{ color: 'text.disabled', display: 'flex' }}>
        <Icon size={16} strokeWidth={1.9} />
      </Box>
      <Box sx={{ minWidth: 0 }}>
        <Typography variant="overline" sx={{ color: 'text.secondary', display: 'block' }}>
          {label}
        </Typography>
        <Typography sx={{ fontFamily: 'monospace', fontSize: '0.875rem', fontWeight: 500 }}>
          {value}
        </Typography>
      </Box>
    </Stack>
  )
  return hint ? <Tooltip title={hint}>{body}</Tooltip> : body
}

function humanizeUptime(seconds: number): string {
  const days = Math.floor(seconds / 86_400)
  const hours = Math.floor((seconds % 86_400) / 3_600)
  if (days > 0) return `${days} j ${hours} h`
  return `${hours} h ${Math.floor((seconds % 3_600) / 60)} min`
}

export function HealthPanel() {
  const [health, setHealth] = useState<Health | null>(null)
  const [error, setError] = useState(false)

  useEffect(() => {
    let alive = true
    let timer: ReturnType<typeof setTimeout> | undefined
    // The machine's load is only meaningful if it keeps moving. The next read
    // is scheduled once the previous one has settled, not on a fixed clock: a
    // daemon slower than the period would otherwise pile up requests.
    const read = () =>
      fetchHealth()
        .then(next => {
          if (!alive) return
          setHealth(next)
          setError(false)
        })
        .catch(() => {
          if (alive) setError(true)
        })
        .finally(() => {
          if (alive) timer = setTimeout(read, 5_000)
        })
    void read()
    return () => {
      alive = false
      clearTimeout(timer)
    }
  }, [])

  if (error) {
    return (
      <KnownLimit register="danger" title="Santé de la machine illisible">
        Le démon ne répond pas sur <code>/api/health</code>.
      </KnownLimit>
    )
  }

  if (!health) return <Skeleton variant="rounded" height={190} />

  const memoryUsed =
    health.memory_total_bytes !== null && health.memory_available_bytes !== null
      ? health.memory_total_bytes - health.memory_available_bytes
      : null
  const memoryPercent =
    memoryUsed !== null && health.memory_total_bytes
      ? Math.round((memoryUsed / health.memory_total_bytes) * 100)
      : null
  const tpm = health.tpm

  return (
    <Stack spacing={2.5}>
      <SectionCard title="Machine" icon={Cpu} accent="state.connecting.main">
        <Stack spacing={2.5}>
          <Box
            sx={{
              display: 'grid',
              gap: 2.5,
              gridTemplateColumns: { xs: 'repeat(2, 1fr)', md: 'repeat(4, 1fr)' },
            }}
          >
            <Reading
              icon={Timer}
              label="Uptime"
              value={health.uptime_seconds === null ? '—' : humanizeUptime(health.uptime_seconds)}
              hint="Depuis le démarrage de la machine, pas du démon."
            />
            <Reading
              icon={Cpu}
              label="Charge"
              value={health.load === null ? '—' : health.load.map(l => l.toFixed(2)).join('  ')}
              hint={`Moyennes sur 1, 5 et 15 minutes${
                health.cpu_count ? ` — ${health.cpu_count} cœurs` : ''
              }. Au-delà du nombre de cœurs, la machine est saturée.`}
            />
            <Reading
              icon={HardDrive}
              label="Mémoire"
              value={
                memoryUsed === null
                  ? '—'
                  : `${formatBytes(memoryUsed)} / ${formatBytes(health.memory_total_bytes)}`
              }
              hint="Mesurée sur MemAvailable — ce que le noyau peut réellement récupérer, pas MemFree, qui est toujours proche de zéro sur un Linux sain."
            />
            <Reading
              icon={Thermometer}
              label="Température"
              value={
                health.temperature_celsius === null
                  ? 'non relevée'
                  : `${health.temperature_celsius.toFixed(1)} °C`
              }
              hint="Zone thermique la plus chaude — celle qui bride en premier. Absente sur machine virtuelle."
            />
          </Box>

          {memoryPercent !== null && (
            <Box>
              <LinearProgress
                variant="determinate"
                value={memoryPercent}
                sx={{
                  bgcolor: 'surfaceContainer.highest',
                  '& .MuiLinearProgress-bar': {
                    bgcolor: memoryPercent > 90 ? 'error.main' : 'state.connecting.main',
                  },
                }}
              />
              <Typography variant="caption" sx={{ color: 'text.secondary', mt: 0.5, display: 'block' }}>
                {memoryPercent} % de la mémoire utilisée
              </Typography>
            </Box>
          )}
        </Stack>
      </SectionCard>

      {tpm && (
        <SectionCard
          title="Scellement TPM"
          icon={ShieldCheck}
          accent={tpm.preserved_vaults ? 'state.up.main' : 'warning.main'}
          subtitle={TPM_KIND[tpm.kind]?.label ?? tpm.kind}
        >
          <Stack spacing={2}>
            <Typography variant="body2" sx={{ color: 'text.secondary' }}>
              {TPM_KIND[tpm.kind]?.detail ?? 'Décision de démarrage inconnue de cette interface.'}
            </Typography>
            {!tpm.preserved_vaults && tpm.kind !== 'disabled' && (
              <KnownLimit register="caution" title="Les coffres scellés ne s’ouvrent plus">
                L’identité WireGuard scellée et l’identité de négociation ont été chiffrées sous un
                autre secret. Une rotation et le ré-enrôlement du parc sont nécessaires.
              </KnownLimit>
            )}
          </Stack>
        </SectionCard>
      )}

    </Stack>
  )
}
