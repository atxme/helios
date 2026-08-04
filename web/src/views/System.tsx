import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import LinearProgress from '@mui/material/LinearProgress'
import Skeleton from '@mui/material/Skeleton'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { CheckCircle2, FileJson, HardDrive, Route, Save, ScrollText, Settings2, Upload } from 'lucide-react'
import { useEffect, useState } from 'react'
import { activateUpdate, fetchUpdateStatus, stageUpdate, uploadUpdateBinary } from '../api'
import { DataRow } from '../components/DataRow'
import { HealthPanel } from '../components/HealthPanel'
import { EventLog } from '../components/EventLog'
import type { TimestampedEvent } from '../components/EventLog'
import { KnownLimit } from '../components/KnownLimit'
import { SectionCard } from '../components/SectionCard'
import type { FinalizedRelease, Status, UpdateStatus } from '../types'

/**
 * Everything an operator touches occasionally.
 *
 * Configuration, the signed update flow, and the full event log. None of these
 * deserved a destination of their own: two of them were read-only dumps of
 * figures already shown on the overview, and the third is used a few times a
 * year.
 */

function FilePicker({
  label,
  accept,
  file,
  icon: Icon,
  onPick,
}: {
  label: string
  accept?: string
  file: File | null
  icon: typeof FileJson
  onPick: (file: File | null) => void
}) {
  return (
    <Stack spacing={0.75}>
      <Typography variant="overline" sx={{ color: 'text.secondary' }}>
        {label}
      </Typography>
      <Button
        component="label"
        variant="outlined"
        color="inherit"
        startIcon={<Icon size={16} />}
        sx={{ justifyContent: 'flex-start', color: 'text.primary' }}
      >
        {file ? file.name : 'Choisir un fichier…'}
        <input type="file" accept={accept} hidden onChange={e => onPick(e.target.files?.[0] ?? null)} />
      </Button>
    </Stack>
  )
}

function UpdatePanel() {
  const [status, setStatus] = useState<UpdateStatus | null>(null)
  const [manifestFile, setManifestFile] = useState<File | null>(null)
  const [binaryFile, setBinaryFile] = useState<File | null>(null)
  const [release, setRelease] = useState<FinalizedRelease | null>(null)
  const [confirmation, setConfirmation] = useState('')
  const [progress, setProgress] = useState(0)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const refresh = async () => {
    try {
      setStatus(await fetchUpdateStatus())
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause))
    }
  }

  useEffect(() => {
    void refresh()
  }, [])

  const upload = async () => {
    if (!manifestFile || !binaryFile) return
    setBusy(true)
    setError(null)
    setMessage(null)
    setProgress(0)
    try {
      const manifest = JSON.parse(await manifestFile.text()) as unknown
      const staged = await stageUpdate(manifest)
      const finalized = await uploadUpdateBinary(staged.release_sequence, binaryFile, (done, total) =>
        setProgress(Math.round((done / total) * 100)),
      )
      setRelease(finalized)
      setMessage('Signature, taille et SHA-256 vérifiés.')
      await refresh()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setBusy(false)
    }
  }

  const activate = async () => {
    if (!release) return
    setBusy(true)
    setError(null)
    try {
      await activateUpdate(release.release_sequence, confirmation)
      setMessage('Activation acceptée. Le tunnel se ferme puis se rétablit.')
      await refresh()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setBusy(false)
    }
  }

  const expected = release ? `INSTALLER ${release.release_sequence}` : ''

  return (
    <SectionCard
      title="Mise à jour"
      icon={Upload}
      accent="secondary.main"
      subtitle="Seul un binaire dont le manifeste porte les signatures Ed25519 et ML-DSA-65 du trousseau compilé est accepté."
    >
      <Stack spacing={2.5}>
        {status && (
          <Box>
            <DataRow label="Canal" value={status.channel} />
            <DataRow label="Version active" value={status.active_version ?? ''} />
            <DataRow
              label="Séquence"
              value={String(status.highest_confirmed_sequence)}
              hint="L’anti-rollback refuse toute release dont la séquence n’est pas strictement supérieure."
            />
          </Box>
        )}

        <Box sx={{ display: 'grid', gap: 2, gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr' } }}>
          <FilePicker
            label="Manifeste .release.json"
            accept="application/json,.json"
            file={manifestFile}
            icon={FileJson}
            onPick={setManifestFile}
          />
          <FilePicker label="Binaire heliosd" file={binaryFile} icon={HardDrive} onPick={setBinaryFile} />
        </Box>

        {busy && progress > 0 && <LinearProgress variant="determinate" value={progress} />}

        <Button
          variant="contained"
          disabled={busy || !manifestFile || !binaryFile}
          onClick={() => void upload()}
          sx={{ alignSelf: 'flex-start' }}
        >
          Vérifier et stager
        </Button>

        {release && (
          <Stack spacing={2} sx={{ pt: 1, borderTop: '1px solid', borderColor: 'divider' }}>
            <Box>
              <DataRow label="Version" value={release.version} />
              <DataRow label="SHA-256" value={release.sha256} wrap />
            </Box>
            <KnownLimit register="caution" title="L’activation coupe le tunnel">
              Tous les clients perdent leur session le temps du redémarrage, et les PSK négociés sont
              libérés.
            </KnownLimit>
            <TextField
              label={`Saisir « ${expected} »`}
              value={confirmation}
              onChange={e => setConfirmation(e.target.value)}
              fullWidth
              slotProps={{ input: { sx: { fontFamily: 'monospace' } } }}
            />
            <Button
              variant="contained"
              color="error"
              disabled={busy || confirmation !== expected}
              onClick={() => void activate()}
              sx={{ alignSelf: 'flex-start' }}
            >
              Activer et redémarrer
            </Button>
          </Stack>
        )}

        {message && (
          <Stack direction="row" spacing={1} sx={{ alignItems: 'center', color: 'state.up.main' }}>
            <CheckCircle2 size={17} strokeWidth={2} />
            <Typography variant="body2" sx={{ color: 'inherit' }}>
              {message}
            </Typography>
          </Stack>
        )}
        {error && (
          <KnownLimit register="danger" title="Refusé">
            {error}
          </KnownLimit>
        )}
      </Stack>
    </SectionCard>
  )
}

interface Props {
  status: Status | null
  events: TimestampedEvent[]
  onSplitTunnelChange: (cidrs: string[]) => Promise<void>
}

export function SystemView({ status, events, onSplitTunnelChange }: Props) {
  const [routes, setRoutes] = useState('')
  const [saving, setSaving] = useState(false)
  const [feedback, setFeedback] = useState<{ ok: boolean; message: string } | null>(null)

  useEffect(() => {
    setRoutes(status?.split_tunnel_cidrs.join('\n') ?? '')
  }, [status?.split_tunnel_cidrs])

  const save = async () => {
    setSaving(true)
    setFeedback(null)
    const cidrs = routes
      .split(/[\n,]/)
      .map(value => value.trim())
      .filter(Boolean)
    try {
      await onSplitTunnelChange(cidrs)
      setFeedback({ ok: true, message: 'Routes transmises.' })
    } catch {
      setFeedback({ ok: false, message: 'Échec de la mise à jour.' })
    } finally {
      setSaving(false)
    }
  }

  return (
    <Stack spacing={2.5}>
      <HealthPanel />

      <Box sx={{ display: 'grid', gap: 2.5, gridTemplateColumns: { xs: '1fr', lg: '1fr 1fr' } }}>
        <SectionCard title="Configuration" icon={Settings2}>
          {status ? (
            <Box>
              {/* No icons: five identical glyphs down a column label nothing. */}
              <DataRow label="Interface" value={status.wg_iface} />
              <DataRow
                label="MSS clamp"
                value={status.mss_clamp === null ? '' : `${status.mss_clamp} octets`}
                hint="Découvert par PMTUD et appliqué au trafic sortant du tunnel."
              />
              <DataRow label="Site-à-site" value={status.wg_peers.join(', ')} />
              <DataRow label="Portail captif" value={status.captive_portal_gateway ?? ''} />
              <DataRow label="Version" value={status.version} />
            </Box>
          ) : (
            <Skeleton variant="rounded" height={180} />
          )}
        </SectionCard>

        <SectionCard
          title="Split-tunneling"
          icon={Route}
          accent="state.connecting.main"
          subtitle="Un CIDR par ligne. Une liste vide désactive les routes de contournement."
        >
          <Stack spacing={2}>
            <TextField
              value={routes}
              onChange={e => setRoutes(e.target.value)}
              multiline
              minRows={4}
              fullWidth
              placeholder={'10.0.0.0/8\n192.168.0.0/16'}
              spellCheck={false}
              slotProps={{ input: { sx: { fontFamily: 'monospace', fontSize: '0.8125rem' } } }}
            />
            <Stack direction="row" spacing={2} sx={{ alignItems: 'center' }}>
              <Button
                variant="contained"
                disabled={saving || !status}
                onClick={() => void save()}
                startIcon={<Save size={16} />}
              >
                {saving ? 'Envoi…' : 'Appliquer'}
              </Button>
              {feedback && (
                <Typography
                  variant="body2"
                  role="status"
                  sx={{ color: feedback.ok ? 'state.up.main' : 'error.main' }}
                >
                  {feedback.message}
                </Typography>
              )}
            </Stack>
          </Stack>
        </SectionCard>
      </Box>

      <UpdatePanel />

      <SectionCard title="Journal complet" icon={ScrollText} disableContentPadding>
        <EventLog events={events} maxHeight={420} />
      </SectionCard>

      <KnownLimit title="Ce qui ne se change pas ici">
        Les secrets WireGuard et la liste d’admission vivent dans{' '}
        <code>/var/lib/helios/network.toml</code> et ne sont jamais sérialisés par l’API. Le fichier
        est relu à chaud, mais le nom de l’interface, le port d’écoute et l’adresse d’administration
        exigent un <code>systemctl restart heliosd</code>.
      </KnownLimit>
    </Stack>
  )
}
