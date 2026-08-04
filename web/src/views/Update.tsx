import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import LinearProgress from '@mui/material/LinearProgress'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { CheckCircle2, FileJson, HardDrive, Upload } from 'lucide-react'
import { useEffect, useState } from 'react'
import { activateUpdate, fetchUpdateStatus, stageUpdate, uploadUpdateBinary } from '../api'
import { DataRow } from '../components/DataRow'
import { KnownLimit } from '../components/KnownLimit'
import { Metric } from '../components/Metric'
import { SectionCard } from '../components/SectionCard'
import type { FinalizedRelease, UpdateStatus } from '../types'

/**
 * Picks one file, and says which one is loaded.
 *
 * A bare `<input type="file">` is styled inconsistently across browsers and
 * gives no room for a label; wrapping it in a button keeps the MD3 shape while
 * leaving the native picker — and its keyboard behaviour — untouched.
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
    <Stack spacing={1}>
      <Typography variant="overline" sx={{ color: 'text.secondary' }}>
        {label}
      </Typography>
      <Button
        component="label"
        variant="outlined"
        color="inherit"
        startIcon={<Icon size={17} />}
        sx={{ justifyContent: 'flex-start', borderColor: 'divider', color: 'text.primary' }}
      >
        {file ? file.name : 'Choisir un fichier…'}
        <input
          type="file"
          accept={accept}
          hidden
          onChange={event => onPick(event.target.files?.[0] ?? null)}
        />
      </Button>
    </Stack>
  )
}

export function UpdateView() {
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
      setError(null)
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
      const finalized = await uploadUpdateBinary(
        staged.release_sequence,
        binaryFile,
        (uploaded, total) => setProgress(Math.round((uploaded / total) * 100)),
      )
      setRelease(finalized)
      setMessage('Signature, taille et SHA-256 vérifiés. La release est prête à être activée.')
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
      setMessage('Activation acceptée. Le tunnel va se fermer puis se rétablir automatiquement.')
      await refresh()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setBusy(false)
    }
  }

  const expectedConfirmation = release ? `INSTALLER ${release.release_sequence}` : ''

  return (
    <Stack spacing={2.5}>
      {status && (
        <Box
          sx={{
            display: 'grid',
            gap: 2,
            gridTemplateColumns: { xs: 'repeat(2, 1fr)', md: 'repeat(4, 1fr)' },
          }}
        >
          <Metric label="Canal" value={status.channel} />
          <Metric label="Cible" value={status.target} />
          <Metric
            label="Séquence confirmée"
            value={String(status.highest_confirmed_sequence)}
            hint="L’anti-rollback refuse toute release dont la séquence n’est pas strictement supérieure."
          />
          <Metric label="Version active" value={status.active_version ?? '—'} />
        </Box>
      )}

      <SectionCard
        icon={Upload}
        title="Transférer une release signée"
        subtitle="Helios n’accepte qu’un binaire dont le manifeste porte les signatures Ed25519 et ML-DSA-65 du trousseau compilé."
      >
        <Stack spacing={2.5}>
          <Box
            sx={{
              display: 'grid',
              gap: 2,
              gridTemplateColumns: { xs: '1fr', sm: '1fr 1fr' },
            }}
          >
            <FilePicker
              label="Manifeste .release.json"
              accept="application/json,.json"
              file={manifestFile}
              icon={FileJson}
              onPick={setManifestFile}
            />
            <FilePicker
              label="Binaire heliosd"
              file={binaryFile}
              icon={HardDrive}
              onPick={setBinaryFile}
            />
          </Box>

          {busy && progress > 0 && (
            <Box>
              <Typography variant="overline" sx={{ color: 'text.secondary' }}>
                Transfert {progress}%
              </Typography>
              <LinearProgress variant="determinate" value={progress} sx={{ mt: 0.5 }} />
            </Box>
          )}

          <Button
            variant="contained"
            disabled={busy || !manifestFile || !binaryFile}
            onClick={() => void upload()}
            sx={{ alignSelf: 'flex-start' }}
          >
            Vérifier et stager
          </Button>
        </Stack>
      </SectionCard>

      {release && (
        <SectionCard
          title="Activation"
          subtitle="Le démon redémarre sur la nouvelle version et revient seul à la précédente si elle ne se confirme pas."
        >
          <Stack spacing={2.5}>
            <Box>
              <DataRow label="Version" value={release.version} />
              <DataRow label="Séquence" value={String(release.release_sequence)} />
              <DataRow label="SHA-256" value={release.sha256} wrap />
            </Box>

            <KnownLimit register="caution" title="Cette action coupe le tunnel">
              Tous les clients perdent leur session le temps du redémarrage, et les PSK négociés sont
              libérés : chacun renégociera au retour du démon.
            </KnownLimit>

            <TextField
              label={`Saisir « ${expectedConfirmation} » pour confirmer`}
              value={confirmation}
              onChange={event => setConfirmation(event.target.value)}
              fullWidth
              slotProps={{ input: { sx: { fontFamily: 'monospace' } } }}
            />

            <Button
              variant="contained"
              color="error"
              disabled={busy || confirmation !== expectedConfirmation}
              onClick={() => void activate()}
              sx={{ alignSelf: 'flex-start' }}
            >
              Activer et redémarrer heliosd
            </Button>
          </Stack>
        </SectionCard>
      )}

      {message && (
        <Stack direction="row" spacing={1.5} sx={{ alignItems: 'center', color: 'state.up.main' }}>
          <CheckCircle2 size={18} strokeWidth={1.8} />
          <Typography variant="body2" sx={{ color: 'inherit' }}>
            {message}
          </Typography>
        </Stack>
      )}

      {error && (
        <KnownLimit register="danger" title="La release a été refusée">
          {error}
        </KnownLimit>
      )}
    </Stack>
  )
}
