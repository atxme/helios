import { AlertTriangle, CheckCircle2, RefreshCw, Upload } from 'lucide-react'
import { useEffect, useState } from 'react'

import { activateUpdate, fetchUpdateStatus, stageUpdate, uploadUpdateBinary } from '../api'
import type { FinalizedRelease, UpdateStatus } from '../types'

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

  useEffect(() => { void refresh() }, [])

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
    <div className="space-y-5 max-w-4xl">
      <div>
        <div className="text-[10px] uppercase tracking-[0.28em] text-cyan-600 dark:text-cyan-400 font-mono">Administration WireGuard</div>
        <h1 className="mt-1 text-2xl font-semibold text-slate-800 dark:text-slate-100">Mise à jour applicative</h1>
        <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">
          Helios accepte uniquement un binaire dont le manifeste porte les signatures Ed25519 et ML-DSA-65 du trousseau compilé.
        </p>
      </div>

      {status && (
        <div className="card hud p-4 grid gap-3 sm:grid-cols-3 text-xs font-mono">
          <div><span className="text-slate-500">Canal</span><div className="mt-1 text-cyan-600 dark:text-cyan-300">{status.channel}</div></div>
          <div><span className="text-slate-500">Target</span><div className="mt-1 break-all">{status.target}</div></div>
          <div><span className="text-slate-500">Séquence confirmée</span><div className="mt-1">{status.highest_confirmed_sequence}</div></div>
        </div>
      )}

      <div className="card hud p-5 space-y-4">
        <div className="flex items-center gap-2 text-sm font-medium"><Upload className="h-4 w-4 text-cyan-500" /> Transférer une release signée</div>
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="text-xs text-slate-500">Manifeste `.release.json`
            <input className="mt-2 block w-full text-xs" type="file" accept="application/json,.json" onChange={event => setManifestFile(event.target.files?.[0] ?? null)} />
          </label>
          <label className="text-xs text-slate-500">Binaire `heliosd`
            <input className="mt-2 block w-full text-xs" type="file" onChange={event => setBinaryFile(event.target.files?.[0] ?? null)} />
          </label>
        </div>
        {busy && progress > 0 && <div className="text-xs font-mono text-cyan-500">Transfert {progress}%</div>}
        <button className="px-4 py-2 rounded-lg bg-cyan-500/15 border border-cyan-500/40 text-cyan-700 dark:text-cyan-300 text-xs disabled:opacity-40" disabled={busy || !manifestFile || !binaryFile} onClick={() => void upload()}>
          Vérifier et stager
        </button>
      </div>

      {release && (
        <div className="card hud p-5 space-y-4 border border-amber-500/30">
          <div className="flex items-center gap-2 text-sm font-medium text-amber-600 dark:text-amber-300"><AlertTriangle className="h-4 w-4" /> Activation avec rollback automatique</div>
          <dl className="text-xs font-mono space-y-1">
            <div>Version : {release.version}</div>
            <div>Séquence : {release.release_sequence}</div>
            <div className="break-all">SHA-256 : {release.sha256}</div>
          </dl>
          <label className="block text-xs text-slate-500">Saisir <span className="font-mono text-amber-600 dark:text-amber-300">{expectedConfirmation}</span>
            <input className="mt-2 w-full rounded border border-[var(--panel-border)] bg-transparent px-3 py-2 font-mono text-sm" value={confirmation} onChange={event => setConfirmation(event.target.value)} />
          </label>
          <button className="px-4 py-2 rounded-lg bg-amber-500/15 border border-amber-500/40 text-amber-700 dark:text-amber-300 text-xs disabled:opacity-40" disabled={busy || confirmation !== expectedConfirmation} onClick={() => void activate()}>
            Activer et redémarrer heliosd
          </button>
        </div>
      )}

      {message && <div className="flex items-start gap-2 text-sm text-emerald-600 dark:text-emerald-300"><CheckCircle2 className="h-4 w-4 mt-0.5" />{message}</div>}
      {error && <div className="flex items-start gap-2 text-sm text-red-500"><RefreshCw className="h-4 w-4 mt-0.5" />{error}</div>}
    </div>
  )
}
