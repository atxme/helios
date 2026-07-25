import { useCallback, useEffect, useRef, useState } from 'react'
import * as api from '../api'
import type {
  ClientConfig,
  ClientProfile,
  LogLine,
  PskKind,
  TelemetrySample,
  TunnelState,
} from '../types'

const MAX_LOGS = 80
/** Throughput curve window. At one sample per second, ~1 minute. */
const MAX_SAMPLES = 60

export function useClient() {
  const [config, setConfig] = useState<ClientConfig>({ profiles: [], selected: null })
  const [state, setState] = useState<TunnelState>('down')
  const [backend, setBackend] = useState<string>('')
  const [adapterUp, setAdapterUp] = useState(false)
  const [logs, setLogs] = useState<LogLine[]>([])
  const [telemetry, setTelemetry] = useState<TelemetrySample | null>(null)
  const [history, setHistory] = useState<TelemetrySample[]>([])
  const [upSince, setUpSince] = useState<number | null>(null)
  // `null` = the ongoing connection hasn't decided yet. Definitely not
  // `'none'` by default: that would assert the absence of a PSK before knowing.
  const [psk, setPsk] = useState<PskKind | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [pathImportedProfile, setPathImportedProfile] = useState<ClientProfile | null>(null)
  const upSinceRef = useRef<number | null>(null)

  const pushLog = useCallback((level: string, message: string) => {
    const ts = new Date().toLocaleTimeString('fr-FR', { hour12: false })
    setLogs((prev) => [{ level, message, ts }, ...prev].slice(0, MAX_LOGS))
  }, [])

  const consumeProfilePath = useCallback(async () => {
    try {
      const imported = await api.importProfilePath()
      if (imported) {
        setError(null)
        setPathImportedProfile(imported.profile)
        // A double-click has no import panel to carry the notice, so the
        // identity failure goes to the global error: the profile is there
        // but would not connect, and that must not stay silent.
        if (imported.identity_error) {
          setError(`Identité non scellée : ${imported.identity_error}`)
        } else if (imported.identity_sealed) {
          pushLog('info', 'identité de négociation scellée dans le stockage protégé')
        }
      }
    } catch (cause) {
      const message = `Import du profil associé impossible : ${String(cause)}`
      setError(message)
      pushLog('error', message)
    }
  }, [pushLog])

  // Initial load + subscription to backend events.
  useEffect(() => {
    api.getConfig().then(setConfig).catch((e) => setError(String(e)))
    api.getState().then(setState).catch(() => {})
    api.backendKind().then(setBackend).catch(() => {})
    api.adapterIsUp().then(setAdapterUp).catch(() => {})

    const unlisten = api.onEvent((ev) => {
      switch (ev.type) {
        case 'state_changed':
          setState(ev.state)
          api.adapterIsUp().then(setAdapterUp).catch(() => {})
          if (ev.state === 'up') {
            if (upSinceRef.current === null) {
              upSinceRef.current = Date.now()
              setUpSince(upSinceRef.current)
            }
          } else if (ev.state === 'down' || ev.state === 'failed') {
            upSinceRef.current = null
            setUpSince(null)
            setTelemetry(null)
            // History resets to zero: stitching two sessions together would
            // produce a continuous curve that never existed.
            setHistory([])
            // The PQC PSK doesn't survive the session: it isn't persisted and
            // gets renegotiated on the next mount. Keeping it would display a
            // protection that no tunnel carries anymore.
            setPsk(null)
          }
          break
        case 'protection':
          setPsk(ev.psk)
          break
        case 'log':
          pushLog(ev.level, ev.message)
          break
        case 'telemetry': {
          const sample = { rx_bps: ev.rx_bps, tx_bps: ev.tx_bps }
          setTelemetry(sample)
          setHistory((prev) => [...prev, sample].slice(-MAX_SAMPLES))
          break
        }
        case 'error':
          setError(ev.message)
          pushLog('error', ev.message)
          break
      }
    })
    const unlistenProfilePath = api.onProfilePath(() => {
      void consumeProfilePath()
    })
    // The first launch may have received its argv before React installs the
    // listener. The command then consumes the path kept on the Rust side.
    void unlistenProfilePath.then(() => consumeProfilePath())
    return () => {
      unlisten.then((f) => f())
      unlistenProfilePath.then((f) => f())
    }
  }, [consumeProfilePath, pushLog])

  const connect = useCallback(async (name?: string) => {
    setError(null)
    // New session, new negotiation: we start over from "unknown". Resetting
    // it here rather than on the `connecting` transition is deliberate — a
    // stale handshake mid-session goes back through `connecting` without the
    // set protection having changed.
    setPsk(null)
    try {
      await api.connect(name)
    } catch (e) {
      setError(String(e))
    }
  }, [])

  const disconnect = useCallback(async () => {
    try {
      await api.disconnect()
      setAdapterUp(false)
    } catch (e) {
      setError(String(e))
    }
  }, [])

  const saveProfile = useCallback(async (p: ClientProfile) => {
    try {
      setError(null)
      setConfig(await api.saveProfile(p))
    } catch (cause) {
      setError(String(cause))
      throw cause
    }
  }, [])

  const importProfile = useCallback(async (contents: string, fileName: string) => {
    try {
      setError(null)
      return await api.importProfile(contents, fileName)
    } catch (cause) {
      setError(String(cause))
      throw cause
    }
  }, [])

  const removeProfile = useCallback(async (name: string) => {
    try {
      setError(null)
      setConfig(await api.deleteProfile(name))
    } catch (cause) {
      setError(String(cause))
      throw cause
    }
  }, [])

  const select = useCallback(async (name: string) => {
    try {
      setError(null)
      setConfig(await api.selectProfile(name))
    } catch (cause) {
      setError(String(cause))
      throw cause
    }
  }, [])

  const clearPathImportedProfile = useCallback(() => setPathImportedProfile(null), [])

  const selectedProfile =
    config.profiles.find((p) => p.name === config.selected) ?? config.profiles[0] ?? null

  return {
    config,
    state,
    backend,
    adapterUp,
    logs,
    telemetry,
    history,
    upSince,
    psk,
    error,
    selectedProfile,
    pathImportedProfile,
    connect,
    disconnect,
    importProfile,
    saveProfile,
    removeProfile,
    select,
    clearPathImportedProfile,
    clearError: () => setError(null),
  }
}
