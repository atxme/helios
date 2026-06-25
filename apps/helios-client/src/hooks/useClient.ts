import { useCallback, useEffect, useRef, useState } from 'react'
import * as api from '../api'
import type {
  ClientConfig,
  ClientProfile,
  LogLine,
  PredefinedProfile,
  TelemetrySample,
  TunnelState,
} from '../types'

const MAX_LOGS = 80

export function useClient() {
  const [config, setConfig] = useState<ClientConfig>({ profiles: [], selected: null })
  const [predefined, setPredefined] = useState<PredefinedProfile[]>([])
  const [state, setState] = useState<TunnelState>('down')
  const [backend, setBackend] = useState<string>('')
  const [logs, setLogs] = useState<LogLine[]>([])
  const [telemetry, setTelemetry] = useState<TelemetrySample | null>(null)
  const [upSince, setUpSince] = useState<number | null>(null)
  const [error, setError] = useState<string | null>(null)
  const upSinceRef = useRef<number | null>(null)

  const pushLog = useCallback((level: string, message: string) => {
    const ts = new Date().toLocaleTimeString('fr-FR', { hour12: false })
    setLogs((prev) => [{ level, message, ts }, ...prev].slice(0, MAX_LOGS))
  }, [])

  // Chargement initial + abonnement aux événements du backend.
  useEffect(() => {
    api.getConfig().then(setConfig).catch((e) => setError(String(e)))
    api.listPredefined().then(setPredefined).catch(() => {})
    api.getState().then(setState).catch(() => {})
    api.backendKind().then(setBackend).catch(() => {})

    const unlisten = api.onEvent((ev) => {
      switch (ev.type) {
        case 'state_changed':
          setState(ev.state)
          if (ev.state === 'up') {
            if (upSinceRef.current === null) {
              upSinceRef.current = Date.now()
              setUpSince(upSinceRef.current)
            }
          } else if (ev.state === 'down' || ev.state === 'failed') {
            upSinceRef.current = null
            setUpSince(null)
            setTelemetry(null)
          }
          break
        case 'log':
          pushLog(ev.level, ev.message)
          break
        case 'telemetry':
          setTelemetry({ rx_bps: ev.rx_bps, tx_bps: ev.tx_bps })
          break
        case 'error':
          setError(ev.message)
          pushLog('error', ev.message)
          break
      }
    })
    return () => {
      unlisten.then((f) => f())
    }
  }, [pushLog])

  const connect = useCallback(async (name?: string) => {
    setError(null)
    try {
      await api.connect(name)
    } catch (e) {
      setError(String(e))
    }
  }, [])

  const disconnect = useCallback(async () => {
    try {
      await api.disconnect()
    } catch (e) {
      setError(String(e))
    }
  }, [])

  const saveProfile = useCallback(async (p: ClientProfile) => {
    setConfig(await api.saveProfile(p))
  }, [])

  const removeProfile = useCallback(async (name: string) => {
    setConfig(await api.deleteProfile(name))
  }, [])

  const select = useCallback(async (name: string) => {
    setConfig(await api.selectProfile(name))
  }, [])

  const selectedProfile =
    config.profiles.find((p) => p.name === config.selected) ?? config.profiles[0] ?? null

  return {
    config,
    predefined,
    state,
    backend,
    logs,
    telemetry,
    upSince,
    error,
    selectedProfile,
    connect,
    disconnect,
    saveProfile,
    removeProfile,
    select,
    clearError: () => setError(null),
  }
}
