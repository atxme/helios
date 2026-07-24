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
/** Fenêtre de la courbe de débit. À un échantillon par seconde, ~1 minute. */
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
  // `null` = la connexion en cours n'a pas encore tranché. Surtout pas `'none'`
  // par défaut : ce serait affirmer l'absence de PSK avant de le savoir.
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
      const profile = await api.importProfilePath()
      if (profile) {
        setError(null)
        setPathImportedProfile(profile)
      }
    } catch (cause) {
      const message = `Import du profil associé impossible : ${String(cause)}`
      setError(message)
      pushLog('error', message)
    }
  }, [pushLog])

  // Chargement initial + abonnement aux événements du backend.
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
            // L'historique repart à zéro : recoller deux sessions produirait une
            // courbe continue qui n'a jamais existé.
            setHistory([])
            // Le PSK PQC ne survit pas à la session : il n'est pas persisté et
            // se renégocie au montage suivant. Le garder afficherait une
            // protection qu'aucun tunnel ne porte plus.
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
    // Le premier lancement a pu recevoir son argv avant que React installe
    // l'écouteur. La commande consomme alors le chemin conservé côté Rust.
    void unlistenProfilePath.then(() => consumeProfilePath())
    return () => {
      unlisten.then((f) => f())
      unlistenProfilePath.then((f) => f())
    }
  }, [consumeProfilePath, pushLog])

  const connect = useCallback(async (name?: string) => {
    setError(null)
    // Nouvelle session, nouvelle négociation : on repart d'« inconnu ». Le
    // remettre ici plutôt que sur la transition `connecting` est délibéré — un
    // handshake périmé en cours de session repasse par `connecting` sans que la
    // protection posée ait changé.
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
