import { useCallback, useEffect, useState } from 'react'

import * as api from '../../api'
import type { VaultOverview } from '../../types'

/**
 * Reads the operator vault overview; a failure is kept, never swallowed.
 * `refresh()` reads it again, keeping the last value on screen meanwhile.
 */
export function useOverview(): {
  overview: VaultOverview | null
  error: string | null
  refresh: () => void
} {
  const [overview, setOverview] = useState<VaultOverview | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [revision, setRevision] = useState(0)
  useEffect(() => {
    let cancelled = false
    void api
      .operatorOverview()
      .then((found) => {
        if (cancelled) return
        setOverview(found)
        setError(null)
      })
      .catch((cause) => {
        if (!cancelled) setError(String(cause))
      })
    return () => {
      cancelled = true
    }
  }, [revision])
  const refresh = useCallback(() => setRevision((current) => current + 1), [])
  return { overview, error, refresh }
}
