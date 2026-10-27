import { useEffect, useState } from 'react'

import * as api from '../../api'
import type { VaultOverview } from '../../types'

/** Reads the operator vault overview once; a failure is kept, never swallowed. */
export function useOverview(): { overview: VaultOverview | null; error: string | null } {
  const [overview, setOverview] = useState<VaultOverview | null>(null)
  const [error, setError] = useState<string | null>(null)
  useEffect(() => {
    let cancelled = false
    void api
      .operatorOverview()
      .then((found) => {
        if (!cancelled) setOverview(found)
      })
      .catch((cause) => {
        if (!cancelled) setError(String(cause))
      })
    return () => {
      cancelled = true
    }
  }, [])
  return { overview, error }
}
