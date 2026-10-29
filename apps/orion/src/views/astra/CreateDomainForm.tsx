import { useEffect, useState } from 'react'
import Alert from '@mui/material/Alert'
import Button from '@mui/material/Button'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'

import * as api from '../../api'
import type { OperatorStatus } from '../../types'

const field = { '& input': { fontSize: 11.5 }, '& label': { fontSize: 11.5 } } as const

/** Creates the trust domain and its first two keys, in one ceremony. */
export function CreateDomainForm({ onCeremony }: { onCeremony: (status: OperatorStatus) => void }) {
  const [rpId, setRpId] = useState('')
  const [origin, setOrigin] = useState('')
  const [originEdited, setOriginEdited] = useState(false)
  const [first, setFirst] = useState('Clé principale')
  const [second, setSecond] = useState('Clé de récupération')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    void api
      .operatorDomainDefaults()
      .then((defaults) => {
        if (cancelled || !defaults.rp_id) return
        const suggested = defaults.rp_id
        // A name the operator already typed is theirs: only fill an empty field.
        setRpId((current) => current || suggested)
        setOrigin((current) => current || `https://${suggested}`)
      })
      .catch(() => {
        // The suggestion is a convenience; the operator can type the name.
      })
    return () => {
      cancelled = true
    }
  }, [])

  const changeRpId = (value: string) => {
    setRpId(value)
    if (!originEdited) setOrigin(value.trim() ? `https://${value.trim()}` : '')
  }

  const ready = rpId.trim() && origin.trim() && first.trim() && second.trim()
  const create = async () => {
    setBusy(true)
    setError(null)
    try {
      onCeremony(
        await api.beginVaultCeremony({
          gesture: 'create_domain',
          rp_id: rpId.trim(),
          authority_url: origin.trim(),
          first_label: first.trim(),
          second_label: second.trim(),
        }),
      )
    } catch (cause) {
      setError(String(cause))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Paper variant="outlined" sx={{ p: 1.75 }}>
      <Typography component="h3" sx={{ fontSize: 12.5, fontWeight: 700, mb: 1 }}>
        Créer un domaine
      </Typography>
      <Stack spacing={1}>
        <TextField
          size="small"
          fullWidth
          label="Nom du domaine (RP ID)"
          value={rpId}
          onChange={(event) => changeRpId(event.target.value)}
          sx={field}
        />
        <Alert severity="warning" variant="outlined" sx={{ fontSize: 11 }}>
          Ce nom ne se change plus. Prenez le nom Tailscale de la gateway si elle est dans un
          tailnet.
        </Alert>
        <TextField
          size="small"
          fullWidth
          label="Origine"
          value={origin}
          onChange={(event) => {
            setOrigin(event.target.value)
            setOriginEdited(true)
          }}
          sx={field}
        />
        <Stack direction="row" spacing={1}>
          <TextField
            size="small"
            fullWidth
            label="Clé principale"
            value={first}
            onChange={(event) => setFirst(event.target.value)}
            sx={field}
          />
          <TextField
            size="small"
            fullWidth
            label="Clé de récupération"
            value={second}
            onChange={(event) => setSecond(event.target.value)}
            sx={field}
          />
        </Stack>
        <Button
          size="small"
          variant="contained"
          disabled={busy || !ready}
          onClick={() => void create()}
          sx={{ alignSelf: 'flex-start', minHeight: 30, fontSize: 11.5 }}
        >
          Créer le domaine
        </Button>
        {error && (
          <Alert severity="error" variant="outlined" sx={{ fontSize: 11.5 }}>
            {error}
          </Alert>
        )}
      </Stack>
    </Paper>
  )
}
