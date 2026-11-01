import { useRef, useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { FileUp, KeyRound } from 'lucide-react'

import * as api from '../../api'
import type {
  CampaignScope,
  IssuerGesture,
  OperatorPendingOperation,
  OperatorStatus,
} from '../../types'
import { readFileText } from './readFileText'
import { useOverview } from './useOverview'

/** The scopes Orion can open a ceremony for; every other campaign is listed but not launchable. */
const OPENABLE_SCOPES = new Set<CampaignScope>([
  'orion_profile',
  'orion_device',
  'fleet_leafs',
  'full_certificate_chain',
  'issuer_delegation',
])

const OPERATION_ID = /^[0-9a-f]{32}$/

const UNREADABLE_REQUEST = 'Ce fichier est illisible ou trop grand (256 Kio au plus).'

/**
 * A button that asks for a file and hands back its text; the content is what
 * travels, never a path. A file that cannot be read says so and opens nothing.
 */
function RequestFileButton({
  label,
  inputLabel,
  disabled,
  onText,
  onUnreadable,
}: {
  label: string
  inputLabel: string
  disabled: boolean
  onText: (text: string) => void
  onUnreadable: () => void
}) {
  const input = useRef<HTMLInputElement>(null)
  const pick = async (file: File | undefined) => {
    if (!file) return
    let text: string
    try {
      text = await readFileText(file)
    } catch {
      onUnreadable()
      return
    }
    onText(text)
  }
  return (
    <>
      <input
        ref={input}
        type="file"
        hidden
        aria-label={inputLabel}
        onChange={(event) => {
          const target = event.target as HTMLInputElement
          void pick(target.files?.[0])
          target.value = ''
        }}
      />
      <Button
        size="small"
        variant="contained"
        disabled={disabled}
        startIcon={<FileUp size={14} aria-hidden />}
        onClick={() => input.current?.click()}
        sx={{ mt: 1, minHeight: 30, fontSize: 11.5 }}
      >
        {label}
      </Button>
    </>
  )
}

/**
 * The Approbations tab: the campaigns the domain opened, a recovery approved by
 * its operation id, and the delegation of Astra's issuer without a campaign.
 */
export function ApprovalsPanel({
  pending,
  onCeremony,
}: {
  pending: OperatorPendingOperation[]
  onCeremony: (status: OperatorStatus) => void
}) {
  const { overview, error: overviewError } = useOverview()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [choosing, setChoosing] = useState<string | null>(null)
  const [recoveryId, setRecoveryId] = useState('')
  const normalised = recoveryId.trim().toLowerCase()
  const recoveryValid = OPERATION_ID.test(normalised)

  const begin = async (open: () => Promise<OperatorStatus>) => {
    setBusy(true)
    setError(null)
    try {
      onCeremony(await open())
    } catch (cause) {
      setError(String(cause))
    } finally {
      setBusy(false)
    }
  }

  const beginIssuer = (gesture: IssuerGesture) => begin(() => api.beginIssuerCeremony(gesture))

  const loaded = overview != null
  const hasOrigin = loaded && Boolean(overview.domain?.astra_authority_url)

  return (
    <>
      <Typography color="text.secondary" sx={{ fontSize: 11.5, lineHeight: 1.55, mb: 1.5 }}>
        {pending.length === 0
          ? 'Aucune opération n’attend l’opérateur.'
          : pending.length === 1
            ? 'Une opération attend l’opérateur.'
            : `${pending.length} opérations attendent l’opérateur.`}
      </Typography>
      <Stack spacing={1.25}>
        {pending.map((operation) => {
          const supported = OPENABLE_SCOPES.has(operation.scope)
          const delegation = operation.scope === 'issuer_delegation'
          return (
            <Paper key={operation.operation_id} variant="outlined" sx={{ px: 1.75, py: 1.5 }}>
              <Typography sx={{ fontSize: 12.5, fontWeight: 650 }}>{operation.reason}</Typography>
              <Typography color="text.secondary" sx={{ mt: 0.25, fontSize: 11.5 }}>
                Demandée par {operation.requested_by} — {operation.target_count} pair
                {operation.target_count > 1 ? 's' : ''}, {operation.required_credentials} clé
                {operation.required_credentials > 1 ? 's' : ''} distincte
                {operation.required_credentials > 1 ? 's' : ''}
              </Typography>
              <Typography
                color="text.disabled"
                sx={{ mt: 0.25, fontSize: 10.5, fontFamily: 'monospace' }}
              >
                {operation.operation_id}
              </Typography>
              <Typography color="text.disabled" sx={{ mt: 0.25, fontSize: 11 }}>
                jusqu’au {new Date(operation.expires_at * 1000).toLocaleString()}
              </Typography>
              <Box sx={{ display: 'flex', gap: 1, flexWrap: 'wrap' }}>
                <Button
                  size="small"
                  variant="contained"
                  disabled={busy || !supported}
                  startIcon={<KeyRound size={14} aria-hidden />}
                  onClick={() =>
                    delegation
                      ? setChoosing(operation.operation_id)
                      : void begin(() =>
                          api.beginOperatorCeremony({
                            kind: 'approve_campaign',
                            operation_id: operation.operation_id,
                          }),
                        )
                  }
                  sx={{ mt: 1, minHeight: 30, fontSize: 11.5 }}
                >
                  Ouvrir la cérémonie
                </Button>
                {delegation && choosing === operation.operation_id && (
                  <RequestFileButton
                    label="Choisir la demande de délégation…"
                    inputLabel="Demande de délégation"
                    disabled={busy}
                    onUnreadable={() => setError(UNREADABLE_REQUEST)}
                    onText={(request) =>
                      void beginIssuer({
                        gesture: 'authorize_issuer',
                        operation_id: operation.operation_id,
                        request,
                      })
                    }
                  />
                )}
              </Box>
              {!supported && (
                <Alert severity="warning" variant="outlined" sx={{ mt: 1, fontSize: 11.5 }}>
                  Cette cérémonie n’est pas encore disponible dans Orion.
                </Alert>
              )}
            </Paper>
          )
        })}
      </Stack>

      <Paper variant="outlined" sx={{ mt: 1.25, px: 1.75, py: 1.5 }}>
        <Typography component="h3" sx={{ fontSize: 12.5, fontWeight: 700, mb: 1 }}>
          Approuver une récupération
        </Typography>
        <TextField
          label="Identifiant d’opération"
          value={recoveryId}
          onChange={(event) => setRecoveryId(event.target.value)}
          placeholder="32 caractères hexadécimaux"
          size="small"
          fullWidth
          slotProps={{ htmlInput: { spellCheck: false, style: { fontFamily: 'monospace' } } }}
        />
        <Button
          size="small"
          variant="contained"
          disabled={busy || !recoveryValid}
          startIcon={<KeyRound size={14} aria-hidden />}
          onClick={() =>
            void begin(() =>
              api.beginOperatorCeremony({ kind: 'recover_identity', operation_id: normalised }),
            )
          }
          sx={{ mt: 1, minHeight: 30, fontSize: 11.5 }}
        >
          Ouvrir la cérémonie
        </Button>
      </Paper>

      <Paper variant="outlined" sx={{ mt: 1.25, px: 1.75, py: 1.5 }}>
        <Typography component="h3" sx={{ fontSize: 12.5, fontWeight: 700, mb: 1 }}>
          Délégation sans campagne
        </Typography>
        {overviewError ? (
          <Alert severity="error" variant="outlined" sx={{ fontSize: 11.5 }}>
            {overviewError}
          </Alert>
        ) : !loaded ? null : hasOrigin ? (
          <Typography color="text.secondary" sx={{ fontSize: 11.5, lineHeight: 1.55 }}>
            Ce domaine a une origine Astra : une délégation passe par une campagne (
            <code>astra issuer request --reason --requested-by</code> sur l’hôte d’Astra).
          </Typography>
        ) : (
          <>
            <Alert severity="warning" variant="outlined" sx={{ fontSize: 11.5 }}>
              Rien ne rattache ce fichier à Astra : il vaut ce que vaut son transport. À réserver à
              un domaine sans origine joignable.
            </Alert>
            <RequestFileButton
              label="Signer une délégation sans campagne…"
              inputLabel="Demande de délégation sans campagne"
              disabled={busy}
              onUnreadable={() => setError(UNREADABLE_REQUEST)}
              onText={(request) =>
                void beginIssuer({ gesture: 'authorize_issuer_offline', request })
              }
            />
          </>
        )}
      </Paper>

      {error && (
        <Alert severity="error" variant="outlined" sx={{ mt: 1.25, fontSize: 11.5 }}>
          {error}
        </Alert>
      )}
    </>
  )
}
