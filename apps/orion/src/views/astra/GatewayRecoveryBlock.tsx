import { useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Paper from '@mui/material/Paper'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'

import * as api from '../../api'
import type { RecoveryPrepared, RecoveryRefusalCode } from '../../types'
import { saveArtifact } from './ArtifactDownloads'
import { MAX_FILE_BYTES, readFileText } from './readFileText'

/** One French sentence per refusal code: the code is the only thing the window reads. */
const REFUSAL_SENTENCES: Record<RecoveryRefusalCode, string> = {
  escrow_unreadable: 'Séquestre illisible avec cette clé.',
  legacy_escrow:
    "Séquestre d'un ancien format, qui ne porte pas le compteur : il faut le séquestre réécrit par la gateway après son passage à F5 (voir MAINTENANCE, « Passage au compteur NV »).",
  escrow_inconsistent: "Le séquestre ne correspond pas à la clé qu'il contient.",
  counter_unknown: 'Valeur du compteur inconnue : lisez-la sur la gateway et saisissez-la.',
  authorization_invalid: "Autorisation non valide : signature manquante ou d'un autre éditeur.",
  foreign_gateway: 'Cette autorisation vise une autre gateway.',
  request_mismatch:
    'Cette autorisation ne correspond pas à la requête préparée (autre valeur de compteur ou autre gateway).',
  frame_malformed: 'Fichier de récupération mal formé.',
  request_malformed: 'Requête préparée illisible ou mal formée.',
  platform_unsupported: "Cette cérémonie n'existe que sous Windows.",
}

const COUNTER_ORIGIN: Record<RecoveryPrepared['counter_source'], string> = {
  given: "Valeur fournie par l'opérateur.",
  escrow_after_ticket:
    "Valeur déduite du séquestre, en supposant qu'un billet a été consommé. Vérifiez anti-rollback.json sur la gateway.",
}

/** What the operator does with the file Orion wrote. Only its name is shown. */
const depositReminder = (fileName: string) =>
  `Fichier enregistré : ${fileName}. À déposer dans /var/lib/helios/wg-key.recovery par l'accès hors bande, puis redémarrer heliosd. Ce fichier contient la clé privée en clair : supprimez-le après usage.`

const COUNTER_INVALID = 'Valeur du compteur invalide : un entier positif est attendu.'

/** The refusal code of a rejected call, or null when the rejection is not one. */
function refusalOf(cause: unknown): RecoveryRefusalCode | null {
  if (typeof cause !== 'object' || cause === null || !('refusal' in cause)) return null
  const code = (cause as { refusal: unknown }).refusal
  return typeof code === 'string' && code in REFUSAL_SENTENCES ? (code as RecoveryRefusalCode) : null
}

/** A refusal's sentence. Anything else is a failure of the call itself: its text is never shown. */
function failureSentence(cause: unknown): string {
  const code = refusalOf(cause)
  return code ? REFUSAL_SENTENCES[code] : 'Erreur inattendue.'
}

/** The file a file field holds, if any. */
function pickedFile(target: EventTarget & (HTMLInputElement | HTMLTextAreaElement)): File | null {
  return (target as HTMLInputElement).files?.[0] ?? null
}

/** The escrow as base64 of its bytes, bounded like the other pasted files. */
async function readEscrowBase64(file: File): Promise<string> {
  if (file.size > MAX_FILE_BYTES) throw new Error('Fichier trop volumineux (maximum 256 Kio).')
  const bytes = new Uint8Array(await file.arrayBuffer())
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
}

/** An empty field is no counter; anything else must be a safe non-negative integer. */
function parseCounter(text: string): number | null {
  const trimmed = text.trim()
  if (trimmed === '') return null
  if (!/^\d+$/.test(trimmed)) throw new Error(COUNTER_INVALID)
  const value = Number(trimmed)
  if (!Number.isSafeInteger(value)) throw new Error(COUNTER_INVALID)
  return value
}

const FIELD_SX = { fontSize: 12 }
const BUTTON_SX = { minHeight: 30, fontSize: 11.5, textTransform: 'none' } as const

/**
 * Step 1: opens the escrow with the operator's key and prepares the public
 * request the publisher signs. The key and the escrow stay in this step.
 */
function PrepareStep({ onPrepared }: { onPrepared: (prepared: RecoveryPrepared | null) => void }) {
  const [escrowFile, setEscrowFile] = useState<File | null>(null)
  const [counterText, setCounterText] = useState('')
  const [busy, setBusy] = useState(false)
  const [prepared, setPrepared] = useState<RecoveryPrepared | null>(null)
  const [error, setError] = useState<string | null>(null)

  const prepare = async () => {
    if (!escrowFile) return
    setBusy(true)
    setError(null)
    try {
      const counter = parseCounter(counterText)
      const escrowB64 = await readEscrowBase64(escrowFile)
      // `null`: the operator cancelled the key dialog. Nothing is shown and nothing is an error.
      const result = await api.gatewayRecoveryPrepare(escrowB64, counter)
      if (result === null) return
      setPrepared(result)
      onPrepared(result)
    } catch (cause) {
      setPrepared(null)
      onPrepared(null)
      setError(failureSentence(cause))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Box component="section" aria-label="Préparation de la requête" sx={{ mt: 1 }}>
      <Typography component="h4" sx={{ fontSize: 12, fontWeight: 700, mb: 0.75 }}>
        Préparer la requête
      </Typography>
      <Stack spacing={1}>
        <TextField
          size="small"
          type="file"
          label="Séquestre (wg-key.escrow)"
          slotProps={{ inputLabel: { shrink: true } }}
          onChange={(event) => setEscrowFile(pickedFile(event.target))}
          fullWidth
          sx={FIELD_SX}
        />
        <TextField
          size="small"
          label="Valeur du compteur (lue sur la gateway)"
          value={counterText}
          onChange={(event) => setCounterText(event.target.value)}
          slotProps={{ htmlInput: { inputMode: 'numeric' } }}
          helperText="Facultatif : sans valeur, le compteur du séquestre plus un est pris."
          fullWidth
          sx={FIELD_SX}
        />
        <Box>
          <Button
            size="small"
            variant="outlined"
            color="inherit"
            disabled={busy || !escrowFile}
            onClick={() => void prepare()}
            sx={BUTTON_SX}
          >
            Préparer la requête
          </Button>
          <Typography color="text.secondary" sx={{ fontSize: 11, mt: 0.5 }}>
            La clé de séquestre est choisie dans une boîte Windows et lue par Orion : elle ne passe jamais par cette page.
          </Typography>
        </Box>
      </Stack>
      {prepared && (
        <Box sx={{ mt: 1.25 }}>
          <Typography sx={{ fontSize: 11.5 }}>
            Clé publique de la gateway :{' '}
            <Box component="span" sx={{ fontFamily: 'monospace', overflowWrap: 'anywhere' }}>
              {prepared.gateway_public_key}
            </Box>
          </Typography>
          <Typography sx={{ fontSize: 11.5 }}>Compteur : {prepared.counter}</Typography>
          <Typography color="text.secondary" sx={{ fontSize: 11 }}>
            {COUNTER_ORIGIN[prepared.counter_source]}
          </Typography>
          <Button
            size="small"
            variant="outlined"
            color="inherit"
            onClick={() => saveArtifact(prepared.request)}
            sx={{ ...BUTTON_SX, mt: 0.75 }}
          >
            Enregistrer wg-recovery-request.json
          </Button>
        </Box>
      )}
      {error && (
        <Alert severity="error" variant="outlined" sx={{ mt: 1, fontSize: 11.5 }}>
          {error}
        </Alert>
      )}
    </Box>
  )
}

/**
 * Step 2: assembles the recovery frame from the signed authorization. The
 * request is prefilled from step 1 of this session, or uploaded.
 */
function AssembleStep({ prepared }: { prepared: RecoveryPrepared | null }) {
  const [escrowFile, setEscrowFile] = useState<File | null>(null)
  const [uploadedRequest, setUploadedRequest] = useState<string | null>(null)
  const [authorization, setAuthorization] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [fileName, setFileName] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  // An uploaded request wins; otherwise the one prepared in step 1 of this session.
  const request = uploadedRequest ?? prepared?.request.contents ?? null

  // A cleared file input clears what it held.
  const pick = async (file: File | null, set: (text: string | null) => void) => {
    setError(null)
    if (!file) {
      set(null)
      return
    }
    try {
      set(await readFileText(file))
    } catch (cause) {
      set(null)
      setError(failureSentence(cause))
    }
  }

  const assemble = async () => {
    if (!escrowFile || request === null || authorization === null) return
    setBusy(true)
    setError(null)
    setFileName(null)
    try {
      const escrowB64 = await readEscrowBase64(escrowFile)
      // `null`: the operator cancelled a dialog. Nothing was written; nothing is shown.
      const assembled = await api.gatewayRecoveryAssemble(escrowB64, request, authorization)
      if (assembled === null) return
      setFileName(assembled.file_name)
    } catch (cause) {
      setError(failureSentence(cause))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Box component="section" aria-label="Autorisation signée" sx={{ mt: 1.5 }}>
      <Typography component="h4" sx={{ fontSize: 12, fontWeight: 700, mb: 0.75 }}>
        Autorisation signée
      </Typography>
      <Stack spacing={1}>
        <TextField
          size="small"
          type="file"
          label="Séquestre (wg-key.escrow)"
          slotProps={{ inputLabel: { shrink: true } }}
          onChange={(event) => setEscrowFile(pickedFile(event.target))}
          fullWidth
          sx={FIELD_SX}
        />
        <TextField
          size="small"
          type="file"
          label="Requête préparée (wg-recovery-request.json)"
          slotProps={{ inputLabel: { shrink: true } }}
          onChange={(event) =>
            void pick(pickedFile(event.target), (text) => setUploadedRequest(text))
          }
          helperText={
            uploadedRequest === null && prepared
              ? "Préremplie avec la requête préparée à l'étape précédente."
              : 'Aucune requête préparée dans cette session : téléversez le fichier.'
          }
          fullWidth
          sx={FIELD_SX}
        />
        <TextField
          size="small"
          type="file"
          label="Autorisation signée (wg-recovery-authorization.json)"
          slotProps={{ inputLabel: { shrink: true } }}
          onChange={(event) =>
            void pick(pickedFile(event.target), (text) => setAuthorization(text))
          }
          fullWidth
          sx={FIELD_SX}
        />
        <Box>
          <Button
            size="small"
            variant="outlined"
            color="inherit"
            disabled={busy || !escrowFile || request === null || authorization === null}
            onClick={() => void assemble()}
            sx={BUTTON_SX}
          >
            Assembler le fichier
          </Button>
        </Box>
      </Stack>
      {fileName && (
        <Alert severity="info" variant="outlined" sx={{ mt: 1.25, fontSize: 11.5 }}>
          {depositReminder(fileName)}
        </Alert>
      )}
      {error && (
        <Alert severity="error" variant="outlined" sx={{ mt: 1, fontSize: 11.5 }}>
          {error}
        </Alert>
      )}
    </Box>
  )
}

/**
 * Recovers a gateway's WireGuard identity from the operator's escrow, offline,
 * through the same core as `helios escrow`. Needs no vault and no elevation.
 */
export function GatewayRecoveryBlock() {
  const [prepared, setPrepared] = useState<RecoveryPrepared | null>(null)

  return (
    <Paper component="section" variant="outlined" aria-label="Récupérer l'identité de la gateway" sx={{ mb: 1.25, p: 1.75 }}>
      <Typography component="h3" sx={{ fontSize: 12.5, fontWeight: 700, mb: 0.5 }}>
        Récupérer l'identité de la gateway
      </Typography>
      <PrepareStep onPrepared={setPrepared} />
      <AssembleStep prepared={prepared} />
    </Paper>
  )
}
