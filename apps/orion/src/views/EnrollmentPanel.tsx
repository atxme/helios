import { useCallback, useEffect, useRef, useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Dialog from '@mui/material/Dialog'
import DialogActions from '@mui/material/DialogActions'
import DialogContent from '@mui/material/DialogContent'
import DialogContentText from '@mui/material/DialogContentText'
import DialogTitle from '@mui/material/DialogTitle'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { Download, MailOpen, X } from 'lucide-react'

import * as api from '../api'
import { CopyButton } from '../components/CopyButton'
import { readProfileDocument } from '../profileDocument'
import type { InvitationPreview, PendingEnrollment } from '../types'

/** Same bound as a profile document: an invitation is a few kilobytes. */
const MAX_INVITATION_BYTES = 64 * 1024

/** A fingerprint as it is compared: no spacing, no case. */
const normalizeFingerprint = (value: string) => value.replace(/\s+/g, '').toLowerCase()

const date = (unix: number) =>
  new Date(unix * 1000).toLocaleString('fr-FR', { dateStyle: 'short', timeStyle: 'short' })

/** How long ago, in the words the list uses. */
function age(unix: number): string {
  const minutes = Math.max(0, Math.round((Date.now() / 1000 - unix) / 60))
  if (minutes < 60) return `il y a ${minutes} min`
  const hours = Math.round(minutes / 60)
  if (hours < 48) return `il y a ${hours} h`
  return `il y a ${Math.round(hours / 24)} j`
}

/** Offers the request as a file, the way the operator receives it. */
function saveRequest(name: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }))
  const link = document.createElement('a')
  link.href = url
  link.download = `${name || 'poste'}.helios-request`
  link.click()
  URL.revokeObjectURL(url)
}

/**
 * Enrollment v5 (NEGOCIATION-DE-CLE-V5 §15), as the Profiles screen shows it.
 *
 * The invitation is read, its `CA-PQ` fingerprint displayed, and nothing
 * happens until the user has typed back the fingerprint the operator read out
 * of band: that confirmation is what pins the authority. Only then are the
 * keys generated — by the shell, which seals them before returning the
 * request.
 */
export function EnrollmentPanel() {
  const fileInput = useRef<HTMLInputElement>(null)
  const [error, setError] = useState<string | null>(null)
  const [invitation, setInvitation] = useState<InvitationPreview | null>(null)
  const [typed, setTyped] = useState('')
  const [name, setName] = useState('')
  const [busy, setBusy] = useState(false)
  const [request, setRequest] = useState<string | null>(null)
  const [pending, setPending] = useState<PendingEnrollment[]>([])
  const [discarding, setDiscarding] = useState<PendingEnrollment | null>(null)

  const refresh = useCallback(async () => {
    try {
      setPending(await api.listPendingEnrollments())
    } catch (cause) {
      setError(`Demandes en attente illisibles : ${String(cause)}`)
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  const close = () => {
    setInvitation(null)
    setTyped('')
    setName('')
    setRequest(null)
  }

  const readInvitation = async (file: File | undefined) => {
    if (!file) return
    setError(null)
    try {
      if (file.size > MAX_INVITATION_BYTES) {
        setError('Fichier trop volumineux pour une invitation (maximum 64 Kio).')
        return
      }
      setInvitation(await api.previewEnrollmentInvitation(await readProfileDocument(file)))
    } catch (cause) {
      setError(String(cause))
    } finally {
      if (fileInput.current) fileInput.current.value = ''
    }
  }

  const create = async () => {
    if (!invitation) return
    setBusy(true)
    setError(null)
    try {
      setRequest(await api.beginEnrollment(invitation.invitation_token, typed, name.trim()))
      await refresh()
    } catch (cause) {
      setError(String(cause))
    } finally {
      setBusy(false)
    }
  }

  const discard = async () => {
    if (!discarding) return
    const target = discarding
    setDiscarding(null)
    try {
      await api.discardPendingEnrollment(target.request_id)
      await refresh()
    } catch (cause) {
      setError(String(cause))
    }
  }

  const matches =
    invitation !== null &&
    normalizeFingerprint(typed) === normalizeFingerprint(invitation.ca_fingerprint)

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
      <Box
        component="input"
        ref={fileInput}
        type="file"
        accept=".helios-invite,text/plain"
        onChange={(event: React.ChangeEvent<HTMLInputElement>) =>
          void readInvitation(event.target.files?.[0])
        }
        sx={{ display: 'none' }}
      />
      <Button
        size="small"
        variant="outlined"
        startIcon={<MailOpen size={15} aria-hidden />}
        onClick={() => fileInput.current?.click()}
      >
        Importer une invitation
      </Button>
      {error && !invitation && (
        <Alert severity="error" onClose={() => setError(null)} sx={{ fontSize: 12 }}>
          {error}
        </Alert>
      )}

      {pending.length > 0 && (
        <Box sx={{ mt: 0.5 }}>
          <Typography
            variant="overline"
            sx={{ color: 'text.secondary', fontSize: 10, letterSpacing: 0.6 }}
          >
            Demandes en attente
          </Typography>
          {pending.map((entry) => (
            <Box
              key={entry.request_id}
              sx={{ display: 'flex', alignItems: 'center', gap: 0.5, py: 0.25 }}
            >
              <Box sx={{ minWidth: 0, flex: 1 }}>
                <Typography sx={{ fontSize: 12, fontWeight: 600 }} noWrap>
                  {entry.requested_name}
                </Typography>
                <Typography sx={{ fontSize: 11, color: 'text.secondary' }} noWrap>
                  {entry.server_name} · {age(entry.created_at_unix)}
                </Typography>
              </Box>
              <Button
                size="small"
                color="inherit"
                onClick={() => setDiscarding(entry)}
                sx={{ fontSize: 11, color: 'text.secondary', minWidth: 0 }}
              >
                Abandonner
              </Button>
            </Box>
          ))}
        </Box>
      )}

      <Dialog open={invitation !== null} onClose={close} aria-labelledby="enrollment-title">
        <DialogTitle id="enrollment-title">Invitation d’enrôlement</DialogTitle>
        <DialogContent sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
          {invitation && request === null && (
            <>
              <DialogContentText component="div">
                <Typography sx={{ fontSize: 13 }}>
                  Gateway : <strong>{invitation.server_name}</strong>
                </Typography>
                <Typography sx={{ fontSize: 13 }}>
                  Valable jusqu’au {date(invitation.expires_at_unix)}
                </Typography>
              </DialogContentText>
              <Box>
                <Typography sx={{ fontSize: 12, color: 'text.secondary' }}>
                  Empreinte de l’autorité CA-PQ que nomme l’invitation
                </Typography>
                <Typography sx={{ fontFamily: 'monospace', fontSize: 13, wordBreak: 'break-word' }}>
                  {invitation.ca_fingerprint}
                </Typography>
              </Box>
              <Typography sx={{ fontSize: 12 }}>
                Faites-vous lire cette empreinte par l’opérateur, par un autre canal que celui qui
                a apporté le fichier, puis recopiez-la. Rien n’est généré avant.
              </Typography>
              <TextField
                size="small"
                label="Empreinte lue par l’opérateur"
                value={typed}
                onChange={(event) => setTyped(event.target.value)}
                error={typed.trim() !== '' && !matches}
                helperText={
                  typed.trim() !== '' && !matches
                    ? 'Ne correspond pas : ne pas poursuivre sans l’avoir vérifiée.'
                    : ' '
                }
                slotProps={{ htmlInput: { spellCheck: false, autoComplete: 'off' } }}
              />
              <TextField
                size="small"
                label="Nom du poste"
                value={name}
                onChange={(event) => setName(event.target.value)}
                helperText="Le nom sous lequel l’opérateur admettra ce poste."
              />
            </>
          )}
          {request !== null && (
            <>
              <Alert severity="success" sx={{ fontSize: 12 }}>
                Demande créée. Les clés de ce poste sont scellées ici et ne le quittent pas.
                Transmettez la demande à l’opérateur ; le document signé qu’il renverra
                s’importe avec « Importer ».
              </Alert>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <Button
                  size="small"
                  variant="contained"
                  startIcon={<Download size={15} aria-hidden />}
                  onClick={() => saveRequest(name.trim(), request)}
                >
                  Enregistrer la demande
                </Button>
                <CopyButton value={request} label="la demande" />
              </Box>
            </>
          )}
          {error && invitation && (
            <Alert severity="error" sx={{ fontSize: 12 }}>
              {error}
            </Alert>
          )}
        </DialogContent>
        <DialogActions>
          <Button color="inherit" startIcon={<X size={15} aria-hidden />} onClick={close}>
            {request === null ? 'Annuler' : 'Fermer'}
          </Button>
          {request === null && (
            <Button
              variant="contained"
              disabled={!matches || name.trim() === '' || busy}
              onClick={() => void create()}
            >
              Créer la demande
            </Button>
          )}
        </DialogActions>
      </Dialog>

      <Dialog
        open={discarding !== null}
        onClose={() => setDiscarding(null)}
        aria-labelledby="discard-enrollment-title"
      >
        <DialogTitle id="discard-enrollment-title">
          Abandonner « {discarding?.requested_name} » ?
        </DialogTitle>
        <DialogContent>
          <DialogContentText>
            Les clés générées pour cette demande sont détruites. Un document signé en réponse ne
            pourra plus être importé sur ce poste : il faudra une nouvelle invitation.
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button color="inherit" onClick={() => setDiscarding(null)}>
            Conserver
          </Button>
          <Button color="error" variant="contained" onClick={() => void discard()}>
            Abandonner la demande
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  )
}
