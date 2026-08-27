import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import CircularProgress from '@mui/material/CircularProgress'
import FormControlLabel from '@mui/material/FormControlLabel'
import Stack from '@mui/material/Stack'
import Switch from '@mui/material/Switch'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { KeyRound, ShieldCheck, Undo2 } from 'lucide-react'
import { useState } from 'react'
import { abortGatewayTransition, installGatewayTransition, prepareGatewayRenewal } from '../api'
import type { CertificateDomain, GatewayDecisionView, GatewayRenewalView } from '../types'
import { DataRow } from './DataRow'
import { KnownLimit } from './KnownLimit'
import { SectionCard } from './SectionCard'

/**
 * The gestures §12.2 asks of this console, and only the ones this gateway owns.
 *
 * # Why the campaign actions are not buttons here
 *
 * « Renouveler les leafs du parc », « toute la chaîne » and « Tourner les
 * autorités » open an **Astra** campaign: the authority resolves it against
 * the targets and generations it holds, and §11.6 keeps that resolution local
 * for a reason — a campaign is the domain's inventory. Wiring a console button
 * through two hops would be inventing that surface, not exposing one. So they
 * are named, with the exact command, and the screen does not pretend.
 *
 * # Why the two ceremony halves are text areas
 *
 * A transition and its abort are signed by `CA-PQ`, in a vault this machine
 * must never hold. The console cannot produce them; what it can do is apply
 * one an operator carried back. Pasting the document is that gesture, and it
 * is deliberately the same object the CLI reads from a file — one shape, two
 * doors.
 */

interface Props {
  domain: CertificateDomain
}

function formatInstant(unix: number): string {
  return new Date(unix * 1000).toLocaleString('fr-FR', {
    dateStyle: 'medium',
    timeStyle: 'short',
  })
}

export function GatewayIdentityActions({ domain }: Props) {
  const [busy, setBusy] = useState<null | 'renewal' | 'install' | 'abort'>(null)
  const [error, setError] = useState<string | null>(null)
  const [renewal, setRenewal] = useState<GatewayRenewalView | null>(null)
  const [decision, setDecision] = useState<GatewayDecisionView | null>(null)
  const [rotateTls, setRotateTls] = useState(false)
  const [newKey, setNewKey] = useState(false)
  const [document, setDocument] = useState('')

  const staged = domain.gateway_transition_pending

  const run = async <T,>(kind: 'renewal' | 'install' | 'abort', action: () => Promise<T>) => {
    setBusy(kind)
    setError(null)
    try {
      return await action()
    } catch (cause: unknown) {
      setError(cause instanceof Error ? cause.message : 'refusé')
      return null
    } finally {
      setBusy(null)
    }
  }

  const onPrepare = async () => {
    const answer = await run('renewal', () =>
      prepareGatewayRenewal({ rotate_tls: rotateTls, new_key: newKey, key_recovery: false }),
    )
    if (answer) {
      setRenewal(answer)
      setDecision(null)
    }
  }

  const onApply = async (kind: 'install' | 'abort') => {
    let parsed: unknown
    try {
      parsed = JSON.parse(document)
    } catch {
      setError('Ce n’est pas un document JSON. Coller la décision signée telle quelle.')
      return
    }
    const answer = await run(kind, () =>
      kind === 'install' ? installGatewayTransition(parsed) : abortGatewayTransition(parsed),
    )
    if (answer) {
      setDecision(answer)
      setDocument('')
    }
  }

  return (
    <Stack spacing={2.5}>
      <SectionCard
        title="Renouveler l’identité gateway"
        subtitle="§11.1 étapes 1 et 2 : la clé suivante est scellée ici, seule sa moitié publique part."
        icon={KeyRound}
        accent="tertiary.main"
      >
        <Stack spacing={2}>
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            La clé candidate est scellée <strong>à côté</strong> de celle en service : la feuille
            active continue de monter les tunnels pendant toute la cérémonie. Relancer est une
            reprise — une demande encore valide pour la même époque est rendue telle quelle.
          </Typography>

          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
            <FormControlLabel
              control={
                <Switch
                  checked={rotateTls}
                  onChange={event => setRotateTls(event.target.checked)}
                  size="small"
                />
              }
              label="Remplacer aussi la feuille TLS"
            />
            <FormControlLabel
              control={
                <Switch
                  checked={newKey}
                  onChange={event => setNewKey(event.target.checked)}
                  size="small"
                />
              }
              label="Détruire la candidate scellée et en tirer une neuve"
            />
          </Stack>

          <Box>
            <Button
              variant="contained"
              disabled={busy !== null || staged}
              onClick={() => void onPrepare()}
              startIcon={
                busy === 'renewal' ? (
                  <CircularProgress size={16} color="inherit" />
                ) : (
                  <KeyRound size={18} />
                )
              }
            >
              Préparer la demande
            </Button>
          </Box>

          {staged && (
            <Typography variant="body2" sx={{ color: 'text.secondary' }}>
              Une transition est déjà en attente à l’époque {domain.gateway_identity_epoch + 1}.
              La promouvoir ou l’annuler avant d’en préparer une autre : une époque ne porte
              qu’une décision.
            </Typography>
          )}

          {renewal && (
            <Box>
              <DataRow label="Époque" value={String(renewal.gateway_identity_epoch)} />
              <DataRow label="Identifiant" value={renewal.request_id} wrap />
              <DataRow
                label="Empreinte"
                value={renewal.request_fingerprint}
                hint="La valeur à comparer au compagnon. Deux empreintes différentes pour une même époque, c’est une substitution."
                wrap
              />
              <DataRow label="Expire" value={formatInstant(renewal.expires_at)} />
              <DataRow
                label="Feuille TLS candidate"
                value={renewal.candidate_tls_fingerprint ?? 'inchangée'}
                wrap
              />
              {renewal.reused && (
                <Typography variant="body2" sx={{ mt: 1, color: 'text.secondary' }}>
                  Demande déjà préparée pour cette époque, rendue inchangée.
                </Typography>
              )}
              <Alert severity="info" sx={{ mt: 1.5 }}>
                Le fichier attend dans <code>/var/lib/helios/gateway-certificate-request.json</code>.
                Le porter au poste opérateur, puis&nbsp;:
                <br />
                <code>astra gateway-identity open --reason … --requested-by …</code>
                <br />
                <code>astra-signer sign-gateway-transition …</code>
              </Alert>
            </Box>
          )}
        </Stack>
      </SectionCard>

      <SectionCard
        title="Appliquer une décision signée"
        subtitle="Ce qui revient de la cérémonie CA-PQ : la transition du §6.1, ou l’avortement du §6.3."
        icon={ShieldCheck}
        accent="tertiary.main"
      >
        <Stack spacing={2}>
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            L’installation <strong>ne change pas l’identité servie</strong> : le basculement
            appartient à <code>activation_at</code> et demande un redémarrage. L’avortement n’est
            accepté que tant que rien n’a été distribué, et il consomme l’époque.
          </Typography>

          <TextField
            multiline
            minRows={4}
            maxRows={12}
            fullWidth
            value={document}
            onChange={event => setDocument(event.target.value)}
            placeholder="Coller ici la transition ou l’avortement signé, tel quel"
            slotProps={{ input: { sx: { fontFamily: 'monospace', fontSize: '0.75rem' } } }}
          />

          <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}>
            <Button
              variant="contained"
              disabled={busy !== null || document.trim() === ''}
              onClick={() => void onApply('install')}
              startIcon={
                busy === 'install' ? (
                  <CircularProgress size={16} color="inherit" />
                ) : (
                  <ShieldCheck size={18} />
                )
              }
            >
              Installer la transition
            </Button>
            <Button
              variant="outlined"
              color="inherit"
              disabled={busy !== null || document.trim() === '' || !staged}
              onClick={() => void onApply('abort')}
              startIcon={
                busy === 'abort' ? <CircularProgress size={16} color="inherit" /> : <Undo2 size={18} />
              }
            >
              Annuler la transition préparée
            </Button>
          </Stack>

          {decision && (
            <Box>
              <DataRow label="Époque" value={String(decision.gateway_identity_epoch)} />
              <DataRow label="Document" value={decision.fingerprint} wrap />
              {decision.activation_at !== null && (
                <DataRow label="Activation" value={formatInstant(decision.activation_at)} />
              )}
              {decision.not_after !== null && (
                <DataRow label="Retrait" value={formatInstant(decision.not_after)} />
              )}
              {decision.already_present && (
                <Typography variant="body2" sx={{ mt: 1, color: 'text.secondary' }}>
                  Cette décision était déjà appliquée. Rien n’a bougé.
                </Typography>
              )}
            </Box>
          )}
        </Stack>
      </SectionCard>

      {error && (
        <Alert severity="error" onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <KnownLimit register="scope" title="Ce que cette console ne fait pas encore">
        « Renouveler les leafs du parc », « Renouveler toute la chaîne » et « Tourner les
        autorités » ouvrent une campagne <strong>Astra</strong>, qui la résout sur les cibles et
        générations qu’elle détient — §11.6 garde cette résolution locale, parce qu’une campagne
        est l’inventaire du domaine. Les ouvrir depuis ici demanderait une surface qui n’existe
        pas&nbsp;: <code>astra campaign open --scope fleet-leafs</code> ou{' '}
        <code>--scope trust-authorities</code>, dans le conteneur Astra.
        <br />
        Le retour temporaire à l’identité précédente pendant le chevauchement n’a pas de commande
        non plus : l’ancien slot reste scellé jusqu’à <code>not_after</code>, mais rien ne demande
        au démon de le resservir.
      </KnownLimit>
    </Stack>
  )
}
