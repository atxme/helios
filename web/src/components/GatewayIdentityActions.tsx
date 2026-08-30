import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import CircularProgress from '@mui/material/CircularProgress'
import FormControlLabel from '@mui/material/FormControlLabel'
import Stack from '@mui/material/Stack'
import Switch from '@mui/material/Switch'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { Anchor, History, KeyRound, ShieldCheck, Undo2 } from 'lucide-react'
import { useState } from 'react'
import {
  abortGatewayTransition,
  installCaTransition,
  installGatewayRollback,
  installGatewayTransition,
  prepareGatewayRenewal,
} from '../api'
import type {
  AnchorDecisionView,
  CertificateDomain,
  GatewayDecisionView,
  GatewayRenewalView,
  GatewayRollbackView,
} from '../types'
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
  const [busy, setBusy] = useState<
    null | 'renewal' | 'install' | 'abort' | 'rollback' | 'anchor'
  >(null)
  const [error, setError] = useState<string | null>(null)
  const [renewal, setRenewal] = useState<GatewayRenewalView | null>(null)
  const [decision, setDecision] = useState<GatewayDecisionView | null>(null)
  const [rollback, setRollback] = useState<GatewayRollbackView | null>(null)
  const [anchor, setAnchor] = useState<AnchorDecisionView | null>(null)
  const [rotateTls, setRotateTls] = useState(false)
  const [newKey, setNewKey] = useState(false)
  const [document, setDocument] = useState('')

  const staged = domain.gateway_transition_pending
  // The window a rollback lives in, computed the same way the daemon does:
  // published, past `activation_at`, short of `not_after`. Outside it the
  // button would offer a gesture the gateway refuses.
  const inOverlap =
    staged &&
    domain.gateway_transition_published &&
    domain.gateway_activation_at !== null &&
    domain.gateway_retire_active_at !== null &&
    domain.now_unix >= domain.gateway_activation_at &&
    domain.now_unix < domain.gateway_retire_active_at

  const run = async <T,>(
    kind: 'renewal' | 'install' | 'abort' | 'rollback' | 'anchor',
    action: () => Promise<T>,
  ) => {
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

  const onAnchor = async () => {
    let parsed: unknown
    try {
      parsed = JSON.parse(document)
    } catch {
      setError('Ce n’est pas un document JSON. Coller la transition signée telle quelle.')
      return
    }
    const answer = await run('anchor', () => installCaTransition(parsed))
    if (answer) {
      setAnchor(answer)
      setDecision(null)
      setRollback(null)
      setDocument('')
    }
  }

  const onRollback = async () => {
    let parsed: unknown
    try {
      parsed = JSON.parse(document)
    } catch {
      setError('Ce n’est pas un document JSON. Coller l’autorisation signée telle quelle.')
      return
    }
    const answer = await run('rollback', () => installGatewayRollback(parsed))
    if (answer) {
      setRollback(answer)
      setDecision(null)
      setAnchor(null)
      setDocument('')
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
      setRollback(null)
      setAnchor(null)
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
        subtitle="Ce qui revient de la cérémonie : la transition du §6.1, son avortement du §6.3, ou la rotation d’ancre du §9.1."
        icon={ShieldCheck}
        accent="tertiary.main"
      >
        <Stack spacing={2}>
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            L’installation <strong>ne change pas l’identité servie</strong> : le basculement
            appartient à <code>activation_at</code> et demande un redémarrage. L’avortement n’est
            accepté que tant que rien n’a été distribué, et il consomme l’époque.
          </Typography>

          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            Une rotation d’ancre <strong>ne déplace pas non plus l’époque</strong> : les deux{' '}
            <code>CA-PQ</code> vérifient à partir de <code>activation_at</code>, et la sortante est
            retirée à <code>not_after</code> — par la même passe qui promeut les générations
            clientes. Comparer l’empreinte entrante avec celle qu’affiche le compagnon&nbsp;: au
            §9.1, c’est la comparaison qui fait foi, pas la signature seule.
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
            <Button
              variant="outlined"
              color="inherit"
              disabled={busy !== null || document.trim() === ''}
              onClick={() => void onAnchor()}
              startIcon={
                busy === 'anchor' ? (
                  <CircularProgress size={16} color="inherit" />
                ) : (
                  <Anchor size={18} />
                )
              }
            >
              Installer la rotation CA-PQ
            </Button>
          </Stack>

          {anchor && (
            <Box>
              <DataRow
                label="Époque CA-PQ"
                value={`${anchor.ca_epoch} → ${anchor.next_ca_epoch} à not_after`}
              />
              <DataRow
                label="Ancre entrante"
                value={anchor.next_ca_fingerprint}
                hint="À comparer avec l’empreinte affichée par le compagnon. Deux valeurs différentes, c’est une substitution."
                wrap
              />
              <DataRow label="Activation" value={formatInstant(anchor.activation_at)} />
              <DataRow label="Retrait" value={formatInstant(anchor.not_after)} />
              {anchor.already_present && (
                <Typography variant="body2" sx={{ mt: 1, color: 'text.secondary' }}>
                  Cette rotation était déjà installée. Rien n’a bougé.
                </Typography>
              )}
            </Box>
          )}

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

      <SectionCard
        title="Revenir à l’identité précédente"
        subtitle="§11.1 étape 8 : pendant le chevauchement seulement, et sans rien déplacer."
        icon={History}
        accent="tertiary.main"
      >
        <Stack spacing={2}>
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            Un rollback de <strong>service</strong>, pas d’état : aucun compteur ne bouge, la
            feuille suivante reste scellée et sa promotion a lieu à <code>not_after</code> comme
            prévu. La sélection expire d’elle-même, au plus tard avec le chevauchement.
          </Typography>

          {!inOverlap ? (
            <Alert severity="info">
              Aucun chevauchement en cours. Avant <code>activation_at</code> l’ancienne feuille est
              déjà celle qui sert&nbsp;; après <code>not_after</code>, la ramener serait un
              rollback d’état, que le §4.4 interdit.
            </Alert>
          ) : (
            <>
              <Alert severity="warning">
                À signer au poste opérateur&nbsp;:
                <br />
                <code>
                  astra-signer sign-gateway-rollback --transition … --out rollback.json --reason …
                  --requested-by …
                </code>
                <br />
                Puis coller l’autorisation ci-dessus et <strong>redémarrer heliosd</strong> : la
                feuille en service est descellée au démarrage et tenue pour la vie du processus.
              </Alert>
              <Button
                variant="outlined"
                color="warning"
                disabled={busy !== null || document.trim() === ''}
                onClick={() => void onRollback()}
                startIcon={
                  busy === 'rollback' ? (
                    <CircularProgress size={16} color="inherit" />
                  ) : (
                    <History size={18} />
                  )
                }
              >
                Resservir l’ancienne feuille
              </Button>
            </>
          )}

          {domain.gateway_rollback_expires_at !== null && (
            <DataRow
              label="Sélection en cours"
              value={`ancienne feuille jusqu’à ${formatInstant(domain.gateway_rollback_expires_at)}`}
            />
          )}

          {rollback && (
            <Box>
              <DataRow label="Époque" value={String(rollback.gateway_identity_epoch)} />
              <DataRow
                label="Feuille resservie"
                value={rollback.selected_certificate_fingerprint}
                wrap
              />
              <DataRow label="Expire" value={formatInstant(rollback.expires_at)} />
              {rollback.already_present && (
                <Typography variant="body2" sx={{ mt: 1, color: 'text.secondary' }}>
                  Cette autorisation était déjà appliquée. Rien n’a bougé.
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
        pas&nbsp;: dans le conteneur Astra,{' '}
        <code>astra campaign open --scope fleet-leafs</code>,{' '}
        <code>--scope trust-authorities</code>, ou <code>astra chain open</code> pour toute la
        chaîne — quatre campagnes ordonnées, quatre touchers, <code>astra chain next</code> entre
        chacune.
      </KnownLimit>
    </Stack>
  )
}
