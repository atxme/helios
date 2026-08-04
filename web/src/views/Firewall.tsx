import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Paper from '@mui/material/Paper'
import Skeleton from '@mui/material/Skeleton'
import Stack from '@mui/material/Stack'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'
import { Globe, Lock, LockOpen, Network, RotateCcw, Send, Server, Wifi } from 'lucide-react'
import { useEffect, useState } from 'react'
import { applyFirewallRules, fetchFirewallRules } from '../api'
import { DataRow } from '../components/DataRow'
import { KnownLimit } from '../components/KnownLimit'
import { SectionCard } from '../components/SectionCard'
import { TUNNEL_STATE, toneColors } from '../state'
import { CARD_RADIUS } from '../theme'
import type { Status, TunnelState } from '../types'

interface Props {
  status: Status | null
  state: TunnelState
}

/**
 * The kill-switch, shown as what it is: a consequence, not a setting.
 *
 * Its tone is the tunnel state's own tone rather than a red/green binary. The
 * previous interface painted "engaged" red across the board, which read as a
 * fault even when the gateway was simply stopped — and left an operator no way
 * to tell a deliberate shutdown from a fail-closed after an error, the one
 * distinction that decides whether anyone needs to be woken up.
 */
function KillSwitchCard({ state }: { state: TunnelState }) {
  const semantics = TUNNEL_STATE[state]
  const tone = toneColors(semantics.tone)
  const engaged = semantics.killSwitchEngaged

  return (
    <Paper
      sx={{
        borderRadius: `${CARD_RADIUS}px`,
        bgcolor: tone.container,
        color: tone.onContainer,
        px: 3,
        py: 2.5,
      }}
    >
      <Stack direction="row" spacing={2.5} sx={{ alignItems: 'center', flexWrap: 'wrap', rowGap: 2 }}>
        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: 52,
            height: 52,
            borderRadius: '50%',
            flexShrink: 0,
            color: tone.main,
            bgcolor: 'surfaceContainer.lowest',
          }}
        >
          {engaged ? <Lock size={24} strokeWidth={1.7} /> : <LockOpen size={24} strokeWidth={1.7} />}
        </Box>
        <Box sx={{ minWidth: 0, flex: 1 }}>
          <Typography variant="h4" sx={{ color: 'inherit', fontWeight: 500 }}>
            {engaged ? 'Kill-switch engagé' : 'Kill-switch levé'}
          </Typography>
          <Typography variant="body2" sx={{ color: 'inherit', opacity: 0.85, mt: 0.75 }}>
            {engaged
              ? state === 'captive_portal'
                ? 'Kill-switch partiel — HTTP/HTTPS limité à la passerelle du portail captif.'
                : 'Trafic LAN bloqué — seuls WireGuard et les exceptions d’administration restent autorisés.'
              : 'Trafic LAN autorisé à travers l’interface WireGuard.'}
          </Typography>
        </Box>
      </Stack>
    </Paper>
  )
}

function NftablesEditor({ dryRun }: { dryRun: boolean }) {
  const [rules, setRules] = useState('')
  const [original, setOriginal] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [feedback, setFeedback] = useState<{ ok: boolean; message: string } | null>(null)
  const dirty = rules !== original

  useEffect(() => {
    fetchFirewallRules()
      .then(response => {
        setRules(response.rules)
        setOriginal(response.rules)
      })
      .catch(() => setRules('# Impossible de charger les règles'))
      .finally(() => setLoading(false))
  }, [])

  const save = async () => {
    setSaving(true)
    setFeedback(null)
    try {
      await applyFirewallRules(rules)
      setOriginal(rules)
      setFeedback({
        ok: true,
        message: dryRun
          ? 'Reçu en simulation — aucune application noyau.'
          : 'Commande reçue — l’application de rulesets bruts reste à câbler dans l’orchestrateur.',
      })
    } catch {
      setFeedback({ ok: false, message: 'Échec de l’envoi au démon.' })
    } finally {
      setSaving(false)
    }
  }

  return (
    <SectionCard
      title="Ruleset nftables"
      subtitle={
        dirty ? 'Modifié — non transmis.' : 'Rendu de la politique structurée appliquée par le démon.'
      }
      action={
        <Stack direction="row" spacing={1}>
          <Button
            size="small"
            variant="outlined"
            color="inherit"
            disabled={!dirty || saving}
            onClick={() => {
              setRules(original)
              setFeedback(null)
            }}
            startIcon={<RotateCcw size={15} />}
            sx={{ borderColor: 'divider', color: 'text.secondary' }}
          >
            Réinitialiser
          </Button>
          <Button
            size="small"
            variant="contained"
            disabled={!dirty || saving}
            onClick={() => void save()}
            startIcon={<Send size={15} />}
          >
            {saving ? 'Envoi…' : 'Transmettre'}
          </Button>
        </Stack>
      }
    >
      <Stack spacing={2}>
        <KnownLimit register="caution" title="Le texte saisi ici n’est pas appliqué au noyau">
          Le rendu reflète fidèlement la politique structurée, mais l’application d’un ruleset
          nftables écrit à la main n’est pas implémentée dans l’orchestrateur : la commande est reçue
          et journalisée, puis ignorée. La politique réelle se change dans la configuration, pas ici.
        </KnownLimit>

        {loading ? (
          <Stack spacing={1}>
            <Skeleton variant="text" width="40%" />
            <Skeleton variant="text" width="65%" />
            <Skeleton variant="text" width="30%" />
          </Stack>
        ) : (
          <TextField
            value={rules}
            onChange={event => {
              setRules(event.target.value)
              setFeedback(null)
            }}
            multiline
            minRows={12}
            fullWidth
            spellCheck={false}
            slotProps={{
              input: { sx: { fontFamily: 'monospace', fontSize: '0.75rem', lineHeight: 1.7 } },
            }}
          />
        )}

        {feedback && (
          <Typography
            variant="body2"
            role="status"
            sx={{ color: feedback.ok ? 'state.up.main' : 'error.main' }}
          >
            {feedback.message}
          </Typography>
        )}
      </Stack>
    </SectionCard>
  )
}

export function FirewallView({ status, state }: Props) {
  const sshCidrs = status?.allow_ssh_from ?? []

  return (
    <Stack spacing={2.5}>
      <KillSwitchCard state={state} />

      <Box
        sx={{
          display: 'grid',
          gap: 2.5,
          gridTemplateColumns: { xs: '1fr', lg: '1fr 1fr' },
        }}
      >
        <SectionCard title="Politique appliquée">
          {status ? (
            <Box>
              <DataRow icon={Globe} label="WAN" value={status.wan_iface} />
              <DataRow icon={Network} label="LAN protégé" value={status.lan_ifaces.join(', ')} />
              <DataRow
                icon={Wifi}
                label="Écoute WG"
                value={status.wg_listen_port ? `UDP ${status.wg_listen_port}` : 'fermée'}
              />
              <DataRow icon={Server} label="Pairs admis" value={String(status.peers.length)} />
            </Box>
          ) : (
            <Skeleton variant="rounded" height={140} />
          )}
        </SectionCard>

        <SectionCard
          title="SSH d’administration"
          subtitle="Exception permanente : ces règles survivent au kill-switch."
        >
          {sshCidrs.length === 0 ? (
            <Typography variant="body2" sx={{ color: 'text.secondary' }}>
              Bloqué — défaut sécurisé. Ouvrir un accès demande de renseigner{' '}
              <code>allow_ssh_from</code> dans la configuration.
            </Typography>
          ) : (
            <Box>
              {sshCidrs.map(cidr => (
                <DataRow
                  key={cidr}
                  icon={Lock}
                  label="tcp/22"
                  value={cidr}
                  hint="Autorisé en permanence, y compris kill-switch engagé."
                />
              ))}
            </Box>
          )}
        </SectionCard>
      </Box>

      <NftablesEditor dryRun={status?.dry_run ?? true} />

      <KnownLimit register="caution" title="Le DNS d’un client ne passe pas par le tunnel">
        Même avec <code>allow_client_internet</code> actif, les requêtes DNS d’un client sortent hors
        du tunnel et sont donc visibles de son réseau local et de son fournisseur d’accès. Le trafic
        applicatif, lui, reste bien encapsulé. Fermer cet écart demande de rediriger le port 53 des
        clients dans le ruleset.
      </KnownLimit>

      <KnownLimit title="Les compteurs de paquets rejetés ne sont pas relevés">
        Ils exigent la lecture des compteurs nftables par Netlink sur la cible ; en simulation aucun
        paquet ne traverse le noyau, il n’y aurait rien à compter.
      </KnownLimit>
    </Stack>
  )
}
