import Box from '@mui/material/Box'
import Chip from '@mui/material/Chip'
import Paper from '@mui/material/Paper'
import Skeleton from '@mui/material/Skeleton'
import Stack from '@mui/material/Stack'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { Fingerprint, Globe, Lock, LockOpen, Network, Server, ShieldCheck, Terminal, Wifi } from 'lucide-react'
import { useEffect, useState } from 'react'
import { fetchTrust } from '../api'
import { DataRow } from '../components/DataRow'
import { KnownLimit } from '../components/KnownLimit'
import { SectionCard } from '../components/SectionCard'
import { TUNNEL_STATE, toneColors } from '../state'
import { CARD_RADIUS } from '../theme'
import type { Status, Trust, TunnelState } from '../types'

/**
 * What is enforced right now, and what this binary trusts.
 *
 * Folds together three former screens. The firewall's raw nftables editor is
 * gone: it accepted text and never applied it, which invited an operator to
 * believe they had changed the policy. A control that does nothing is worse
 * than an absent one.
 */

/**
 * The kill-switch, shown as what it is: a consequence, not a setting.
 *
 * Its tone follows the tunnel state rather than a red/green binary. Painting
 * "engaged" red across the board read as a fault even when the gateway was
 * simply stopped, and left no way to tell a deliberate shutdown from a
 * fail-closed after an error — the one distinction that decides whether
 * anybody needs to be woken up.
 */
function KillSwitchCard({ state }: { state: TunnelState }) {
  const semantics = TUNNEL_STATE[state]
  const tone = toneColors(semantics.tone)
  const engaged = semantics.killSwitchEngaged

  return (
    <Paper
      sx={{
        position: 'relative',
        overflow: 'hidden',
        borderRadius: `${CARD_RADIUS}px`,
        bgcolor: 'surfaceContainer.low',
        border: '1px solid',
        borderColor: 'divider',
        boxShadow: 'var(--mui-palette-cardShadow)',
        px: 3,
        py: 2.5,
        '&::before': {
          content: '""',
          position: 'absolute',
          insetBlock: 0,
          left: 0,
          width: '4px',
          bgcolor: tone.main,
        },
      }}
    >
      <Stack direction="row" spacing={2.5} sx={{ alignItems: 'center', pl: 1 }}>
        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: 46,
            height: 46,
            borderRadius: '12px',
            flexShrink: 0,
            bgcolor: tone.container,
            color: tone.main,
          }}
        >
          {engaged ? <Lock size={23} strokeWidth={2} /> : <LockOpen size={23} strokeWidth={2} />}
        </Box>
        <Box sx={{ minWidth: 0 }}>
          <Typography variant="h4">
            {engaged ? 'Kill-switch engagé' : 'Kill-switch levé'}
          </Typography>
          <Typography variant="body2" sx={{ color: 'text.secondary', mt: 0.5 }}>
            {engaged
              ? state === 'captive_portal'
                ? 'HTTP/HTTPS limité à la passerelle du portail captif.'
                : 'Trafic LAN bloqué. Seuls WireGuard et les exceptions d’administration passent.'
              : 'Trafic LAN autorisé à travers l’interface WireGuard.'}
          </Typography>
        </Box>
      </Stack>
    </Paper>
  )
}

function TrustPanel() {
  const [trust, setTrust] = useState<Trust | null>(null)
  const [error, setError] = useState(false)

  useEffect(() => {
    fetchTrust()
      .then(setTrust)
      .catch(() => setError(true))
  }, [])

  if (error) {
    return (
      <KnownLimit register="danger" title="Ancre de confiance illisible">
        Le démon ne répond pas sur <code>/api/trust</code>.
      </KnownLimit>
    )
  }

  if (!trust) return <Skeleton variant="rounded" height={180} />

  return (
    <Stack spacing={2.5}>
      {trust.development_keys && (
        <KnownLimit register="danger" title="Trousseau de développement compilé dans ce binaire">
          Il accepte des artefacts signés par les clés de test du dépôt — n’importe qui peut en
          forger. Normal en développement, jamais sur un équipement déployé.
        </KnownLimit>
      )}

      <SectionCard
        title="Ancre de confiance"
        icon={Fingerprint}
        accent="tertiary.main"
      >
        <Stack spacing={2}>
          <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap', rowGap: 1 }}>
            {trust.required_algs.map(alg => (
              <Chip
                key={alg}
                size="small"
                label={alg}
                sx={{
                  bgcolor: 'tertiary.container',
                  color: 'tertiary.onContainer',
                  fontFamily: 'monospace',
                }}
              />
            ))}
          </Stack>

          <Box>
            {trust.publisher_keys.map(key => (
              <DataRow
                key={key.key_epoch}
                label={`époque ${key.key_epoch}`}
                value={key.fingerprint}
                hint="SHA-256(ed25519 ‖ ml-dsa-65), tronqué à 128 bits. Un trousseau dont seule la moitié Ed25519 serait la bonne ne produirait pas cette valeur."
                wrap
              />
            ))}
            <DataRow label="Domaine" value={trust.reseal_domain} wrap />
          </Box>
        </Stack>
      </SectionCard>
    </Stack>
  )
}

export function SecurityView({ status, state }: { status: Status | null; state: TunnelState }) {
  const sshCidrs = status?.allow_ssh_from ?? []
  const negotiation = status?.key_negotiation_port ?? null

  return (
    <Stack spacing={2.5}>
      <KillSwitchCard state={state} />

      <Box sx={{ display: 'grid', gap: 2.5, gridTemplateColumns: { xs: '1fr', lg: '1fr 1fr' } }}>
        <SectionCard title="Politique appliquée" icon={ShieldCheck} accent="state.up.main">
          {status ? (
            <Box>
              <DataRow icon={Globe} label="WAN" value={status.wan_ifaces.join(', ')} />
              <DataRow icon={Network} label="LAN protégé" value={status.lan_ifaces.join(', ')} />
              <DataRow
                icon={Wifi}
                label="Écoute WG"
                value={status.wg_listen_port ? `UDP ${status.wg_listen_port}` : 'fermée'}
              />
              <DataRow icon={Server} label="Pairs admis" value={String(status.peers.length)} />
              <DataRow
                icon={Lock}
                label="Défaut"
                value="DROP"
                hint="Architecture fail-closed : rien ne passe sans règle explicite."
              />
            </Box>
          ) : (
            <Skeleton variant="rounded" height={160} />
          )}
        </SectionCard>

        <SectionCard
          title="Négociation post-quantique"
          icon={Fingerprint}
          accent="tertiary.main"
        >
          <Box>
            <DataRow
              icon={Wifi}
              label="Port"
              value={negotiation ? `UDP ${negotiation}` : 'inactif'}
              hint="Absent, le service reste fermé sans erreur : aucun PSK post-quantique n’est négocié, et un client qui épingle cette gateway échoue avant WireGuard."
            />
            <DataRow
              label="Authentification"
              value="ML-DSA-87"
              hint="Requête, réponse, confirmation et commit sont signés. TLS 1.3 mutuel reste le transport, il n’est plus l’ancre."
            />
            <DataRow
              label="Secret"
              value="ML-KEM-1024"
              hint="Orion génère la paire éphémère, Helios encapsule. Le PSK est posé sur le plan de données avant d’être annoncé."
            />
            <DataRow
              label="Plancher"
              value="monte seul"
              hint="Chaque négociation aboutie élève le plancher du pair. Aucun message réseau ne peut l’abaisser : seule une édition locale de network.toml le peut."
            />
          </Box>
        </SectionCard>
      </Box>

      <SectionCard
        title="SSH d’administration"
        icon={Terminal}
        accent="warning.main"
      >
        {sshCidrs.length === 0 ? (
          <Typography variant="body2" sx={{ color: 'text.secondary' }}>
            Bloqué — défaut sécurisé. Ouvrir un accès demande de renseigner{' '}
            <code>allow_ssh_from</code> dans la configuration.
          </Typography>
        ) : (
          <Stack direction="row" spacing={1} sx={{ flexWrap: 'wrap', rowGap: 1 }}>
            {sshCidrs.map(cidr => (
              <Tooltip key={cidr} title="Autorisé en permanence, y compris kill-switch engagé.">
                <Chip
                  size="small"
                  label={`${cidr} · tcp/22`}
                  sx={{
                    bgcolor: 'warning.container',
                    color: 'warning.onContainer',
                    fontFamily: 'monospace',
                  }}
                />
              </Tooltip>
            ))}
          </Stack>
        )}
      </SectionCard>

      <TrustPanel />
    </Stack>
  )
}
