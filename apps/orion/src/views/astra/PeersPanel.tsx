import { useCallback, useEffect, useRef, useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import CircularProgress from '@mui/material/CircularProgress'
import Paper from '@mui/material/Paper'
import Typography from '@mui/material/Typography'

import * as api from '../../api'
import { GRAPHITE, RULE } from '../../theme'
import type {
  OperatorStatus,
  PeersOverview,
  RevocationGesture,
  RevocationReasonChoice,
  RotationsOverview,
} from '../../types'
import { MotifChoice } from './RotationSteps'
import { PrerequisiteLine } from './RotationsPanel'
import { STATE, peerRows } from './peerRows'
import type { PeerRow } from './peerRows'
import { formatDate, overlapReason, prerequisites, reachLabel } from './rotationRows'
import type { Prerequisite } from './rotationRows'

const MOTIFS: { value: RevocationReasonChoice; label: string }[] = [
  { value: 'stolen_or_lost', label: 'Volé ou perdu' },
  { value: 'compromised', label: 'Compromis' },
  { value: 'no_longer_used', label: 'Plus utilisé' },
  { value: 'replaced', label: 'Remplacé' },
]

const UNREAD_NAMES = {
  certificates: 'Postes',
  admitted: 'Admission',
  astra_revoked: 'Astra',
  pending_revocations: 'Révocations en attente',
} as const

function named(lines: Prerequisite[], label: string): Prerequisite[] {
  return lines.filter((line) => line.label === label)
}

/**
 * What cutting a workstation needs: the tunnel, the administrator and the gateway. The rotations
 * overview states them when it was read; the peers read states them otherwise. Neither needs
 * Astra or the vault, so a failed rotations read never blocks the cut.
 */
function cutLines(peers: PeersOverview, rotations: RotationsOverview | null): Prerequisite[] {
  if (rotations) {
    const base = prerequisites(rotations, 'renew_fleet')
    return [
      ...named(base, 'Tunnel connecté'),
      ...named(base, 'Administrateur du tunnel'),
      {
        label: 'Gateway du domaine',
        ok: rotations.domain.state === 'ok',
        fix: null,
        fixAction: null,
        detail: reachLabel(rotations.domain),
      },
    ]
  }
  const reach = peers.certificates
  const ok = reach.state === 'ok'
  const detail = reachLabel(reach)
  return ['Tunnel connecté', 'Administrateur du tunnel', 'Gateway du domaine'].map((label) => ({
    label,
    ok,
    fix: null,
    fixAction: null,
    detail,
  }))
}

/**
 * What signing needs: Astra, the vault, a concordant domain, and no CA-PQ overlap running. A
 * red line here leaves the row « Coupé, révocation à signer » rather than stopping the cut.
 */
function signLines(rotations: RotationsOverview | null): Prerequisite[] {
  if (!rotations) {
    return [
      {
        label: 'Prérequis de signature non lus.',
        ok: false,
        fix: null,
        fixAction: null,
        detail: null,
      },
    ]
  }
  const base = prerequisites(rotations, 'renew_fleet')
  const overlap = overlapReason(rotations.caPqOverlap)
  return [
    ...named(base, 'Service Astra'),
    ...named(base, 'Coffre présent'),
    ...named(base, 'Domaine concordant'),
    { label: 'Signature possible', ok: overlap === null, fix: null, fixAction: null, detail: overlap },
  ]
}

/** The line of the reads that failed, above the list: the way the rotations tab says it. */
function unreadLine(peers: PeersOverview): string | null {
  const parts = (Object.keys(UNREAD_NAMES) as (keyof typeof UNREAD_NAMES)[])
    .map((key) => {
      const label = reachLabel(peers[key])
      return label === null ? null : `${UNREAD_NAMES[key]} : ${label}`
    })
    .filter((part): part is string => part !== null)
  return parts.length > 0 ? parts.join(' · ') : null
}

/**
 * The Postes tab: one row per workstation of the domain, its computed state, and « Révoquer »
 * or « Reprendre » through the revocation ceremony. The ceremony's keys and follow-up are drawn
 * by the Astra view once `onCeremony` hands it over, as the Rotations tab does.
 */
export function PeersPanel({ onCeremony }: { onCeremony: (status: OperatorStatus) => void }) {
  const [peers, setPeers] = useState<PeersOverview | null>(null)
  const [peersError, setPeersError] = useState<string | null>(null)
  const [rotations, setRotations] = useState<RotationsOverview | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const [motif, setMotif] = useState<RevocationReasonChoice | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const alive = useRef(true)

  // Both reads at once, each keeping its own answer: a failed one leaves the other standing.
  const read = useCallback(async () => {
    const [peersRead, rotationsRead] = await Promise.allSettled([
      api.operatorPeersOverview(),
      api.operatorRotationsOverview(),
    ])
    if (!alive.current) return
    if (peersRead.status === 'fulfilled') {
      setPeers(peersRead.value)
      setPeersError(null)
    } else {
      setPeersError(String(peersRead.reason))
    }
    setRotations(rotationsRead.status === 'fulfilled' ? rotationsRead.value : null)
  }, [])

  useEffect(() => {
    alive.current = true
    void read()
    return () => {
      alive.current = false
    }
  }, [read])

  const rows = peers ? peerRows(peers) : []
  const chosen = rows.find((row) => row.key === selected && row.action !== null) ?? null
  const lines = peers ? { cut: cutLines(peers, rotations), sign: signLines(rotations) } : null
  const cutReady = lines !== null && lines.cut.every((line) => line.ok)
  const signReady = lines !== null && lines.sign.every((line) => line.ok)
  // « Révoquer » cuts first, so it needs the cut group; « Reprendre » only signs, so it needs the sign group.
  const gateOpen = chosen?.action === 'resume' ? signReady : cutReady

  const choose = (row: PeerRow) => {
    setError(null)
    setMotif(null)
    setSelected((current) => (current === row.key ? null : row.key))
  }

  const send = async (row: PeerRow, reason: RevocationReasonChoice) => {
    setBusy(true)
    setError(null)
    const gesture: RevocationGesture =
      row.action === 'resume'
        ? { gesture: 'resume', peer: row.key, reason }
        : { gesture: 'revoke', peer: row.key, name: row.name, reason }
    try {
      onCeremony(await api.beginRevocationCeremony(gesture))
    } catch (cause) {
      setError(String(cause))
    } finally {
      setBusy(false)
      void read()
    }
  }

  if (!peers) {
    return peersError ? (
      <Alert severity="error" variant="outlined" sx={{ fontSize: 11.5 }}>
        {peersError}
      </Alert>
    ) : (
      <Box sx={{ display: 'flex', justifyContent: 'center', py: 3 }}>
        <CircularProgress size={18} aria-label="Lecture en cours" />
      </Box>
    )
  }

  const unread = unreadLine(peers)

  return (
    <>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 1 }}>
        <Typography component="h3" sx={{ fontSize: 13, fontWeight: 650 }}>
          Postes
        </Typography>
        <Button
          size="small"
          variant="outlined"
          aria-label="Actualiser"
          disabled={busy}
          onClick={() => void read()}
          sx={{ minWidth: 32, minHeight: 28, fontSize: 13 }}
        >
          ↻
        </Button>
      </Box>
      {unread && (
        <Typography color="text.secondary" sx={{ fontSize: 11.5, mb: 1 }}>
          {unread}
        </Typography>
      )}
      {rows.length === 0 && !unread && (
        <Typography color="text.secondary" sx={{ fontSize: 11.5 }}>
          Aucun poste.
        </Typography>
      )}
      {rows.map((row) => {
        const revoked = row.state === STATE.REVOKED
        return (
          <Paper
            key={row.key}
            component="section"
            aria-label={row.name}
            variant="outlined"
            sx={{ mb: 1, px: 1.5, py: 1.25, borderColor: RULE, opacity: revoked ? 0.6 : 1 }}
          >
            <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 1, minWidth: 0 }}>
              <Typography sx={{ fontSize: 13, fontWeight: 700, overflowWrap: 'anywhere' }}>
                {row.name}
              </Typography>
              {row.own && (
                <Typography color="text.secondary" sx={{ fontSize: 11 }}>
                  Ce poste
                </Typography>
              )}
            </Box>
            {row.addedAt !== undefined && (
              <Typography color="text.secondary" sx={{ fontSize: 11 }}>
                {`Ajouté le ${formatDate(row.addedAt)}`}
              </Typography>
            )}
            <Typography sx={{ fontSize: 11.5, color: revoked ? GRAPHITE : 'text.primary' }}>
              {row.state}
            </Typography>
            <Typography color="text.secondary" sx={{ fontSize: 11.5 }}>
              {`Échéance le ${formatDate(row.notAfter)}`}
            </Typography>
            {row.reason && (
              <Typography color="text.secondary" sx={{ fontSize: 11, overflowWrap: 'anywhere' }}>
                {row.reason}
              </Typography>
            )}
            {row.action && (
              <Button
                size="small"
                variant="outlined"
                disabled={busy}
                aria-expanded={chosen?.key === row.key}
                onClick={() => choose(row)}
                sx={{ mt: 0.75, minHeight: 28, fontSize: 12 }}
              >
                {row.action === 'resume' ? 'Reprendre' : 'Révoquer'}
              </Button>
            )}
          </Paper>
        )
      })}

      {chosen && (
        <Paper component="section" aria-label="Prérequis" variant="outlined" sx={{ mt: 1, px: 1.5, py: 1.25 }}>
          <Typography component="h3" sx={{ mb: 0.5, fontSize: 12.5, fontWeight: 700 }}>
            Prérequis
          </Typography>
          {lines && (
            <Box component="ul" sx={{ m: 0, p: 0 }}>
              {[...lines.cut, ...lines.sign].map((line) => (
                <PrerequisiteLine key={line.label} line={line} busy={busy} />
              ))}
            </Box>
          )}
          {chosen.action === 'revoke' && !signReady && (
            <Typography color="text.secondary" sx={{ mt: 0.75, fontSize: 11.5 }}>
              Signature impossible pour l’instant : la coupure se fait quand même et la ligne reste
              « Coupé, révocation à signer », avec la raison.
            </Typography>
          )}

          {gateOpen && (
            <Box sx={{ mt: 1.25 }}>
              <MotifChoice
                legend="Motif"
                choices={MOTIFS}
                value={motif}
                disabled={busy}
                onChoose={setMotif}
              />
              {motif && (
                <Paper component="section" aria-label="Confirmation" variant="outlined" sx={{ px: 1.5, py: 1 }}>
                  {chosen.action === 'revoke' && (
                    <Typography sx={{ mb: 1, fontSize: 12 }}>
                      {`Révoquer ${chosen.name} ? Le poste sera coupé tout de suite. C'est définitif.`}
                    </Typography>
                  )}
                  <Button
                    size="small"
                    variant="contained"
                    disabled={busy}
                    onClick={() => void send(chosen, motif)}
                    sx={{ minHeight: 30, fontSize: 12 }}
                  >
                    {chosen.action === 'resume' ? 'Reprendre' : 'Révoquer'}
                  </Button>
                </Paper>
              )}
            </Box>
          )}
          {error && (
            <Alert severity="error" variant="outlined" sx={{ mt: 1, fontSize: 11.5 }}>
              {error}
            </Alert>
          )}
        </Paper>
      )}
      {!chosen && error && (
        <Alert severity="error" variant="outlined" sx={{ mt: 1, fontSize: 11.5 }}>
          {error}
        </Alert>
      )}
    </>
  )
}
