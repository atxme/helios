import Box from '@mui/material/Box'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { AlertTriangle } from 'lucide-react'

import { CopyButton } from './CopyButton'
import type { CertificateFacts, CertificateInventory, CertificatePhase } from '../types'

/**
 * The four certificates a connection depends on, with their dates.
 *
 * # What this answers, and what it deliberately does not
 *
 * A user with a profile that stops connecting has one question: *is something
 * expired?* Until now Orion could not answer it. The negotiation block showed
 * a fingerprint and two «présent / absent» words, so an expired gateway leaf
 * and a wrong endpoint produced the same screen — and the same failure, right
 * before WireGuard, with nothing to look at.
 *
 * So this states dates, and the renewal ladder the protocol itself uses: 80 %
 * of the lifetime opens the window, 90 % warns, 95 % is critical. Those
 * thresholds are computed in Rust by `ValidityPeriod`, the same type the
 * gateway planner reads. A panel with thresholds of its own would eventually
 * contradict the thing that decides.
 *
 * It reports and does not act. Renewal is still the operator re-issuing and
 * the user re-importing: Orion holds no trust store yet, so there is no
 * «Renouveler» button here, because there is nothing behind one.
 *
 * # Values, no captions
 *
 * Each row is a name, an instant and a state. What a phase means is on hover,
 * where someone who wonders will look, and nowhere else.
 */

/** Tints, matching the state palette: readable on the paper background. */
const CALM = '#5A6B65'
const DUE = '#A16207'
const LATE = '#9B2C2C'
const AHEAD = '#2F5D8A'

interface PhaseSkin {
  label: string
  color: string
  /** What the phase means. Hover only. */
  hint: string
  alarming: boolean
}

const PHASE: Record<CertificatePhase, PhaseSkin> = {
  not_yet_valid: {
    label: 'pas encore valide',
    color: AHEAD,
    hint: 'Préparé pour plus tard : sa validité n’a pas commencé. Une rotation en cours a cette allure.',
    alarming: false,
  },
  valid: {
    label: 'valide',
    color: CALM,
    hint: 'Dans sa période de validité, avant les 80 % qui ouvrent le renouvellement.',
    alarming: false,
  },
  renewal_due: {
    label: 'renouvellement ouvert',
    color: DUE,
    hint: 'Passé 80 % de sa durée de vie : c’est la fenêtre où le renouvellement doit avoir lieu.',
    alarming: true,
  },
  warning: {
    label: 'renouvellement en retard',
    color: DUE,
    hint: 'Passé 90 % de sa durée de vie. Le renouvellement aurait dû aboutir.',
    alarming: true,
  },
  critical: {
    label: 'expiration imminente',
    color: LATE,
    hint: 'Passé 95 % de sa durée de vie. À l’échéance, la connexion échouera avant WireGuard.',
    alarming: true,
  },
  expired: {
    label: 'expiré',
    color: LATE,
    hint: 'Hors validité : la connexion échoue avant WireGuard.',
    alarming: true,
  },
}

/** Date in the machine's locale, to the minute. Seconds say nothing here. */
function instant(seconds: number): string {
  return new Date(seconds * 1000).toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  })
}

export function CertificatePanel({
  inventory,
  identityName,
}: {
  inventory: CertificateInventory | null
  /** Name of the protected identity the profile asks for, if any. */
  identityName: string
}) {
  if (!inventory) return null

  const rows: Array<{ label: string; facts: CertificateFacts | null }> = [
    { label: 'gateway PQ', facts: inventory.gateway_pq },
    { label: 'gateway CA TLS', facts: inventory.gateway_ca_tls },
    { label: 'ce poste TLS', facts: inventory.client_tls },
    { label: 'ce poste PQ', facts: inventory.client_pq },
  ]
  // The client half is missing for a reason the machine knows: either the
  // profile names no identity, or it names one this machine has not sealed.
  // Saying which is what turns "deux lignes vides" into an action.
  const clientMissing =
    !inventory.client_tls &&
    !inventory.client_pq &&
    identityName.trim() !== '' &&
    !inventory.identity_sealed

  // Counted **with** the missing identity, and that is the point: a profile
  // that pins nothing readable and names an unsealed identity is exactly the
  // one the message exists for. Rendering nothing there would leave the user
  // with the failure and no cause.
  const anything = rows.some((row) => row.facts) || inventory.faults.length > 0 || clientMissing
  if (!anything) return null

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.75, mt: 0.5 }}>
      {rows.map(({ label, facts }) => (
        <CertificateRow key={label} label={label} facts={facts} />
      ))}

      {clientMissing && (
        <Fault>
          Aucune identité protégée nommée <strong>{identityName}</strong> scellée sur ce poste.
        </Fault>
      )}
      {inventory.faults.map((fault) => (
        <Fault key={fault}>{fault}</Fault>
      ))}
    </Box>
  )
}

function CertificateRow({ label, facts }: { label: string; facts: CertificateFacts | null }) {
  const skin = facts ? PHASE[facts.phase] : null

  return (
    <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 0.75, minWidth: 0 }}>
      <Typography
        color="text.disabled"
        sx={{
          width: 104,
          flexShrink: 0,
          fontFamily: 'monospace',
          fontSize: 9.5,
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
        }}
      >
        {label}
      </Typography>

      {!facts || !skin ? (
        <Typography
          color="text.disabled"
          sx={{ fontFamily: 'monospace', fontSize: 10.5 }}
        >
          absent
        </Typography>
      ) : (
        <>
          <Tooltip
            describeChild
            title={`${skin.hint} Ouverture du renouvellement : ${instant(facts.renewal_at)}.`}
          >
            <Typography
              sx={{ flexShrink: 0, color: skin.color, fontFamily: 'monospace', fontSize: 10.5 }}
            >
              {skin.label}
            </Typography>
          </Tooltip>
          {skin.alarming && (
            <AlertTriangle
              size={12}
              aria-hidden
              style={{ color: skin.color, flexShrink: 0, alignSelf: 'center' }}
            />
          )}
          <Typography
            noWrap
            color="text.secondary"
            sx={{ minWidth: 0, fontFamily: 'monospace', fontSize: 10.5 }}
          >
            {`jusqu’au ${instant(facts.not_after)}`}
          </Typography>
          {/* The subject is what tells two profiles of one fleet apart, and
              the fingerprint is what one reads out to the operator. Both are
              on hover: the row states the fact, the identity is the detail. */}
          <Tooltip describeChild title={`${facts.subject} — émis par ${facts.issuer}`}>
            <Typography
              noWrap
              color="text.disabled"
              sx={{ minWidth: 0, fontFamily: 'monospace', fontSize: 10 }}
            >
              {facts.fingerprint.slice(0, 16)}
            </Typography>
          </Tooltip>
          <Box sx={{ ml: 'auto', flexShrink: 0 }}>
            <CopyButton value={facts.fingerprint} label={`l’empreinte ${label}`} />
          </Box>
        </>
      )}
    </Box>
  )
}

/** A slot that exists and could not be read. Never an absence. */
function Fault({ children }: { children: React.ReactNode }) {
  return (
    <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 0.75 }}>
      <AlertTriangle
        size={13}
        aria-hidden
        style={{ color: LATE, flexShrink: 0, marginTop: 2 }}
      />
      <Typography color="error" sx={{ fontSize: 11, lineHeight: 1.5 }}>
        {children}
      </Typography>
    </Box>
  )
}
