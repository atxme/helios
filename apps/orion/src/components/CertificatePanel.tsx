import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { AlertTriangle } from 'lucide-react'

import { CopyButton } from './CopyButton'
import type {
  CertificateAction,
  CertificateActionState,
  CertificateFacts,
  CertificateInventory,
  CertificatePhase,
} from '../types'

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
 * # The answer before the evidence
 *
 * A row used to be four monospace fragments on one baseline — an uppercase
 * label, a phase, a date, sixteen hex characters — all at the same weight and
 * all under 11 px. Reading it meant parsing it. What replaces it puts the
 * verdict first, as a tinted pill of the same shape as the shell's posture
 * chip, then *how long* — the value the user came for, since «expire dans
 * 4 jours» is what makes someone act and «jusqu'au 19 août 2026» is what makes
 * them compute. The absolute instant stays beside it, quieter; the subject,
 * the issuer and the fingerprint go to the hover and the copy button, because
 * they are what one reads out to an operator, not what one scans.
 *
 * Rows are grouped by *whose* certificate it is. «gateway CA TLS» and «ce
 * poste TLS» differ by two words in the middle of a monospace string; under
 * two headings they differ by which block they sit in.
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
  /** Worst-first ordering, so a card can carry the state of its worst row. */
  severity: number
}

const PHASE: Record<CertificatePhase, PhaseSkin> = {
  not_yet_valid: {
    label: 'pas encore valide',
    color: AHEAD,
    hint: 'Préparé pour plus tard : sa validité n’a pas commencé. Une rotation en cours a cette allure.',
    alarming: false,
    severity: 1,
  },
  valid: {
    label: 'valide',
    color: CALM,
    hint: 'Dans sa période de validité, avant les 80 % qui ouvrent le renouvellement.',
    alarming: false,
    severity: 0,
  },
  renewal_due: {
    label: 'renouvellement ouvert',
    color: DUE,
    hint: 'Passé 80 % de sa durée de vie : c’est la fenêtre où le renouvellement doit avoir lieu.',
    alarming: true,
    severity: 2,
  },
  warning: {
    label: 'renouvellement en retard',
    color: DUE,
    hint: 'Passé 90 % de sa durée de vie. Le renouvellement aurait dû aboutir.',
    alarming: true,
    severity: 3,
  },
  critical: {
    label: 'expiration imminente',
    color: LATE,
    hint: 'Passé 95 % de sa durée de vie. À l’échéance, la connexion échouera avant WireGuard.',
    alarming: true,
    severity: 4,
  },
  expired: {
    label: 'expiré',
    color: LATE,
    hint: 'Hors validité : la connexion échoue avant WireGuard.',
    alarming: true,
    severity: 5,
  },
}

/**
 * The state of the worst certificate an inventory holds, or `null` if it holds
 * none.
 *
 * Exported so the card that carries a profile's name carries its verdict too:
 * a screen listing several profiles must be answerable without opening each
 * one, and «expiré» on the card is that answer.
 */
export function worstPhase(inventory: CertificateInventory | null): CertificatePhase | null {
  if (!inventory) return null
  const phases = [
    inventory.gateway_pq,
    inventory.gateway_ca_tls,
    inventory.client_tls,
    inventory.client_pq,
  ]
    .filter((facts): facts is CertificateFacts => Boolean(facts))
    .map((facts) => facts.phase)
  if (phases.length === 0) return null
  return phases.reduce((worst, phase) =>
    PHASE[phase].severity > PHASE[worst].severity ? phase : worst,
  )
}

/** Whether a phase is one the user has to do something about. */
export function isAlarming(phase: CertificatePhase): boolean {
  return PHASE[phase].alarming
}

/** Date in the machine's locale, to the minute. Seconds say nothing here. */
function instant(seconds: number): string {
  return new Date(seconds * 1000).toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  })
}

const HOUR = 3600
const DAY = 24 * HOUR

/**
 * How far an instant is, in the coarsest unit that still says something.
 *
 * A certificate's remaining life is what decides whether the user acts today
 * or forgets the screen; a date alone makes them do the subtraction, and doing
 * it wrong is the whole failure this panel exists to prevent.
 */
function distance(seconds: number, now: number): string {
  const delta = Math.abs(seconds - now)
  if (delta >= 730 * DAY) return `${Math.round(delta / (365.25 * DAY))} ans`
  if (delta >= 2 * DAY) return `${Math.round(delta / DAY)} jours`
  if (delta >= 2 * HOUR) return `${Math.round(delta / HOUR)} heures`
  return `${Math.max(1, Math.round(delta / 60))} minutes`
}

/** «dans 42 jours» while it lasts, «depuis 3 jours» once it is over. */
function deadline(notAfter: number, now: number): string {
  return notAfter >= now ? `dans ${distance(notAfter, now)}` : `depuis ${distance(notAfter, now)}`
}

export function CertificatePanel({
  inventory,
  identityName,
  actions = [],
  lastError = null,
  onRun,
}: {
  inventory: CertificateInventory | null
  /** Name of the protected identity the profile asks for, if any. */
  identityName: string
  /** The four actions of spec §12.2 and their state, decided in Rust. */
  actions?: CertificateActionState[]
  /** Last action result on this profile — §12.2 asks for it. */
  lastError?: string | null
  onRun?: (action: CertificateAction) => void
}) {
  if (!inventory) return null

  interface Group {
    owner: string
    rows: Array<{ label: string; facts: CertificateFacts | null }>
  }
  const groups: Group[] = [
    {
      owner: 'Gateway',
      rows: [
        { label: 'signature PQ', facts: inventory.gateway_pq },
        { label: 'autorité TLS', facts: inventory.gateway_ca_tls },
      ],
    },
    {
      owner: 'Ce poste',
      rows: [
        { label: 'TLS', facts: inventory.client_tls },
        { label: 'signature PQ', facts: inventory.client_pq },
      ],
    },
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
  const anything =
    groups.some((group) => group.rows.some((row) => row.facts)) ||
    inventory.faults.length > 0 ||
    clientMissing ||
    actions.length > 0
  if (!anything) return null

  // §12.2 asks for the chosen renewal date. It is the client leaf's own
  // instant: the gateway leaf rotates on the operator's schedule, this one on
  // this machine's.
  const renewal = inventory.client_pq ?? inventory.client_tls
  const now = Date.now() / 1000

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.25, mt: 1 }}>
      {groups.map((group) => (
        <Box key={group.owner} sx={{ display: 'flex', flexDirection: 'column', gap: 0.25 }}>
          <Typography variant="overline" color="text.disabled">
            {group.owner}
          </Typography>
          {group.rows.map((row) => (
            <CertificateRow
              key={`${group.owner} ${row.label}`}
              label={row.label}
              copyLabel={`l’empreinte ${group.owner.toLowerCase()} ${row.label}`}
              facts={row.facts}
              now={now}
            />
          ))}
        </Box>
      ))}

      {renewal && (
        <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 1, minWidth: 0 }}>
          <Typography color="text.secondary" sx={{ width: 110, flexShrink: 0, fontSize: 11.5 }}>
            renouvellement
          </Typography>
          <Typography color="text.primary" sx={{ fontSize: 11.5, fontWeight: 600 }}>
            {deadline(renewal.renewal_at, now)}
          </Typography>
          <Typography noWrap color="text.disabled" sx={{ minWidth: 0, fontSize: 11 }}>
            {instant(renewal.renewal_at)}
          </Typography>
        </Box>
      )}

      {inventory.previous_identity?.phase === 'available' && (
        <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 1, minWidth: 0 }}>
          <Typography color="text.secondary" sx={{ width: 110, flexShrink: 0, fontSize: 11.5 }}>
            retour temporaire
          </Typography>
          <Typography color="text.primary" sx={{ fontSize: 11.5, fontWeight: 600 }}>
            {inventory.previous_identity.selected ? 'ancienne identité servie' : 'disponible'}
          </Typography>
          <Typography noWrap color="text.disabled" sx={{ minWidth: 0, fontSize: 11 }}>
            jusqu’au {instant(inventory.previous_identity.available_until)}
          </Typography>
        </Box>
      )}

      {clientMissing && (
        <Fault>
          Aucune identité protégée nommée <strong>{identityName}</strong> scellée sur ce poste.
        </Fault>
      )}
      {inventory.faults.map((fault) => (
        <Fault key={fault}>{fault}</Fault>
      ))}

      {/* The last attempt's result. A 403 while the active PQ leaf is still
          valid is a policy answer («not due»), not a broken renewal. Keep
          that distinction visible without asking the gateway to disclose the
          protected Astra reason over the tunnel. */}
      {lastError && (
        <RenewalResult message={lastError} inventory={inventory} />
      )}

      {actions.length > 0 && (
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.75 }}>
          {actions.map((state) => (
            <ActionButton key={state.action} state={state} onRun={onRun} />
          ))}
        </Box>
      )}
    </Box>
  )
}

/**
 * Presents the bounded refusal the gateway is allowed to return.
 *
 * Astra deliberately collapses its protected reasons to HTTP 403. Orion can
 * still make the one safe distinction it owns: a current client PQ leaf means
 * the ordinary renewal window has not opened yet. This is deliberately
 * conservative; every other 403 remains an error instead of being guessed at
 * as `not_due`.
 */
function RenewalResult({
  message,
  inventory,
}: {
  message: string
  inventory: CertificateInventory
}) {
  const notDue = /\b403\b/.test(message) && inventory.client_pq?.phase === 'valid'
  return (
    <Alert severity={notDue ? 'info' : 'error'} variant="outlined" sx={{ py: 0, fontSize: 11 }}>
      {notDue
        ? 'Renouvellement non nécessaire pour le moment : le certificat client est encore valide et la protection de la gateway bloque la rotation avant sa fenêtre.'
        : message}
    </Alert>
  )
}

/**
 * One of the four actions, with the reason it cannot run on hover.
 *
 * Disabled and explained, never hidden. §12.2 lists the four by name, and an
 * action that disappears when unavailable teaches the user it does not exist —
 * so the day it becomes available, nobody looks for it.
 *
 * Outlined and wrapped in a row rather than stacked as four full-width text
 * buttons: disabled text buttons read as grey sentences, so the user could not
 * tell there were buttons there at all — and four of them stacked cost more
 * height than the certificates they act on.
 *
 * The label is the shell's. §12.2 forbids putting a global action behind an
 * ambiguous «Renouveler», and the one place that rule can be enforced is where
 * the labels are defined.
 */
function ActionButton({
  state,
  onRun,
}: {
  state: CertificateActionState
  onRun?: (action: CertificateAction) => void
}) {
  const blocked = state.blocked_by !== null
  const button = (
    <span>
      <Button
        size="small"
        variant="outlined"
        color={blocked ? 'inherit' : 'primary'}
        disabled={blocked || !onRun}
        onClick={() => onRun?.(state.action)}
        sx={{
          minHeight: 30,
          px: 1.25,
          fontSize: 11,
          fontWeight: 550,
          textTransform: 'none',
          borderColor: 'divider',
          color: blocked ? 'text.disabled' : undefined,
        }}
      >
        {state.label}
      </Button>
    </span>
  )
  return state.message ? (
    <Tooltip describeChild title={state.message}>
      {button}
    </Tooltip>
  ) : (
    button
  )
}

/**
 * The verdict, as a tinted pill.
 *
 * Same shape as the shell's posture chip on purpose: Orion already teaches
 * that a rounded tinted capsule is «l'état de cette chose», and a second
 * vocabulary for the same idea would have to be learned twice.
 */
export function PhasePill({ phase, dense = false }: { phase: CertificatePhase; dense?: boolean }) {
  const skin = PHASE[phase]
  return (
    <Tooltip describeChild title={skin.hint}>
      <Box
        sx={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 0.6,
          flexShrink: 0,
          px: 0.9,
          py: 0.2,
          borderRadius: 5,
          border: `1px solid ${skin.color}33`,
          bgcolor: `${skin.color}14`,
        }}
      >
        <Box
          aria-hidden
          sx={{ width: 6, height: 6, borderRadius: '50%', flexShrink: 0, bgcolor: skin.color }}
        />
        <Typography
          noWrap
          sx={{ color: skin.color, fontSize: dense ? 10.5 : 11, fontWeight: 650 }}
        >
          {skin.label}
        </Typography>
      </Box>
    </Tooltip>
  )
}

function CertificateRow({
  label,
  copyLabel,
  facts,
  now,
}: {
  label: string
  copyLabel: string
  facts: CertificateFacts | null
  now: number
}) {
  return (
    <Box
      sx={{
        display: 'grid',
        gridTemplateColumns: '110px minmax(0, auto) 1fr auto',
        alignItems: 'center',
        gap: 1,
        minHeight: 26,
        minWidth: 0,
      }}
    >
      <Typography noWrap color="text.secondary" sx={{ fontSize: 11.5 }}>
        {label}
      </Typography>

      {!facts ? (
        <Typography color="text.disabled" sx={{ gridColumn: '2 / -1', fontSize: 11.5 }}>
          absent
        </Typography>
      ) : (
        <>
          <PhasePill phase={facts.phase} />
          <Box sx={{ display: 'flex', alignItems: 'baseline', gap: 1, minWidth: 0 }}>
            <Typography
              noWrap
              sx={{
                flexShrink: 0,
                fontSize: 11.5,
                fontWeight: 600,
                color: PHASE[facts.phase].alarming ? PHASE[facts.phase].color : 'text.primary',
              }}
            >
              {deadline(facts.not_after, now)}
            </Typography>
            {/* The subject is what tells two profiles of one fleet apart, and
                the fingerprint is what one reads out to the operator. Both are
                on hover: the row states the fact, the identity is the detail. */}
            <Tooltip
              describeChild
              title={`${facts.subject} — émis par ${facts.issuer}. Empreinte ${facts.fingerprint}.`}
            >
              <Typography noWrap color="text.disabled" sx={{ minWidth: 0, fontSize: 11 }}>
                {instant(facts.not_after)}
              </Typography>
            </Tooltip>
          </Box>
          <CopyButton value={facts.fingerprint} label={copyLabel} />
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
