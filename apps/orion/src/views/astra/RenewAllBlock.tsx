import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import Checkbox from '@mui/material/Checkbox'
import FormControlLabel from '@mui/material/FormControlLabel'
import Paper from '@mui/material/Paper'
import TextField from '@mui/material/TextField'
import Typography from '@mui/material/Typography'

import * as api from '../../api'
import { RULE } from '../../theme'
import type {
  CampaignScope,
  GatewayRenewTerms,
  OperatorOpened,
  OperatorStatus,
  RotationsOverview,
} from '../../types'
import { GATEWAY_LABELS } from './gatewayRows'
import { TERMS_DEFAULT, TermsFields, termsError } from './GatewayIdentityBlock'
import type { TermsDraft } from './GatewayIdentityBlock'
import { PLAN_STEPS, chainRow, stepBlocker } from './chainRow'
import type { ChainAction } from './chainRow'
import { liveOperation, prerequisites, rotationRows, valueOf } from './rotationRows'
import type { CeremonyHandoff, RotationStepContext } from './RotationsPanel'

const DEFAULT_REASON = 'Tout renouveler'
const FINISHED = 'Parc autorisé ; chaque poste se renouvelle à sa prochaine connexion.'
const CA_TLS_REMINDER = 'Rappel : Terminer la rotation CA TLS à son échéance.'
const ABANDON_KEEPS = 'Ce qui est déjà approuvé garde son effet.'
const STALE = 'Le plan a changé : relire la ligne.'
const LOST_REQUEST = "Demande de délégation perdue : rouvrir l'étape."
const NO_CEREMONY = 'Aucune cérémonie ouverte.'

const BUTTONS: Record<ChainAction, string> = {
  start: 'Commencer',
  resume_step: "Reprendre l'étape",
  continue: 'Continuer',
  reopen: "Rouvrir l'étape",
  finish: 'Terminer le plan',
  abandon: 'Abandonner le plan',
}

/** The actions that open a step whose ceremony needs more than a click: their body is drawn below the row. */
type BodyAction = 'resume_step' | 'continue' | 'reopen'

type Plan = { steps: CampaignScope[]; current: number; operation_id: string | null }

const nowSeconds = () => Math.floor(Date.now() / 1000)

const isEnded = (status: OperatorStatus) =>
  typeof status.gesture === 'string' && ['done', 'failed', 'cancelled'].includes(status.gesture)

/** The plan Astra holds; a read without one is stale for every gesture that needs it. */
function planOf(o: RotationsOverview): Plan {
  const plan = valueOf(o.authority)?.chain
  if (!plan || plan.current >= plan.steps.length) throw new Error(STALE)
  return plan
}

/** The step an action acts on: the one after the current for « Continuer », the current one otherwise. */
function stepOf(plan: Plan, action: BodyAction | 'finish'): CampaignScope | undefined {
  if (action === 'finish') return undefined
  return action === 'continue' ? plan.steps[plan.current + 1] : plan.steps[plan.current]
}

/** The renewal terms as the gateway's ceremony takes them; the key recovery is not offered here. */
const gatewayTerms = (draft: TermsDraft, rotateTls: boolean): GatewayRenewTerms => ({
  rotate_tls: rotateTls,
  key_recovery: false,
  prepare_days: Number(draft.prepare),
  overlap_days: Number(draft.overlap),
  validity_days: Number(draft.validity),
})

/** The rotation row's reason, without the campaign check: a resumption has one open by definition. */
function resumeBlocker(o: RotationsOverview, now: number): string | null {
  const row = rotationRows(o, now).find((candidate) => candidate.action === 'replace_ca_tls')
  return row?.disabledReason ?? prerequisites(o, 'replace_ca_tls').find((line) => !line.ok)?.label ?? null
}

/**
 * The « Tout renouveler » row of the Rotations tab: the plan Astra holds, and the gestures that
 * move it. Each gesture reads the overview first, checks what can be checked before Astra is
 * asked, and hands the ceremony of the step to the screen.
 */
export function RenewAllBlock({
  overview,
  onCeremony,
  refresh,
  renderStep,
  operatorLabel,
  fleetApprovedThisSession = null,
}: {
  overview: RotationsOverview
  onCeremony: CeremonyHandoff
  /** Reads the overview again; `null` when the read did not go through. */
  refresh: () => Promise<RotationsOverview | null>
  renderStep?: (context: RotationStepContext) => ReactNode
  /** The label of the first key, for `requested_by`. */
  operatorLabel: string
  /** The campaign whose fleet approval ended `done` in this session, kept by the screen. */
  fleetApprovedThisSession?: string | null
}) {
  const plan = valueOf(overview.authority)?.chain ?? null
  const planKey = plan ? `${plan.current}|${plan.operation_id}|${plan.steps.join(',')}` : ''
  const [held, setHeld] = useState<OperatorOpened | null>(null)
  const [running, setRunning] = useState(false)
  const [pick, setPick] = useState<ChainAction | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [invalid, setInvalid] = useState<string | null>(null)
  const [reason, setReason] = useState(DEFAULT_REASON)
  const [terms, setTerms] = useState<TermsDraft>(TERMS_DEFAULT)
  const [rotateTls, setRotateTls] = useState(false)

  // Read when the plan moves, and on mount: the request Orion holds, and whether a ceremony is open.
  useEffect(() => {
    let alive = true
    void (async () => {
      try {
        const found = await api.operatorChainHeld()
        if (alive) setHeld(found ?? null)
      } catch {
        if (alive) setHeld(null)
      }
      try {
        const status = await api.operatorCeremonyStatus()
        if (!alive) return
        setRunning(status !== null && !isEnded(status))
      } catch {
        // The last reading stands: the next read of the plan tries again.
      }
    })()
    return () => {
      alive = false
    }
  }, [planKey])

  const now = nowSeconds()
  const row = chainRow({ overview, now, held, fleetApprovedThisSession })
  const picked = pick && row.actions.includes(pick) ? pick : null

  const readFresh = async (): Promise<RotationsOverview> => {
    const fresh = await refresh()
    if (!fresh) throw new Error('Lecture impossible : relire plus tard.')
    return fresh
  }

  /** False, with its notice, while another ceremony is open. */
  const ceremonyFree = async (): Promise<boolean> => {
    const status = await api.operatorCeremonyStatus()
    if (status && !isEnded(status)) {
      setNotice('Cérémonie en cours')
      return false
    }
    return true
  }

  const gatewayCeremony = async (draft: TermsDraft, rotate: boolean) => {
    await api.beginGatewayCeremony({ gesture: 'renew', ...gatewayTerms(draft, rotate), in_chain: true })
    const status = await api.operatorCeremonyStatus()
    if (!status) throw new Error(NO_CEREMONY)
    onCeremony(status)
  }

  /** Hands over the ceremony of the step Astra just opened. */
  const openedCeremony = async (opened: OperatorOpened) => {
    if (opened.scope === 'issuer_delegation') {
      if (!opened.delegation_request) throw new Error('demande de délégation absente')
      onCeremony(
        await api.beginIssuerCeremony({
          gesture: 'authorize_issuer',
          operation_id: opened.operation_id,
          request: opened.delegation_request,
        }),
      )
    } else if (opened.scope === 'gateway_identity') {
      await gatewayCeremony(terms, rotateTls)
    } else if (opened.scope === 'fleet_leafs') {
      onCeremony(await api.beginOperatorCeremony({ kind: 'approve_campaign', operation_id: opened.operation_id }))
    } else {
      throw new Error(STALE)
    }
  }

  const finished = (fresh: RotationsOverview) => {
    setPick(null)
    setNotice(fresh.caTlsCloseAt !== null ? `${FINISHED} ${CA_TLS_REMINDER}` : FINISHED)
  }

  /** « Commencer » : the delegation's controls, then the chain, then the delegation's ceremony. */
  const start = async () => {
    const fresh = await readFresh()
    // The four steps, as the row read them to offer « Commencer »: a plan started over a step
    // that cannot run would stop there with the first campaign already spent.
    const at = nowSeconds()
    const blocker = PLAN_STEPS.map((scope) => stepBlocker(fresh, scope, at)).find((reason) => reason !== null)
    if (blocker) throw new Error(blocker)
    if (!(await ceremonyFree())) return
    await openedCeremony(await api.operatorChainStart(reason.trim() || DEFAULT_REASON, operatorLabel))
  }

  /** « Reprendre l'étape » on the operation Astra holds open: no call to next. */
  const resume = async (current: Plan) => {
    const scope = current.steps[current.current]
    if (scope === 'issuer_delegation') {
      const live = await api.operatorChainHeld()
      if (!live || live.operation_id !== current.operation_id || !live.delegation_request) {
        throw new Error(LOST_REQUEST)
      }
      onCeremony(
        await api.beginIssuerCeremony({
          gesture: 'authorize_issuer',
          operation_id: live.operation_id,
          request: live.delegation_request,
        }),
      )
    } else if (scope === 'gateway_identity') {
      await gatewayCeremony(terms, rotateTls)
    } else if (scope === 'fleet_leafs' && current.operation_id) {
      onCeremony(
        await api.beginOperatorCeremony({ kind: 'approve_campaign', operation_id: current.operation_id }),
      )
    } else if (scope !== 'trust_authorities') {
      throw new Error(STALE)
    }
  }

  /** « Continuer », « Rouvrir l'étape », « Terminer le plan » on the step's closed campaign. */
  const advance = async (action: 'continue' | 'reopen' | 'finish') => {
    const fresh = await readFresh()
    const current = planOf(fresh)
    // The row offered « Terminer le plan » on an older read: closing a plan whose last campaign
    // is open would leave it unapproved, so the fresh row decides, and is shown.
    if (action === 'finish') {
      const offered = chainRow({ overview: fresh, now: nowSeconds(), held, fleetApprovedThisSession })
      if (!offered.actions.includes('finish')) return
    }
    if (!(await ceremonyFree())) return
    const scope = stepOf(current, action)
    if (scope === 'trust_authorities') return // The CA TLS step is led by its own ceremony.
    if (scope) {
      const blocker = stepBlocker(fresh, scope, nowSeconds())
      if (blocker) throw new Error(blocker)
      if (scope === 'gateway_identity') {
        await api.operatorGatewayCheckRenewal(gatewayTerms(terms, rotateTls))
      }
    }
    if (action === 'reopen') {
      await openedCeremony(await api.operatorChainReopen(current.current))
      return
    }
    // Astra opens the next step here, or finishes the plan when there is none.
    const outcome = await api.operatorChainNext(current.current)
    if (outcome.outcome === 'finished') {
      finished(fresh)
      return
    }
    await openedCeremony(outcome)
  }

  const run = (action: BodyAction | 'finish' | 'start') => {
    setBusy(true)
    setError(null)
    setNotice(null)
    setInvalid(null)
    const job =
      action === 'start'
        ? start()
        : action === 'resume_step'
          ? readFresh().then((fresh) => resume(planOf(fresh)))
          : advance(action)
    job
      .catch((cause: unknown) => setError(cause instanceof Error ? cause.message : String(cause)))
      .finally(() => setBusy(false))
  }

  const abandon = async () => {
    setBusy(true)
    setError(null)
    try {
      await api.operatorChainAbandon()
      setPick(null)
      await refresh()
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause))
    } finally {
      setBusy(false)
    }
  }

  /** The row's button: a step that needs its body opens it; the others run at once. */
  const choose = (action: ChainAction) => {
    setError(null)
    setNotice(null)
    setInvalid(null)
    if (action === 'abandon') {
      setPick((current) => (current === 'abandon' ? null : 'abandon'))
      return
    }
    if (action === 'start' || action === 'finish') {
      setPick(null)
      run(action)
      return
    }
    const scope = plan ? stepOf(plan, action) : undefined
    if (scope === 'gateway_identity' || scope === 'trust_authorities') {
      setPick((current) => (current === action ? null : action))
      return
    }
    setPick(null)
    run(action)
  }

  // The CA TLS step: its prerequisites first, then the step's own ceremony, whose approval takes
  // the chain's step itself (`chainStep`), once Orion's own checks have passed.
  const caTlsBody = (action: BodyAction) => {
    const blocker =
      action === 'resume_step'
        ? resumeBlocker(overview, now)
        : stepBlocker(overview, 'trust_authorities', now)
    if (blocker) return <Typography sx={{ fontSize: 11.5, color: 'text.secondary' }}>{blocker}</Typography>
    if (!renderStep) return null
    const chainStep =
      action === 'resume_step' || !plan ? undefined : { reopen: action === 'reopen', expected_step: plan.current }
    return renderStep({
      action: 'replace_ca_tls',
      overview,
      existingOperation: action === 'resume_step' ? liveOperation(overview, 'replace_ca_tls', now) : null,
      operatorLabel,
      onCeremony: (status, existingOperation) => onCeremony(status, existingOperation, chainStep),
      refresh,
    })
  }

  const gatewayBody = (action: BodyAction) => (
    <Box sx={{ mt: 1 }}>
      <FormControlLabel
        control={
          <Checkbox
            checked={rotateTls}
            disabled={busy}
            onChange={(event) => setRotateTls(event.target.checked)}
          />
        }
        label="Remplacer aussi la feuille TLS"
      />
      <TermsFields terms={terms} onChange={setTerms} disabled={busy} />
      {invalid && (
        <Alert severity="warning" variant="outlined" sx={{ mb: 1, fontSize: 11.5 }}>
          {invalid}
        </Alert>
      )}
      <Button
        size="small"
        variant="contained"
        disabled={busy || running}
        onClick={() => {
          const wrong = termsError(terms)
          setInvalid(wrong)
          if (!wrong) run(action)
        }}
        sx={{ minHeight: 30, fontSize: 12 }}
      >
        {GATEWAY_LABELS.renew}
      </Button>
    </Box>
  )

  let body: ReactNode = null
  if (picked === 'abandon') {
    body = (
      <Paper component="section" aria-label="Confirmation" variant="outlined" sx={{ mt: 1.25, px: 1.5, py: 1 }}>
        <Typography sx={{ mb: 0.75, fontSize: 12 }}>{ABANDON_KEEPS}</Typography>
        <Button
          size="small"
          variant="contained"
          disabled={busy}
          onClick={() => void abandon()}
          sx={{ minHeight: 30, fontSize: 12 }}
        >
          Confirmer l'abandon du plan
        </Button>
      </Paper>
    )
  } else if (picked && plan) {
    const scope = stepOf(plan, picked as BodyAction)
    body = (
      <Box sx={{ mt: 1.25 }}>
        {scope === 'gateway_identity' ? gatewayBody(picked as BodyAction) : caTlsBody(picked as BodyAction)}
      </Box>
    )
  }

  return (
    <Paper
      component="section"
      aria-label={row.title}
      variant="outlined"
      sx={{ mb: 1, px: 1.5, py: 1.25, borderColor: RULE, bgcolor: 'background.paper' }}
    >
      <Typography sx={{ fontSize: 13, fontWeight: 700 }}>{row.title}</Typography>
      <Typography sx={{ fontSize: 11.5 }}>{row.state}</Typography>
      {row.detail && (
        <Typography color="text.secondary" sx={{ fontSize: 11, overflowWrap: 'anywhere' }}>
          {row.detail}
        </Typography>
      )}
      {row.actions.includes('start') && (
        <Box sx={{ mt: 1 }}>
          <TextField
            label="Motif"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            size="small"
            fullWidth
            disabled={busy || running}
            sx={{ mb: 1 }}
          />
          {row.disabledReason && (
            <Typography color="text.secondary" sx={{ mb: 0.75, fontSize: 11.5 }}>
              {row.disabledReason}
            </Typography>
          )}
          <Button
            size="small"
            variant="contained"
            disabled={busy || running || row.disabledReason !== null}
            onClick={() => run('start')}
            sx={{ minHeight: 28, fontSize: 12 }}
          >
            {BUTTONS.start}
          </Button>
        </Box>
      )}
      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.75, mt: 0.75 }}>
        {row.actions
          .filter((action) => action !== 'start')
          .map((action) => (
            <Button
              key={action}
              size="small"
              variant="outlined"
              disabled={busy || running}
              aria-expanded={picked === action}
              onClick={() => choose(action)}
              sx={{ minHeight: 28, fontSize: 12 }}
            >
              {BUTTONS[action]}
            </Button>
          ))}
      </Box>
      {body}
      {notice && (
        <Alert severity="info" variant="outlined" sx={{ mt: 1, fontSize: 11.5 }}>
          {notice}
        </Alert>
      )}
      {error && (
        <Alert
          severity="error"
          variant="outlined"
          sx={{ mt: 1, fontSize: 11.5 }}
          action={
            <Button size="small" disabled={busy} onClick={() => void refresh()} sx={{ fontSize: 11.5 }}>
              Relire plus tard
            </Button>
          }
        >
          {error}
        </Alert>
      )}
    </Paper>
  )
}
