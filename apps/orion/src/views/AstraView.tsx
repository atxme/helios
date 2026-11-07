import type { ReactNode } from 'react'
import { useCallback, useEffect, useRef, useState } from 'react'
import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import ButtonBase from '@mui/material/ButtonBase'
import Typography from '@mui/material/Typography'

import * as api from '../api'
import { OperatorCeremonyPanel } from './OperatorCeremony'
import { DomainCreated } from './astra/DomainCreated'
import { DomainPanel } from './astra/DomainPanel'
import { ApprovalsPanel } from './astra/ApprovalsPanel'
import { RotationsPanel } from './astra/RotationsPanel'
import { ArtifactDownloads } from './astra/ArtifactDownloads'
import { EnrollmentOperatorPanel } from './astra/EnrollmentOperatorPanel'
import { VaultPanel } from './astra/VaultPanel'
import { GUTTER, MINT, PINE, RULE } from '../theme'
import type {
  OperatorPendingOperation,
  OperatorStatus,
  RotationsOverview,
} from '../types'

/** Under the files of a bootstrap that failed after its leaf was written. */
const BOOTSTRAP_LEAF_KEPT =
  'La feuille est émise et enregistrée à côté du coffre ; « Finaliser le domaine » reprend ce qui manque.'

const TABS = [
  'Enrôlement',
  'Coffre et clés',
  'Domaine',
  'Approbations',
  'Rotations',
  'Gateways',
] as const
type AstraTab = (typeof TABS)[number]

function WaitingNote({ children }: { children: string }) {
  return (
    <Alert severity="info" variant="outlined" sx={{ fontSize: 11.5 }}>
      {children}
    </Alert>
  )
}

/** Operator surface for the two distinct credentials required by ADR-008 §7.6. */
export function AstraView({
  onRecoveryReady,
  localRecoveryId = null,
}: {
  /** Resumes the client-owned half once Astra has released the recovery grant. */
  onRecoveryReady?: (operationId: string) => Promise<void>
  /** The one recovery opened from this machine's Certificats screen; any other is remote. */
  localRecoveryId?: string | null
} = {}) {
  const [error, setError] = useState<string | null>(null)
  // A protocol-2 ceremony, when one is open. It can outlive this view — the
  // helper keeps working while the operator looks at another tab — so it is
  // read on mount rather than only created here.
  const [ceremony, setCeremony] = useState<OperatorStatus | null>(null)
  const [pending, setPending] = useState<OperatorPendingOperation[]>([])
  // What the Rotations read says outside its own tab: `null` until the authority has been
  // read, which keeps every approval suspended rather than assuming there is no overlap.
  const [caPqOverlap, setCaPqOverlap] = useState<boolean | null>(null)
  const [journal, setJournal] = useState<RotationsOverview['journal']>(null)
  const [tab, setTab] = useState<AstraTab>('Enrôlement')
  const [finishingRecovery, setFinishingRecovery] = useState(false)
  const recoveryAttempt = useRef<string | null>(null)

  const readRotations = useCallback(async (cancelled: () => boolean = () => false) => {
    try {
      const found = await api.operatorRotationsOverview()
      if (cancelled()) return
      setCaPqOverlap(found.caPqOverlap)
      setJournal(found.journal)
    } catch {
      // Unread stays unread: approvals remain suspended.
    }
  }, [])

  const takeOverview = useCallback((found: RotationsOverview) => {
    setCaPqOverlap(found.caPqOverlap)
    setJournal(found.journal)
    if (found.pending.state === 'ok') setPending(found.pending.value)
  }, [])

  const finishRecovery = useCallback(
    (operationId: string, attempt: string, force = false) => {
      if (!onRecoveryReady || (!force && recoveryAttempt.current === attempt)) return
      recoveryAttempt.current = attempt
      setFinishingRecovery(true)
      setError(null)
      void onRecoveryReady(operationId)
        .catch((cause) => setError(String(cause)))
        .finally(() => setFinishingRecovery(false))
    },
    [onRecoveryReady],
  )

  useEffect(() => {
    let cancelled = false
    void api
      .operatorCeremonyStatus()
      .then((found) => {
        if (!cancelled) setCeremony(found)
      })
      .catch(() => {})
    void api
      .operatorPendingOperations()
      .then((found) => {
        if (!cancelled) setPending(found)
      })
      .catch(() => {})
    // One read at mount; the Rotations tab polls the same overview while it is shown.
    void readRotations(() => cancelled)
    return () => {
      cancelled = true
    }
  }, [readRotations])

  // The command returns the first state after a press (usually
  // `processing_key`). The helper then continues on its own while Windows
  // owns the modal WebAuthn dialog, so later states must be observed here.
  // Without this poll a two-key campaign never displays its second prompt.
  useEffect(() => {
    if (!ceremony) return
    const terminal =
      typeof ceremony.gesture === 'string' &&
      ['done', 'failed', 'cancelled'].includes(ceremony.gesture)
    if (terminal) return
    const timer = window.setTimeout(() => {
      void api
        .operatorCeremonyStatus()
        .then((found) => {
          if (found && found.revision >= ceremony.revision) setCeremony(found)
        })
        .catch((cause) => setError(String(cause)))
    }, 350)
    return () => window.clearTimeout(timer)
  }, [ceremony])

  // The helper owns the operator half only. Once it has released the grant,
  // Orion must immediately resume the client session it kept in Rust: that
  // installs the candidate and relays the signed commit to the gateway. The
  // old screen lost this hand-off when switching tabs and forced a second
  // press on « Récupérer ».
  useEffect(() => {
    if (
      !onRecoveryReady ||
      ceremony?.operation !== 'recover_identity' ||
      ceremony.gesture !== 'done' ||
      !ceremony.operation_id ||
      ceremony.operation_id !== localRecoveryId
    ) {
      return
    }
    const attempt = `${ceremony.session_id}:${ceremony.operation_id}`
    finishRecovery(ceremony.operation_id, attempt)
  }, [ceremony, finishRecovery, onRecoveryReady, localRecoveryId])

  const dismissCeremony = async () => {
    setError(null)
    try {
      await api.dismissOperatorCeremony()
      setCeremony(null)
      setPending(await api.operatorPendingOperations())
      void readRotations()
    } catch (cause) {
      setError(String(cause))
    }
  }

  const openCeremony = (next: OperatorStatus) => setCeremony(next)

  // A live protocol-2 ceremony owns the tab entirely. It is not a section
  // beside the CA-TLS form: an operator holding a security key must not be
  // shown, in the same view, a second ceremony they could start by mistake.
  if (ceremony) {
    const inCampaign =
      ceremony.manifest?.operation === 'issuer_authorization' && ceremony.manifest.campaign != null
    return (
      <Box sx={{ height: '100%', overflowY: 'auto', px: GUTTER, py: 1.5 }}>
        <Typography component="h2" sx={{ fontSize: 13, fontWeight: 700, mb: 0.5 }}>
          Astra
        </Typography>
        <Typography color="text.secondary" sx={{ fontSize: 11.5, lineHeight: 1.55, mb: 1.5 }}>
          Une opération attend l’opérateur.
        </Typography>
        <OperatorCeremonyPanel
          status={ceremony}
          onStatus={setCeremony}
          onDismiss={() => void dismissCeremony()}
          journal={journal}
        />
        {(ceremony.operation === 'invite_enrollment' ||
          ceremony.operation === 'accept_enrollment' ||
          ceremony.operation === 'finalize_domain' ||
          ceremony.operation === 'issue_gateway_bootstrap') && (
          <ArtifactDownloads
            gesture={ceremony.gesture}
            failedNote={
              ceremony.operation === 'issue_gateway_bootstrap' ? BOOTSTRAP_LEAF_KEPT : undefined
            }
          />
        )}
        {ceremony.operation === 'issue_gateway_bootstrap' && ceremony.gesture === 'done' && (
          <Typography color="text.secondary" sx={{ mt: 1, fontSize: 11.5 }}>
            Portez la feuille sur la gateway : elle s’installe à son amorçage (voir
            DEPLOIEMENT-ASTRA).
          </Typography>
        )}
        {ceremony.operation === 'recover_identity' &&
          ceremony.gesture === 'done' &&
          ceremony.operation_id !== localRecoveryId && (
            <Typography color="text.secondary" sx={{ mt: 1, fontSize: 11.5 }}>
              Récupération approuvée. Le poste concerné reprend de son côté.
            </Typography>
          )}
        {ceremony.operation === 'authorize_issuer' && !inCampaign && (
          <ArtifactDownloads gesture={ceremony.gesture} />
        )}
        {ceremony.operation === 'authorize_issuer' && ceremony.gesture === 'done' && (
          <Typography color="text.secondary" sx={{ mt: 1, fontSize: 11.5 }}>
            {inCampaign
              ? 'Délégation enregistrée par Astra. Redémarrer Astra pour qu’il émette sous elle.'
              : 'À installer sur l’hôte d’Astra : astra issuer install --authorization <fichier>.'}
          </Typography>
        )}
        {ceremony.operation === 'create_domain' && ceremony.gesture === 'done' && <DomainCreated />}
        {finishingRecovery && (
          <Alert severity="info" variant="outlined" sx={{ mt: 1.25, fontSize: 11.5 }}>
            Grant reçu : installation et commit de la nouvelle identité…
          </Alert>
        )}
        {error && (
          <>
            <Alert severity="error" variant="outlined" sx={{ mt: 1.25, fontSize: 11.5 }}>
              La cérémonie Astra a abouti, mais Orion n’a pas pu terminer la récupération :{' '}
              {error}
            </Alert>
            {ceremony.operation === 'recover_identity' &&
              ceremony.gesture === 'done' &&
              ceremony.operation_id && (
                <Button
                  size="small"
                  variant="outlined"
                  disabled={finishingRecovery}
                  onClick={() =>
                    finishRecovery(
                      ceremony.operation_id as string,
                      `${ceremony.session_id}:${ceremony.operation_id}`,
                      true,
                    )
                  }
                  sx={{ mt: 0.75, minHeight: 30, fontSize: 11.5 }}
                >
                  Réessayer la finalisation
                </Button>
              )}
          </>
        )}
      </Box>
    )
  }

  // Campaigns the domain opened and nobody has approved yet. Read from the
  // gateway in the tunnel: they are how an operator finds work without being
  // handed an identifier by whoever ran the command that created it.
  const approvals = (
    <ApprovalsPanel
      pending={pending}
      onCeremony={openCeremony}
      caPqOverlap={caPqOverlap}
      onOpenRotations={() => setTab('Rotations')}
    />
  )

  const rotations = (
    <RotationsPanel
      onCeremony={openCeremony}
      onOverview={takeOverview}
    />
  )

  const panels: Record<AstraTab, ReactNode> = {
    'Enrôlement': <EnrollmentOperatorPanel onCeremony={setCeremony} />,
    'Coffre et clés': <VaultPanel onCeremony={setCeremony} />,
    'Domaine': <DomainPanel onCeremony={setCeremony} />,
    'Approbations': approvals,
    'Rotations': rotations,
    'Gateways': (
      <WaitingNote>La gestion des gateways arrivera dans une prochaine version d’Orion.</WaitingNote>
    ),
  }

  return (
    <Box sx={{ height: '100%', overflowY: 'auto', px: GUTTER, py: 1.5 }}>
      <Typography component="h2" sx={{ fontSize: 13, fontWeight: 700, mb: 0.5 }}>
        Astra
      </Typography>
      {/* A fixed grid rather than a tab strip: six labels in one row overflow
          the window Orion is drawn for, and a scrolling strip hides sections
          the operator must see. Three columns keep every section in view, in
          two rows, at the base size. */}
      <Box
        role="tablist"
        aria-label="Sections Astra"
        style={{ gridTemplateColumns: 'repeat(3, minmax(0, 1fr))' }}
        sx={{ display: 'grid', gap: 0.75, mb: 1.5 }}
      >
        {TABS.map((name) => {
          const selected = name === tab
          const count = name === 'Approbations' ? pending.length : 0
          return (
            <ButtonBase
              key={name}
              role="tab"
              aria-selected={selected}
              onClick={() => setTab(name)}
              sx={{
                minWidth: 0,
                minHeight: 32,
                px: 0.75,
                gap: 0.5,
                borderRadius: 1.5,
                border: `1px solid ${selected ? PINE : RULE}`,
                bgcolor: selected ? MINT : 'background.paper',
                color: selected ? PINE : 'text.secondary',
                fontSize: 12,
                fontWeight: selected ? 700 : 600,
                transition: 'background-color 150ms ease, border-color 150ms ease',
                '&:hover': { borderColor: PINE },
                '&.Mui-focusVisible': { outline: `2px solid ${PINE}`, outlineOffset: 1 },
              }}
            >
              <Box component="span" sx={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {name}
              </Box>
              {count > 0 && (
                <Box
                  component="span"
                  sx={{
                    flexShrink: 0,
                    minWidth: 16,
                    height: 16,
                    px: 0.5,
                    borderRadius: 8,
                    bgcolor: PINE,
                    color: '#fff',
                    fontSize: 10,
                    fontWeight: 700,
                    lineHeight: '16px',
                  }}
                >
                  {count}
                </Box>
              )}
            </ButtonBase>
          )
        })}
      </Box>
      {panels[tab]}
    </Box>
  )
}
