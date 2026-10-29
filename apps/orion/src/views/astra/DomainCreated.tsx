import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import CircularProgress from '@mui/material/CircularProgress'
import Paper from '@mui/material/Paper'
import Typography from '@mui/material/Typography'

import { groupedHex } from '../OperatorCeremony'
import { useOverview } from './useOverview'

const code = { fontFamily: 'monospace', fontSize: 10.5 } as const

/**
 * The end of « Créer un domaine » (spec §4.1.4): the two fingerprints to keep,
 * the backup to make now, and what comes next. Read from the overview of the
 * vault just written, never from the ceremony status.
 */
export function DomainCreated() {
  const { overview, error } = useOverview()
  if (error) {
    return (
      <Alert severity="error" variant="outlined" sx={{ mt: 1.25, fontSize: 11.5 }}>
        Lecture du coffre impossible : {error}
      </Alert>
    )
  }
  if (!overview) return <CircularProgress size={16} aria-label="Lecture du coffre" sx={{ mt: 1.25 }} />

  const rows: [string, string][] = [
    ['Empreinte du coffre', overview.vault_fingerprint ? groupedHex(overview.vault_fingerprint) : '—'],
    ['Empreinte CA-PQ', overview.domain?.ca_pq_fingerprint ?? '—'],
  ]
  return (
    <Paper variant="outlined" sx={{ mt: 1.25, p: 1.75 }}>
      <Typography component="h3" sx={{ fontSize: 12.5, fontWeight: 700, mb: 1.25 }}>
        Domaine créé
      </Typography>
      <Box component="dl" sx={{ display: 'grid', gridTemplateColumns: '150px minmax(0, 1fr)', gap: '5px 12px', m: 0 }}>
        {rows.map(([label, value]) => (
          <Box key={label} sx={{ display: 'contents' }}>
            <Typography component="dt" color="text.secondary" sx={{ fontSize: 10.5 }}>
              {label}
            </Typography>
            <Typography component="dd" sx={{ m: 0, minWidth: 0, overflowWrap: 'anywhere', ...code }}>
              {value}
            </Typography>
          </Box>
        ))}
      </Box>
      <Alert severity="warning" variant="outlined" sx={{ mt: 1.25, fontSize: 11.5 }}>
        Sauvegardez le coffre : copiez authority-vault.json sur un support hors ligne. Le perdre,
        c’est perdre le domaine ; il est chiffré, une copie ne l’expose pas.
      </Alert>
      <Typography sx={{ mt: 1.25, fontSize: 11.5, fontWeight: 650 }}>Étapes suivantes</Typography>
      <Box component="ol" sx={{ m: 0, mt: 0.5, pl: 2.5, fontSize: 11.5, lineHeight: 1.6 }}>
        <li>
          Déployer la gateway : <Box component="code" sx={code}>./scripts/deploy.sh</Box>.
        </li>
        <li>
          Amorcer la gateway, encore en ligne de commande :{' '}
          <Box component="code" sx={code}>astra-signer issue-gateway-bootstrap</Box> (avec{' '}
          <Box component="code" sx={code}>--vault</Box> si le coffre n’est pas à l’emplacement par
          défaut).
        </li>
        <li>
          « Domaine » → « Finaliser le domaine », puis{' '}
          <Box component="code" sx={code}>./scripts/deploy.sh --astra</Box>.
        </li>
      </Box>
    </Paper>
  )
}
