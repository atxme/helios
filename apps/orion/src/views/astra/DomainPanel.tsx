import Alert from '@mui/material/Alert'
import Box from '@mui/material/Box'
import CircularProgress from '@mui/material/CircularProgress'
import Paper from '@mui/material/Paper'
import Typography from '@mui/material/Typography'

import { useOverview } from './useOverview'

/** The trust domain recorded in the operator vault (public values only). */
export function DomainPanel() {
  const { overview, error } = useOverview()
  if (error) {
    return (
      <Alert severity="error" variant="outlined" sx={{ fontSize: 11.5 }}>
        Lecture du domaine impossible : {error}
      </Alert>
    )
  }
  if (!overview) return <CircularProgress size={16} aria-label="Lecture du domaine" />
  const domain = overview.domain
  if (!domain) {
    return (
      <Alert severity="info" variant="outlined" sx={{ fontSize: 11.5 }}>
        Aucun relais n’est enregistré dans le coffre : le domaine n’a pas encore été relayé.
      </Alert>
    )
  }
  const rows: [string, string, boolean][] = [
    ['Domaine de confiance', domain.trust_domain_id, false],
    ['Identifiant RP', domain.rp_id, false],
    ['Empreinte CA-PQ', domain.ca_pq_fingerprint, true],
    ['Époque CA', domain.ca_epoch === null ? '—' : String(domain.ca_epoch), false],
    [
      'Époque CA-TLS',
      domain.ca_tls_present && domain.ca_tls_epoch !== null ? String(domain.ca_tls_epoch) : 'absente',
      false,
    ],
    ['Nom du serveur', domain.server_name ?? '—', false],
    ['Clé WireGuard de la gateway', domain.gateway_wg_public_key ?? '—', true],
  ]
  return (
    <Paper variant="outlined" sx={{ p: 1.75 }}>
      <Typography component="h3" sx={{ fontSize: 12.5, fontWeight: 700, mb: 1.25 }}>
        Domaine
      </Typography>
      <Box component="dl" sx={{ display: 'grid', gridTemplateColumns: '150px minmax(0, 1fr)', gap: '5px 12px', m: 0 }}>
        {rows.map(([label, value, mono]) => (
          <Box key={label} sx={{ display: 'contents' }}>
            <Typography component="dt" color="text.secondary" sx={{ fontSize: 10.5 }}>
              {label}
            </Typography>
            <Typography
              component="dd"
              sx={{ m: 0, minWidth: 0, overflowWrap: 'anywhere', fontSize: 10.5, fontFamily: mono ? 'monospace' : 'inherit' }}
            >
              {value}
            </Typography>
          </Box>
        ))}
      </Box>
    </Paper>
  )
}
