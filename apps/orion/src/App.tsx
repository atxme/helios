import { useEffect, useState } from 'react'
import Alert from '@mui/material/Alert'
import AppBar from '@mui/material/AppBar'
import Badge from '@mui/material/Badge'
import Box from '@mui/material/Box'
import Chip from '@mui/material/Chip'
import IconButton from '@mui/material/IconButton'
import Paper from '@mui/material/Paper'
import Tab from '@mui/material/Tab'
import Tabs from '@mui/material/Tabs'
import Toolbar from '@mui/material/Toolbar'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { Radio, Settings2, Terminal, X } from 'lucide-react'
import { useClient } from './hooks/useClient'
import { ConnectView } from './views/ConnectView'
import { ProfilesView } from './views/ProfilesView'
import { EventLog } from './components/EventLog'
import { OrionMark } from './components/OrionMark'
import { postureMeta } from './components/state'

type Tab = 'connect' | 'profiles'

export default function App() {
  const c = useClient()
  const [tab, setTab] = useState<Tab>('connect')
  const [logOpen, setLogOpen] = useState(false)
  const posture = postureMeta(c.state, c.adapterUp)

  useEffect(() => {
    if (c.pathImportedProfile) setTab('profiles')
  }, [c.pathImportedProfile])

  return (
    <Box sx={{ display: 'flex', height: '100vh', flexDirection: 'column', gap: 1, p: 1 }}>
      <AppBar
        component="header"
        position="static"
        color="transparent"
        elevation={0}
        sx={{ flexShrink: 0, border: 0, borderRadius: 2.5 }}
      >
        <Toolbar disableGutters sx={{ minHeight: 52, gap: 1.5, px: 1.25 }}>
          <OrionMark
            style={{ width: 32, height: 32, flexShrink: 0, color: '#22d3ee' }}
            title="Orion"
          />
          <Box sx={{ minWidth: 0, lineHeight: 1 }}>
            <Typography
              component="h1"
              sx={{ fontSize: 13, fontWeight: 800, letterSpacing: '0.26em', lineHeight: 1 }}
            >
              ORION
            </Typography>
            <Typography
              color="primary.light"
              sx={{ mt: 0.6, fontFamily: 'monospace', fontSize: 9, letterSpacing: '0.12em' }}
            >
              WIREGUARD · POST-QUANTIQUE
            </Typography>
          </Box>

          {/* La posture réelle reste lisible depuis toutes les vues. */}
          <Chip
            size="small"
            aria-label={`${posture.label}. ${posture.detail}`}
            label={posture.label}
            icon={
              <Box
                component="span"
                sx={{
                  width: 7,
                  height: 7,
                  borderRadius: '50%',
                  bgcolor: posture.color,
                  boxShadow:
                    posture.posture === 'protected' ? `0 0 8px ${posture.color}` : undefined,
                }}
              />
            }
            sx={{
              ml: 'auto',
              maxWidth: 190,
              color: posture.color,
              bgcolor: `${posture.color}12`,
              border: `1px solid ${posture.color}40`,
              '& .MuiChip-label': { overflow: 'hidden', textOverflow: 'ellipsis' },
              '& .MuiChip-icon': { ml: 1 },
            }}
          />
        </Toolbar>
      </AppBar>

      <Box component="nav" aria-label="Navigation principale" sx={{ display: 'flex', px: 0.5 }}>
        <Tabs
          value={tab}
          onChange={(_event, value: Tab) => setTab(value)}
          aria-label="Vues d’Orion"
          sx={{ minHeight: 44 }}
        >
          <Tab
            id="orion-tab-connect"
            value="connect"
            icon={<Radio size={16} aria-hidden />}
            iconPosition="start"
            label="Connexion"
            aria-controls="orion-panel-connect"
          />
          <Tab
            id="orion-tab-profiles"
            value="profiles"
            icon={<Settings2 size={16} aria-hidden />}
            iconPosition="start"
            label="Profils"
            aria-controls="orion-panel-profiles"
          />
        </Tabs>

        <Tooltip title={logOpen ? 'Fermer le journal' : 'Ouvrir le journal'}>
          <IconButton
            color={logOpen ? 'primary' : 'default'}
            onClick={() => setLogOpen((open) => !open)}
            aria-label={logOpen ? 'Fermer le journal' : 'Ouvrir le journal'}
            aria-expanded={logOpen}
            aria-controls="orion-event-log"
            sx={{ ml: 'auto', alignSelf: 'center' }}
          >
            <Badge badgeContent={c.logs.length} color="primary" max={99}>
              <Terminal size={18} aria-hidden />
            </Badge>
          </IconButton>
        </Tooltip>
      </Box>

      {c.error && (
        <Alert
          severity="error"
          variant="outlined"
          action={
            <IconButton
              color="inherit"
              size="small"
              onClick={c.clearError}
              aria-label="Masquer l’erreur"
            >
              <X size={16} aria-hidden />
            </IconButton>
          }
          sx={{ mx: 0.5, flexShrink: 0, bgcolor: 'rgba(127, 29, 29, 0.18)' }}
        >
          {c.error}
        </Alert>
      )}

      <Paper
        component="main"
        elevation={8}
        sx={{
          minHeight: 0,
          flex: 1,
          overflow: 'hidden',
          bgcolor: 'rgba(12, 20, 38, 0.78)',
          backdropFilter: 'blur(12px)',
          boxShadow: '0 18px 50px -28px rgba(0, 0, 0, 0.9)',
        }}
      >
        {tab === 'connect' ? (
          <Box
            id="orion-panel-connect"
            role="tabpanel"
            aria-labelledby="orion-tab-connect"
            sx={{ height: '100%' }}
          >
            <ConnectView
              state={c.state}
              profile={c.selectedProfile}
              upSince={c.upSince}
              telemetry={c.telemetry}
              history={c.history}
              backend={c.backend}
              adapterUp={c.adapterUp}
              onConnect={() => c.connect(c.selectedProfile?.name)}
              onDisconnect={c.disconnect}
            />
          </Box>
        ) : (
          <Box
            id="orion-panel-profiles"
            role="tabpanel"
            aria-labelledby="orion-tab-profiles"
            sx={{ height: '100%' }}
          >
            <ProfilesView
              config={c.config}
              pathImport={c.pathImportedProfile}
              onPathImportHandled={c.clearPathImportedProfile}
              onImport={c.importProfile}
              onSave={c.saveProfile}
              onDelete={c.removeProfile}
              onSelect={c.select}
            />
          </Box>
        )}
      </Paper>

      {logOpen && (
        <Paper
          id="orion-event-log"
          component="footer"
          elevation={4}
          sx={{ flexShrink: 0, overflow: 'hidden', bgcolor: 'rgba(12, 20, 38, 0.9)' }}
        >
          <EventLog logs={c.logs} />
        </Paper>
      )}
    </Box>
  )
}
