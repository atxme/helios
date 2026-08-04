import Box from '@mui/material/Box'
import ButtonBase from '@mui/material/ButtonBase'
import Chip from '@mui/material/Chip'
import Stack from '@mui/material/Stack'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { useColorScheme } from '@mui/material/styles'
import { AlertCircle, Monitor, Moon, Sun } from 'lucide-react'
import type { ReactNode } from 'react'
import type { WsStatus } from '../hooks/useHelios'
import { NAV_ITEMS, navItem } from '../navigation'
import type { NavId } from '../navigation'
import { EMPHASIZED, GUTTER, RAIL_WIDTH, SUN } from '../theme'
import type { Status, TunnelState } from '../types'
import { HeliosMark } from './HeliosMark'
import { StateChip } from './StateBadge'

/**
 * The frame every view is seen through: navigation rail, header, content.
 *
 * The rail is permanent rather than collapsible. Four destinations never
 * change, and a drawer would trade a permanent 92 px for a permanent extra
 * click. Below `sm` it becomes a horizontal bar — that width happens when an
 * operator opens the console on a cramped laptop screen, not because Helios is
 * mobile-first.
 *
 * The header carries what stays true whichever view is open: the tunnel state,
 * whether the daemon is simulating, and whether the event stream is live. An
 * operator who navigated to Système does not stop needing to know the tunnel
 * just dropped.
 */

const WS_INDICATOR: Record<WsStatus, { color: string; label: string; hint: string }> = {
  connected: {
    color: 'state.up.main',
    label: 'En direct',
    hint: 'Le flux d’événements est ouvert : l’affichage suit le démon.',
  },
  connecting: {
    color: 'state.connecting.main',
    label: 'Connexion',
    hint: 'Ouverture du flux d’événements.',
  },
  disconnected: {
    // Never "hors ligne": that is what a *tunnel* is, and the state chip sits
    // right next to this one. Two different facts cannot share a word in the
    // same header.
    color: 'state.failed.main',
    label: 'Flux coupé',
    hint: 'Flux fermé : l’affichage peut être périmé. Une reconnexion est tentée automatiquement.',
  },
}

function RailItem({
  item,
  active,
  onSelect,
}: {
  item: (typeof NAV_ITEMS)[number]
  active: boolean
  onSelect: () => void
}) {
  const { icon: Icon } = item
  return (
    <ButtonBase
      onClick={onSelect}
      aria-current={active ? 'page' : undefined}
      sx={{
        width: '100%',
        flexDirection: 'column',
        gap: 0.5,
        py: 1,
        borderRadius: '10px',
        color: active ? 'primary.main' : 'text.secondary',
        bgcolor: active ? 'primary.container' : 'transparent',
        transition: `background-color 200ms ${EMPHASIZED}, color 200ms ${EMPHASIZED}`,
        '&:hover': {
          bgcolor: active ? 'primary.container' : 'surfaceContainer.high',
          color: active ? 'primary.main' : 'text.primary',
        },
        '&.Mui-focusVisible': { outline: '2px solid', outlineColor: 'primary.main', outlineOffset: 2 },
      }}
    >
      <Icon size={20} strokeWidth={active ? 2.2 : 1.8} />
      <Typography
        sx={{
          fontSize: '0.6875rem',
          fontWeight: active ? 650 : 500,
          lineHeight: 1.2,
          color: 'inherit',
        }}
      >
        {item.label}
      </Typography>
    </ButtonBase>
  )
}

/** Cycles system → light → dark. Three states, so a toggle would not do. */
function ColorSchemeToggle() {
  const { mode, setMode } = useColorScheme()

  // Before mount MUI has not resolved the stored preference; guessing an icon
  // here would flip it on hydration.
  if (!mode) return <Box sx={{ height: 34 }} />

  const next = mode === 'system' ? 'light' : mode === 'light' ? 'dark' : 'system'
  const LABEL = {
    system: { Icon: Monitor, text: 'Thème système' },
    light: { Icon: Sun, text: 'Thème clair' },
    dark: { Icon: Moon, text: 'Thème sombre' },
  } as const
  const { Icon, text } = LABEL[mode]

  return (
    <Tooltip title={`${text} — cliquer pour ${LABEL[next].text.toLowerCase()}`}>
      <ButtonBase
        onClick={() => setMode(next)}
        aria-label={text}
        sx={{
          width: 34,
          height: 34,
          borderRadius: '8px',
          color: 'text.secondary',
          '&:hover': { bgcolor: 'surfaceContainer.high', color: 'text.primary' },
          '&.Mui-focusVisible': { outline: '2px solid', outlineColor: 'primary.main', outlineOffset: 2 },
        }}
      >
        <Icon size={17} strokeWidth={1.8} />
      </ButtonBase>
    </Tooltip>
  )
}

interface Props {
  children: ReactNode
  nav: NavId
  onNav: (id: NavId) => void
  status: Status | null
  currentState: TunnelState
  error: string | null
  wsStatus: WsStatus
  /** Controls belonging to the open view, shown next to its heading. */
  actions?: ReactNode
}

export function AppShell({
  children,
  nav,
  onNav,
  status,
  currentState,
  error,
  wsStatus,
  actions,
}: Props) {
  const current = navItem(nav)
  const ws = WS_INDICATOR[wsStatus]

  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: { xs: 'column', sm: 'row' },
        height: '100%',
        bgcolor: 'background.default',
      }}
    >
      <Box
        component="nav"
        aria-label="Sections de la console"
        sx={{
          display: 'flex',
          flexShrink: 0,
          bgcolor: 'surfaceContainer.lowest',
          borderColor: 'divider',
          flexDirection: { xs: 'row', sm: 'column' },
          width: { xs: '100%', sm: RAIL_WIDTH },
          borderRight: { xs: 0, sm: '1px solid' },
          borderBottom: { xs: '1px solid', sm: 0 },
          alignItems: 'center',
          gap: 0.75,
          px: 1.25,
          py: { xs: 1, sm: 2 },
          overflowX: { xs: 'auto', sm: 'visible' },
        }}
      >
        <Box
          sx={{
            display: { xs: 'none', sm: 'flex' },
            flexDirection: 'column',
            alignItems: 'center',
            gap: 0.75,
            mb: 2,
          }}
        >
          {/* The sun is spent here, and nowhere else in the interface. */}
          <Box sx={{ color: SUN, display: 'flex' }}>
            <HeliosMark size={30} title="Helios" />
          </Box>
          <Typography
            variant="overline"
            sx={{ color: 'text.secondary', fontSize: '0.625rem', lineHeight: 1 }}
          >
            Helios
          </Typography>
        </Box>

        {NAV_ITEMS.map(item => (
          <Box key={item.id} sx={{ width: { xs: 76, sm: '100%' }, flexShrink: 0 }}>
            <RailItem item={item} active={item.id === nav} onSelect={() => onNav(item.id)} />
          </Box>
        ))}

        <Stack
          spacing={1}
          sx={{ display: { xs: 'none', sm: 'flex' }, mt: 'auto', pt: 2, alignItems: 'center' }}
        >
          <ColorSchemeToggle />
          {status && (
            <Typography
              variant="caption"
              sx={{ color: 'text.disabled', fontFamily: 'monospace', fontSize: '0.6875rem' }}
            >
              v{status.version}
            </Typography>
          )}
        </Stack>
      </Box>

      <Box sx={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <Stack
          component="header"
          direction="row"
          spacing={2}
          sx={{
            alignItems: 'center',
            px: GUTTER,
            pt: GUTTER,
            pb: 2.5,
            flexWrap: 'wrap',
            rowGap: 1.5,
          }}
        >
          <Box sx={{ minWidth: 0, flex: 1 }}>
            <Typography variant="h3">{current.title}</Typography>
            <Typography variant="body2" sx={{ color: 'text.secondary', mt: 0.5 }}>
              {current.description}
            </Typography>
          </Box>

          <Stack direction="row" spacing={1.25} sx={{ alignItems: 'center', flexShrink: 0 }}>
            {actions}
            {status?.dry_run && (
              <Tooltip title="Les backends noyau ne sont pas utilisés : les commandes sont journalisées, pas appliquées.">
                <Chip
                  size="small"
                  label="Simulation"
                  sx={{ bgcolor: 'warning.container', color: 'warning.onContainer' }}
                />
              </Tooltip>
            )}
            <Tooltip title={ws.hint}>
              <Stack direction="row" spacing={0.75} sx={{ alignItems: 'center', px: 0.5 }}>
                <Box sx={{ width: 7, height: 7, borderRadius: '50%', bgcolor: ws.color }} />
                <Typography variant="overline" sx={{ color: 'text.secondary' }}>
                  {ws.label}
                </Typography>
              </Stack>
            </Tooltip>
            <StateChip state={currentState} />
          </Stack>
        </Stack>

        {error && (
          <Stack
            direction="row"
            spacing={1.5}
            role="alert"
            sx={{
              mx: GUTTER,
              mb: 2,
              px: 2,
              py: 1.5,
              borderRadius: '10px',
              alignItems: 'center',
              bgcolor: 'error.container',
              color: 'error.onContainer',
            }}
          >
            <AlertCircle size={17} strokeWidth={2} />
            <Typography variant="body2" sx={{ color: 'inherit', fontWeight: 500 }}>
              {error}
            </Typography>
          </Stack>
        )}

        <Box component="main" sx={{ flex: 1, overflowY: 'auto', px: GUTTER, pb: 6 }}>
          <Box sx={{ maxWidth: 1180 }}>{children}</Box>
        </Box>
      </Box>
    </Box>
  )
}
