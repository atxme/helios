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
import { EMPHASIZED, GUTTER, RAIL_WIDTH } from '../theme'
import type { Status, TunnelState } from '../types'
import { HeliosLockup } from './HeliosMark'
import { StateChip } from './StateBadge'

/**
 * The frame every view is seen through: MD3 navigation rail, app bar, content.
 *
 * The rail is permanent rather than collapsible. A supervision console is
 * navigated dozens of times per session and the destination set never changes,
 * so a drawer would trade a permanent 96 px for a permanent extra click. Below
 * `sm` the rail turns into a horizontal bar — the same seven destinations,
 * scrolled — because a phone-width viewport happens when an operator opens the
 * console from a laptop on a cramped screen, not because Helios is mobile-first.
 *
 * The app bar carries what is true regardless of the view: the tunnel state,
 * whether the daemon is simulating, and whether the event stream is live. An
 * operator who navigates away from the dashboard does not stop needing to know
 * that the tunnel just dropped.
 */

const WS_INDICATOR: Record<WsStatus, { color: string; label: string; hint: string }> = {
  connected: {
    color: 'state.up.main',
    label: 'Temps réel',
    hint: 'Le flux d’événements est ouvert : l’état affiché suit le démon.',
  },
  connecting: {
    color: 'state.connecting.main',
    label: 'Connexion…',
    hint: 'Ouverture du flux d’événements.',
  },
  disconnected: {
    color: 'state.failed.main',
    label: 'Flux coupé',
    hint: 'Le flux est fermé : l’état affiché peut être périmé. Une reconnexion est tentée automatiquement.',
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
        py: 0.75,
        borderRadius: 3,
        color: active ? 'rail.textActive' : 'rail.text',
        transition: `color 260ms ${EMPHASIZED}`,
        '&:hover': { color: 'rail.textActive' },
        '&:hover .rail-indicator': { bgcolor: 'rail.indicator' },
        '&.Mui-focusVisible': { outline: '2px solid', outlineColor: 'primary.main', outlineOffset: 2 },
      }}
    >
      {/* MD3 active indicator: a pill behind the icon, never a side bar. */}
      <Box
        className="rail-indicator"
        sx={{
          width: 54,
          height: 32,
          borderRadius: 999,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          bgcolor: active ? 'rail.indicator' : 'transparent',
          transition: `background-color 260ms ${EMPHASIZED}`,
        }}
      >
        <Icon size={20} strokeWidth={active ? 2.1 : 1.7} />
      </Box>
      <Typography
        sx={{
          fontSize: '0.6875rem',
          fontWeight: active ? 700 : 500,
          letterSpacing: '0.02em',
          lineHeight: 1.2,
          color: 'inherit',
          textAlign: 'center',
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

  // Before mount, MUI has not yet resolved the stored preference; rendering a
  // guessed icon here would flip on hydration.
  if (!mode) return <Box sx={{ height: 36 }} />

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
          width: 36,
          height: 36,
          borderRadius: '50%',
          color: 'rail.text',
          '&:hover': { color: 'rail.textActive', bgcolor: 'rail.indicator' },
          '&.Mui-focusVisible': { outline: '2px solid', outlineColor: 'primary.main', outlineOffset: 2 },
        }}
      >
        <Icon size={18} strokeWidth={1.7} />
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
}

export function AppShell({ children, nav, onNav, status, currentState, error, wsStatus }: Props) {
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
          position: 'relative',
          display: 'flex',
          flexShrink: 0,
          // The rail keeps its night in both schemes: it is the one fixed
          // instrument, it carries the mark, and holding it constant gives the
          // light scheme a spine instead of a pale field of panels.
          bgcolor: 'rail.bg',
          borderColor: 'rail.border',
          flexDirection: { xs: 'row', sm: 'column' },
          width: { xs: '100%', sm: RAIL_WIDTH },
          borderRight: { xs: 0, sm: '1px solid' },
          borderBottom: { xs: '1px solid', sm: 0 },
          alignItems: 'center',
          gap: 0.5,
          px: { xs: 1, sm: 1.25 },
          py: { xs: 1, sm: 2 },
          overflowX: { xs: 'auto', sm: 'visible' },
          // A sliver of corona along the inner edge — the sun, seen from the side.
          '&::after': {
            content: '""',
            position: 'absolute',
            display: { xs: 'none', sm: 'block' },
            pointerEvents: 'none',
            top: 0,
            bottom: 0,
            right: 0,
            // '1px', not 1: in MUI's system a unitless width of 1 means 100%,
            // which turns this hairline into a sheet covering the whole rail
            // and swallowing every click on it.
            width: '1px',
            background:
              'linear-gradient(180deg, transparent 0%, var(--mui-palette-primary-main) 18%, transparent 62%)',
            opacity: 0.5,
          },
        }}
      >
        <Box sx={{ display: { xs: 'none', sm: 'block' }, mb: 2 }}>
          <HeliosLockup />
        </Box>

        {NAV_ITEMS.map(item => (
          <Box key={item.id} sx={{ width: { xs: 72, sm: '100%' }, flexShrink: 0 }}>
            <RailItem item={item} active={item.id === nav} onSelect={() => onNav(item.id)} />
          </Box>
        ))}

        <Stack
          spacing={1}
          sx={{
            display: { xs: 'none', sm: 'flex' },
            mt: 'auto',
            pt: 2,
            alignItems: 'center',
          }}
        >
          <ColorSchemeToggle />
          {status && (
            <Typography
              variant="caption"
              sx={{ color: 'rail.text', fontFamily: 'monospace', opacity: 0.7 }}
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
            alignItems: 'flex-start',
            px: GUTTER,
            pt: GUTTER,
            pb: 2,
            flexWrap: 'wrap',
            rowGap: 1.5,
          }}
        >
          <Box sx={{ minWidth: 0, flex: 1 }}>
            <Typography variant="h3" sx={{ fontWeight: 500 }}>
              {current.title}
            </Typography>
            <Typography variant="body2" sx={{ color: 'text.secondary', mt: 0.75, maxWidth: '68ch' }}>
              {current.description}
            </Typography>
          </Box>

          <Stack direction="row" spacing={1} sx={{ alignItems: 'center', flexShrink: 0 }}>
            {status?.dry_run && (
              <Tooltip title="Les backends noyau WireGuard et nftables ne sont pas utilisés : les commandes sont journalisées, pas appliquées.">
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
              px: 2.5,
              py: 1.75,
              borderRadius: '14px',
              alignItems: 'center',
              bgcolor: 'error.container',
              color: 'error.onContainer',
            }}
          >
            <AlertCircle size={18} strokeWidth={1.8} />
            <Typography variant="body2" sx={{ color: 'inherit' }}>
              {error}
            </Typography>
          </Stack>
        )}

        <Box
          component="main"
          sx={{
            flex: 1,
            overflowY: 'auto',
            px: GUTTER,
            pb: 6,
          }}
        >
          <Box sx={{ maxWidth: 1080 }}>{children}</Box>
        </Box>
      </Box>
    </Box>
  )
}
