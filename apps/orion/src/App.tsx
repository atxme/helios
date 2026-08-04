import { useEffect, useState } from 'react'
import Alert from '@mui/material/Alert'
import Badge from '@mui/material/Badge'
import Box from '@mui/material/Box'
import ButtonBase from '@mui/material/ButtonBase'
import IconButton from '@mui/material/IconButton'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { ChevronDown, Radio, Settings2, Terminal, X } from 'lucide-react'
import * as api from './api'
import type { VaultPosture } from './types'
import { useClient } from './hooks/useClient'
import { ConnectView } from './views/ConnectView'
import { ProfilesView } from './views/ProfilesView'
import { AboutDialog } from './components/AboutDialog'
import { EventLog } from './components/EventLog'
import { OrionMark } from './components/OrionMark'
import { PosturePanel } from './components/PosturePanel'
import { postureMeta } from './components/state'
import { GUTTER, PINE } from './theme'

/**
 * Application shell — a navigation rail, a content area, nothing that scrolls.
 *
 * The rail only shows icons and only expands on hover or focus. Two reasons:
 * the first view stays uncluttered, and above all the icons occupy a
 * **fixed-width** slot, which aligns them by construction. Tabs that center
 * the icon + label group shift the icons as soon as the labels aren't the
 * same length — that's exactly the defect being fixed here.
 */

type View = 'connect' | 'profiles' | 'logs'

/** Width of the collapsed rail. The icon slot is exactly this width. */
const RAIL = 56
/** Expanded width. The panel covers the content: nothing reflows. */
const NAV_OPEN = 184

const VIEWS: { value: View; label: string; icon: typeof Radio }[] = [
  { value: 'connect', label: 'Connexion', icon: Radio },
  { value: 'profiles', label: 'Profils', icon: Settings2 },
  { value: 'logs', label: 'Journal', icon: Terminal },
]

export default function App() {
  const c = useClient()
  const [view, setView] = useState<View>('connect')
  const [navOpen, setNavOpen] = useState(false)
  const [postureAnchor, setPostureAnchor] = useState<HTMLElement | null>(null)
  // Read on every opening rather than once at startup: BitLocker can be
  // suspended and the memory-lock privilege can change while Orion runs, so a
  // cached value would eventually claim a protection that has since gone.
  // A failure leaves it `null` — unknown, never "fine".
  const [vault, setVault] = useState<VaultPosture | null>(null)
  const [about, setAbout] = useState(false)
  /**
   * Bumped when the tray asks for an import.
   *
   * A counter rather than a boolean: the second «Importer…» in a row must
   * reopen the picker, and a flag already set changes nothing. The profile
   * screen watches the value, not its truth.
   */
  const [importRequest, setImportRequest] = useState(0)
  useEffect(() => {
    if (!postureAnchor) return
    let cancelled = false
    api
      .vaultPosture()
      .then((found) => {
        if (!cancelled) setVault(found)
      })
      .catch(() => {
        if (!cancelled) setVault(null)
      })
    return () => {
      cancelled = true
    }
  }, [postureAnchor])
  const posture = postureMeta(c.state, c.adapterUp)

  useEffect(() => {
    if (c.pathImportedProfile) setView('profiles')
  }, [c.pathImportedProfile])

  // The menu names an intent; deciding what it means to the window is this
  // component's job. Two of the five are not views: an import opens the profile
  // screen *and* its file picker, and «À propos» opens a dialog over whatever
  // is displayed rather than replacing it.
  useEffect(() => {
    const unlisten = api.onTrayView((trayView) => {
      if (trayView === 'about') {
        setAbout(true)
        return
      }
      if (trayView === 'import') {
        setView('profiles')
        setImportRequest((request) => request + 1)
        return
      }
      setView(trayView)
    })
    return () => {
      unlisten.then((removeListener) => removeListener())
    }
  }, [])

  // Each view has its own space needs: connection fits in a narrow column,
  // the profile form needs two columns, the log wants width. The window
  // follows the view rather than permanently adopting the maximum of the
  // three.
  useEffect(() => {
    void api.resizeForView(view).catch(() => {})
  }, [view])

  return (
    <Box
      sx={{
        display: 'grid',
        gridTemplateRows: 'auto auto 1fr',
        height: '100vh',
        overflow: 'hidden',
        bgcolor: 'background.default',
      }}
    >
      <Box
        component="header"
        sx={{
          display: 'flex',
          alignItems: 'center',
          gap: 1.25,
          height: 52,
          px: GUTTER,
          borderBottom: 1,
          borderColor: 'divider',
        }}
      >
        <OrionMark style={{ width: 24, height: 24, flexShrink: 0, color: PINE }} title="Orion" />
        <Typography component="h1" sx={{ fontSize: 15, fontWeight: 700, letterSpacing: '-0.01em' }}>
          Orion
        </Typography>

        {/* Sole carrier of posture in the UI: the Connect view no longer
            repeats it. One word here, the grounds behind it in the panel —
            which is also the only place stating that DNS leaves the tunnel. */}
        <Tooltip title={posture.detail}>
          <ButtonBase
            onClick={(event) => setPostureAnchor(event.currentTarget)}
            aria-haspopup="dialog"
            aria-expanded={Boolean(postureAnchor)}
            aria-label={`${posture.label}. ${posture.detail} Ouvrir le détail de la posture.`}
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 0.75,
              ml: 'auto',
              px: 1.25,
              py: 0.5,
              borderRadius: 5,
              border: `1px solid ${posture.color}33`,
              bgcolor: `${posture.accent}14`,
              '&:hover': { bgcolor: `${posture.accent}24` },
              '&.Mui-focusVisible': { outline: `2px solid ${posture.color}`, outlineOffset: 2 },
            }}
          >
            <Box
              aria-hidden
              sx={{ width: 7, height: 7, borderRadius: '50%', flexShrink: 0, bgcolor: posture.accent }}
            />
            <Typography sx={{ color: posture.color, fontSize: 11.5, fontWeight: 650 }}>
              {posture.label}
            </Typography>
            <ChevronDown size={13} aria-hidden style={{ color: posture.color }} />
          </ButtonBase>
        </Tooltip>
      </Box>

      <PosturePanel
        anchor={postureAnchor}
        onClose={() => setPostureAnchor(null)}
        state={c.state}
        adapterUp={c.adapterUp}
        profile={c.selectedProfile}
        psk={c.psk}
        backend={c.backend}
        vault={vault}
      />

      <AboutDialog open={about} onClose={() => setAbout(false)} />

      {c.error ? (
        <Alert
          severity="error"
          variant="outlined"
          action={
            <IconButton color="inherit" size="small" onClick={c.clearError} aria-label="Masquer l’erreur">
              <X size={15} aria-hidden />
            </IconButton>
          }
          sx={{ borderRadius: 0, border: 0, borderBottom: 1, borderColor: 'divider', py: 0.25 }}
        >
          {c.error}
        </Alert>
      ) : (
        <Box />
      )}

      <Box sx={{ display: 'grid', gridTemplateColumns: `${RAIL}px 1fr`, minHeight: 0 }}>
        <Box component="nav" aria-label="Navigation principale" sx={{ position: 'relative' }}>
          <Box
            onMouseEnter={() => setNavOpen(true)}
            onMouseLeave={() => setNavOpen(false)}
            onFocus={() => setNavOpen(true)}
            onBlur={(event) => {
              // Only close if focus truly leaves the rail: without this
              // check, moving from one element to another via keyboard
              // would collapse it.
              if (!event.currentTarget.contains(event.relatedTarget as Node | null)) {
                setNavOpen(false)
              }
            }}
            sx={{
              position: 'absolute',
              top: 0,
              bottom: 0,
              left: 0,
              display: 'flex',
              flexDirection: 'column',
              width: navOpen ? NAV_OPEN : RAIL,
              pt: 1,
              bgcolor: 'background.default',
              borderRight: 1,
              borderColor: 'divider',
              overflow: 'hidden',
              // The expanded panel covers the content instead of pushing it:
              // reflowing the layout on every hover would be unbearable.
              zIndex: 3,
              boxShadow: navOpen ? '6px 0 20px -12px rgba(16, 35, 28, 0.45)' : 'none',
              transition: 'width 160ms ease, box-shadow 160ms ease',
              '@media (prefers-reduced-motion: reduce)': { transition: 'none' },
            }}
          >
            {VIEWS.map(({ value, label, icon: Icon }) => {
              const active = view === value
              const pending = value === 'logs' && view !== 'logs' ? c.logs.length : 0
              return (
                <ButtonBase
                  key={value}
                  onClick={() => setView(value)}
                  aria-current={active ? 'page' : undefined}
                  sx={{
                    position: 'relative',
                    display: 'flex',
                    justifyContent: 'flex-start',
                    width: '100%',
                    minHeight: 46,
                    flexShrink: 0,
                    color: active ? 'primary.main' : 'text.secondary',
                    '&:hover': { bgcolor: 'action.hover' },
                    '&.Mui-focusVisible': { outline: `2px solid ${PINE}`, outlineOffset: -2 },
                  }}
                >
                  {active && (
                    <Box
                      aria-hidden
                      sx={{
                        position: 'absolute',
                        top: 8,
                        bottom: 8,
                        left: 0,
                        width: 2,
                        borderRadius: 1,
                        bgcolor: 'primary.main',
                      }}
                    />
                  )}
                  {/* Fixed-width icon slot: this is what guarantees
                      alignment, collapsed as well as expanded. */}
                  <Box
                    sx={{ display: 'grid', placeItems: 'center', width: RAIL, flexShrink: 0 }}
                  >
                    <Badge
                      badgeContent={pending}
                      color="primary"
                      max={99}
                      slotProps={{ badge: { style: { fontSize: 9, height: 15, minWidth: 15 } } }}
                    >
                      <Icon size={18} aria-hidden />
                    </Badge>
                  </Box>
                  <Typography
                    sx={{
                      whiteSpace: 'nowrap',
                      fontSize: 13,
                      fontWeight: active ? 650 : 500,
                      opacity: navOpen ? 1 : 0,
                      transition: 'opacity 140ms ease',
                    }}
                  >
                    {label}
                  </Typography>
                </ButtonBase>
              )
            })}
          </Box>
        </Box>

        <Box component="main" sx={{ minWidth: 0, minHeight: 0, overflow: 'hidden' }}>
          {view === 'connect' && (
            <Box role="region" aria-label="Connexion" sx={{ height: '100%' }}>
              <ConnectView
                state={c.state}
                profile={c.selectedProfile}
                upSince={c.upSince}
                telemetry={c.telemetry}
                history={c.history}
                adapterUp={c.adapterUp}
                psk={c.psk}
                onConnect={() => c.connect(c.selectedProfile?.name)}
                onDisconnect={c.disconnect}
                onOpenSsh={() => c.openSshTerminal(c.selectedProfile?.name)}
              />
            </Box>
          )}

          {view === 'profiles' && (
            <Box role="region" aria-label="Profils" sx={{ height: '100%' }}>
              <ProfilesView
                config={c.config}
                pathImport={c.pathImportedProfile}
                importRequest={importRequest}
                onPathImportHandled={c.clearPathImportedProfile}
                onImport={c.importProfile}
                onSave={c.saveProfile}
                onDelete={c.removeProfile}
                onSelect={c.select}
              />
            </Box>
          )}

          {view === 'logs' && (
            <Box role="region" aria-label="Journal" sx={{ height: '100%' }}>
              <EventLog logs={c.logs} />
            </Box>
          )}
        </Box>
      </Box>
    </Box>
  )
}
