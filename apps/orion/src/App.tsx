import { useEffect, useState } from 'react'
import Alert from '@mui/material/Alert'
import Badge from '@mui/material/Badge'
import Box from '@mui/material/Box'
import ButtonBase from '@mui/material/ButtonBase'
import IconButton from '@mui/material/IconButton'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { Radio, Settings2, Terminal, X } from 'lucide-react'
import * as api from './api'
import { useClient } from './hooks/useClient'
import { ConnectView } from './views/ConnectView'
import { ProfilesView } from './views/ProfilesView'
import { EventLog } from './components/EventLog'
import { OrionMark } from './components/OrionMark'
import { postureMeta } from './components/state'
import { GUTTER, PINE } from './theme'

/**
 * Coquille de l’application — un rail de navigation, une zone de contenu, rien
 * qui défile.
 *
 * Le rail n’affiche que des icônes et ne se déploie qu’au survol ou au focus.
 * Deux raisons : la première vue reste dégagée, et surtout les icônes occupent
 * un emplacement de **largeur fixe**, ce qui les aligne par construction. Des
 * onglets qui centrent le groupe icône + libellé décalent les icônes dès que les
 * libellés n’ont pas la même longueur — c’est exactement le défaut qu’on corrige
 * ici.
 */

type View = 'connect' | 'profiles' | 'logs'

/** Largeur du rail replié. L’emplacement d’icône fait exactement cette largeur. */
const RAIL = 56
/** Largeur déployée. Le panneau recouvre le contenu : rien ne se remet en page. */
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
  const posture = postureMeta(c.state, c.adapterUp)

  useEffect(() => {
    if (c.pathImportedProfile) setView('profiles')
  }, [c.pathImportedProfile])

  // Chaque vue a ses besoins de place : la connexion tient dans une colonne
  // étroite, le formulaire de profils réclame deux colonnes, le journal veut de
  // la largeur. La fenêtre suit la vue plutôt que d'adopter en permanence le
  // maximum des trois.
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

        {/* Seul porteur de la posture dans l'IHM : la vue Connexion ne la
            répète plus. L'explication est là, en infobulle, sans encombrer. */}
        <Tooltip title={posture.detail}>
          <Box
            aria-label={`${posture.label}. ${posture.detail}`}
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
            }}
          >
            <Box
              aria-hidden
              sx={{ width: 7, height: 7, borderRadius: '50%', flexShrink: 0, bgcolor: posture.accent }}
            />
            <Typography sx={{ color: posture.color, fontSize: 11.5, fontWeight: 650 }}>
              {posture.label}
            </Typography>
          </Box>
        </Tooltip>
      </Box>

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
              // Ne referme que si le focus quitte réellement le rail : sans ce
              // test, passer d'un élément à l'autre au clavier le replierait.
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
              // Le panneau déployé recouvre le contenu au lieu de le pousser :
              // une remise en page à chaque survol serait insupportable.
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
                  {/* Emplacement d'icône de largeur fixe : c'est lui qui garantit
                      l'alignement, replié comme déployé. */}
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
                backend={c.backend}
                adapterUp={c.adapterUp}
                onConnect={() => c.connect(c.selectedProfile?.name)}
                onDisconnect={c.disconnect}
              />
            </Box>
          )}

          {view === 'profiles' && (
            <Box role="region" aria-label="Profils" sx={{ height: '100%' }}>
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
