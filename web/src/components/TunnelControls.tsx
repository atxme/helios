import Box from '@mui/material/Box'
import Button from '@mui/material/Button'
import CircularProgress from '@mui/material/CircularProgress'
import Stack from '@mui/material/Stack'
import Typography from '@mui/material/Typography'
import { DoorOpen, Lock, LockOpen, Power, PowerOff } from 'lucide-react'
import { useState } from 'react'
import { TUNNEL_STATE, toneColors } from '../state'
import type { TunnelState } from '../types'

/**
 * The two commands that change what the gateway does.
 *
 * MD3's button hierarchy is used literally: exactly one filled button per
 * card — the action being invited — and outlines for everything else. Which
 * one is filled follows the state, so the screen always offers a single
 * obvious next move.
 *
 * The kill-switch line at the bottom is a **readout, not a control**. It has
 * no affordance on purpose: the kill-switch is not something an operator sets,
 * it is what the tunnel state implies (`state.ts` holds that mapping). Making
 * it look actionable would suggest traffic can be released without a handshake.
 */

interface Props {
  state: TunnelState
  daemonError: boolean
  captiveGateway: string | null
  onConnect: () => Promise<void>
  onDisconnect: () => Promise<void>
  onReleaseCaptivePortal: () => Promise<void>
}

export function TunnelControls({
  state,
  daemonError,
  captiveGateway,
  onConnect,
  onDisconnect,
  onReleaseCaptivePortal,
}: Props) {
  const [busy, setBusy] = useState(false)
  const semantics = TUNNEL_STATE[state]
  const tone = toneColors(semantics.tone)

  const run = async (action: () => Promise<void>) => {
    setBusy(true)
    try {
      await action()
    } catch {
      // The shell's banner already carries the error surfaced by useHelios.
    } finally {
      setBusy(false)
    }
  }

  const canConnect = !daemonError && (state === 'down' || state === 'failed')
  const canDisconnect = !daemonError && state !== 'down'

  return (
    <Stack spacing={2} sx={{ height: '100%' }}>
      <Typography variant="body2" sx={{ color: 'text.secondary' }}>
        Helios monte une interface WireGuard serveur et attend les handshakes des clients admis.
      </Typography>

      <Stack direction={{ xs: 'column', sm: 'row' }} spacing={1.5}>
        <Button
          variant={canConnect ? 'contained' : 'outlined'}
          disabled={!canConnect || busy}
          onClick={() => void run(onConnect)}
          startIcon={
            busy && canConnect ? <CircularProgress size={16} color="inherit" /> : <Power size={18} />
          }
        >
          Monter l’interface
        </Button>
        <Button
          variant="outlined"
          color="inherit"
          disabled={!canDisconnect || busy}
          onClick={() => void run(onDisconnect)}
          startIcon={<PowerOff size={18} />}
          sx={{
            borderColor: 'divider',
            color: 'text.secondary',
            '&:hover': { borderColor: 'error.main', color: 'error.main' },
          }}
        >
          Arrêter l’interface
        </Button>
      </Stack>

      {state === 'captive_portal' && (
        <Button
          variant="contained"
          disableElevation
          disabled={busy}
          onClick={() => void run(onReleaseCaptivePortal)}
          startIcon={<DoorOpen size={18} />}
          sx={{
            alignSelf: 'flex-start',
            bgcolor: 'state.captivePortal.container',
            color: 'state.captivePortal.onContainer',
            '&:hover': { bgcolor: 'state.captivePortal.container', filter: 'brightness(0.95)' },
          }}
        >
          Portail validé{captiveGateway ? ` (${captiveGateway})` : ''}
        </Button>
      )}

      <Stack
        direction="row"
        spacing={1.5}
        sx={{
          mt: 'auto',
          pt: 2,
          alignItems: 'center',
          borderTop: '1px solid',
          borderColor: 'divider',
        }}
      >
        <Box sx={{ color: 'text.secondary', display: 'flex' }}>
          {semantics.killSwitchEngaged ? <Lock size={15} strokeWidth={1.8} /> : <LockOpen size={15} strokeWidth={1.8} />}
        </Box>
        <Typography variant="overline" sx={{ color: 'text.secondary' }}>
          Kill-switch
        </Typography>
        <Typography variant="overline" sx={{ ml: 'auto', color: tone.main }}>
          {semantics.trafficLabel}
        </Typography>
      </Stack>
    </Stack>
  )
}
