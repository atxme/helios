import Stack from '@mui/material/Stack'
import { Clock, Wifi } from 'lucide-react'
import { DataRow } from '../components/DataRow'
import { KnownLimit } from '../components/KnownLimit'
import { NetworkStats } from '../components/NetworkStats'
import { SectionCard } from '../components/SectionCard'
import type { Status, TelemetrySample } from '../types'

interface Props {
  samples: TelemetrySample[]
  status: Status | null
}

export function TelemetryView({ samples, status }: Props) {
  return (
    <Stack spacing={2.5}>
      <SectionCard
        title="Débit"
        subtitle="Échelle relative à la fenêtre affichée — la courbe dit la stabilité, le chiffre dit la magnitude."
      >
        <NetworkStats samples={samples} sparklineHeight={72} />
      </SectionCard>

      <SectionCard title="Source des mesures">
        <DataRow icon={Wifi} label="Interface" value={status?.wan_iface ?? ''} />
        <DataRow
          icon={Clock}
          label="Période"
          value="1 s"
          hint="Le démon échantillonne /proc/net/dev et pousse un événement de télémétrie par seconde."
        />
      </SectionCard>

      <KnownLimit title="CPU, mémoire et température ne sont pas relevés">
        Ces compteurs exigent la lecture de <code>/proc/stat</code> et de{' '}
        <code>/sys/class/thermal</code> sur la cible, hors du périmètre de la télémétrie réseau
        actuelle. Les débits ci-dessus, eux, sont mesurés y compris en simulation.
      </KnownLimit>
    </Stack>
  )
}
