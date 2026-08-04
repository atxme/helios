import Box from '@mui/material/Box'
import Chip from '@mui/material/Chip'
import Skeleton from '@mui/material/Skeleton'
import Stack from '@mui/material/Stack'
import Tooltip from '@mui/material/Tooltip'
import Typography from '@mui/material/Typography'
import { Check, Fingerprint, Lock, ScrollText, X } from 'lucide-react'
import { useEffect, useState } from 'react'
import { fetchTrust } from '../api'
import { DataRow } from '../components/DataRow'
import { KnownLimit } from '../components/KnownLimit'
import { SectionCard } from '../components/SectionCard'
import type { Trust } from '../types'

/** Readable labels for the required algorithms, with what each one brings. */
const ALG_LABEL: Record<string, { name: string; note: string }> = {
  ed25519: {
    name: 'Ed25519',
    note: 'Signature classique, éprouvée. Tient tant qu’aucun calculateur quantique pertinent n’existe.',
  },
  'ml-dsa-65': {
    name: 'ML-DSA-65',
    note: 'Signature post-quantique (FIPS 204). Couvre la durée de vie du matériel déployé.',
  },
}

/** Splits the fingerprint into groups of four — comparable like an SSH one. */
function groupFingerprint(fingerprint: string): string {
  return (fingerprint.match(/.{1,4}/g) ?? [fingerprint]).join(' ')
}

/**
 * One of the three rules that do all the work at verification time.
 *
 * `rejects` is the axis, not "good/bad": the first two describe what gets an
 * artifact thrown out, the third what gets tolerated. Marking all three with a
 * green check — as a naive list would — would hide that the last one is the
 * only place where this gateway accepts something it does not understand.
 */
function Rule({ rejects, children }: { rejects: boolean; children: React.ReactNode }) {
  return (
    <Stack direction="row" spacing={1.5} sx={{ alignItems: 'flex-start', py: 0.75 }}>
      <Box sx={{ display: 'flex', mt: 0.25, color: rejects ? 'error.main' : 'text.disabled' }}>
        {rejects ? <X size={15} strokeWidth={2.5} /> : <Check size={15} strokeWidth={2.5} />}
      </Box>
      <Typography variant="body2" sx={{ color: 'text.secondary' }}>
        {children}
      </Typography>
    </Stack>
  )
}

export function TrustView() {
  const [trust, setTrust] = useState<Trust | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchTrust()
      .then(setTrust)
      .catch(() => setError('Ancre de confiance illisible — heliosd ne répond pas sur /api/trust'))
  }, [])

  if (error) {
    return (
      <KnownLimit register="danger" title="Ancre de confiance illisible">
        {error}
      </KnownLimit>
    )
  }

  if (!trust) {
    return (
      <Stack spacing={2.5}>
        <Skeleton variant="rounded" height={180} />
        <Skeleton variant="rounded" height={140} />
      </Stack>
    )
  }

  return (
    <Stack spacing={2.5}>
      {trust.development_keys && (
        <KnownLimit register="danger" title="Trousseau de développement compilé dans ce binaire">
          Il accepte des artefacts signés par les clés de test publiées dans le dépôt — n’importe qui
          peut en forger. C’est normal en développement, jamais sur un équipement déployé. Un build{' '}
          <code>release</code> exige <code>HELIOS_PUBLISHER_KEYRING_PATH</code> et échoue sans lui.
        </KnownLimit>
      )}

      <SectionCard
        icon={Lock}
        title={`Signatures exigées (${trust.required_algs.length})`}
        subtitle="Toutes valides, sinon rejet. Jamais « au moins une »."
      >
        <Stack spacing={2}>
          {trust.required_algs.map(alg => {
            const meta = ALG_LABEL[alg]
            return (
              <Box key={alg}>
                <Stack direction="row" spacing={1} sx={{ alignItems: 'baseline' }}>
                  <Typography variant="body2" sx={{ fontWeight: 600 }}>
                    {meta?.name ?? alg}
                  </Typography>
                  <Typography
                    sx={{ fontFamily: 'monospace', fontSize: '0.75rem', color: 'text.secondary' }}
                  >
                    {alg}
                  </Typography>
                </Stack>
                {meta && (
                  <Typography variant="body2" sx={{ color: 'text.secondary', mt: 0.25 }}>
                    {meta.note}
                  </Typography>
                )}
              </Box>
            )
          })}

          <Box sx={{ pt: 1.5, borderTop: '1px solid', borderColor: 'divider' }}>
            <Rule rejects>Un algorithme exigé sans signature valide → rejet.</Rule>
            <Rule rejects>Une signature présente mais invalide → rejet, même si les autres passent.</Rule>
            <Rule rejects={false}>
              Un algorithme <em>inconnu</em> en supplément → ignoré, pour la compatibilité avant.
            </Rule>
          </Box>
        </Stack>
      </SectionCard>

      <SectionCard
        icon={Fingerprint}
        title={`Trousseau éditeur (${trust.publisher_keys.length})`}
        subtitle="Compilé dans le binaire. Une rotation de clé éditeur exige une mise à jour du firmware."
      >
        <Stack spacing={1.5}>
          {trust.publisher_keys.map(key => (
            <Stack
              key={key.key_epoch}
              direction="row"
              spacing={2}
              sx={{ alignItems: 'center', flexWrap: 'wrap', rowGap: 1 }}
            >
              <Chip
                size="small"
                label={`époque ${key.key_epoch}`}
                sx={{
                  bgcolor: 'primary.container',
                  color: 'primary.onContainer',
                  fontFamily: 'monospace',
                }}
              />
              <Tooltip title="SHA-256(ed25519 ‖ ml-dsa-65), tronqué à 128 bits">
                <Typography
                  sx={{
                    fontFamily: 'monospace',
                    fontSize: '0.8125rem',
                    wordBreak: 'break-all',
                    minWidth: 0,
                  }}
                >
                  {groupFingerprint(key.fingerprint)}
                </Typography>
              </Tooltip>
            </Stack>
          ))}

          <Typography variant="body2" sx={{ color: 'text.secondary', pt: 1 }}>
            L’empreinte couvre les <strong>deux</strong> clés de l’époque hachées ensemble : un
            trousseau dont seule la moitié Ed25519 serait la bonne ne produirait pas la même valeur.
          </Typography>
        </Stack>
      </SectionCard>

      <SectionCard
        icon={ScrollText}
        title="Séparation de domaine"
        subtitle="Une signature de billet ne peut pas être rejouée comme signature d’un autre artefact."
      >
        <Box>
          <DataRow label="Domaine du billet" value={trust.reseal_domain} wrap />
          <DataRow label="Version de format" value={String(trust.reseal_format_version)} />
          <DataRow
            label="Octets signés"
            value="domaine ‖ version_format ‖ key_epoch ‖ payload_canonique"
            wrap
          />
        </Box>
      </SectionCard>
    </Stack>
  )
}
