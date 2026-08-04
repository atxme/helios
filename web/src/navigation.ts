import {
  Activity,
  LayoutDashboard,
  RadioTower,
  RefreshCw,
  Settings2,
  Shield,
  ShieldCheck,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

/**
 * The console's seven destinations.
 *
 * Each one carries its own heading and its own one-line brief, and the shell —
 * not the view — renders them. Previously every view opened with a hand-rolled
 * `<h1>` plus a paragraph, in four different type sizes across seven files;
 * the heading drifted from the rail label often enough that the two disagreed
 * on what a screen was called.
 *
 * Seven is also the ceiling of an MD3 navigation rail. An eighth destination
 * is a signal to group, not to shrink the labels.
 */
export type NavId =
  | 'dashboard'
  | 'telemetry'
  | 'wireguard'
  | 'firewall'
  | 'trust'
  | 'update'
  | 'settings'

export interface NavItem {
  id: NavId
  /** Under the icon in the rail — must stay on one line. */
  label: string
  /** In the app bar, at the top of the view. */
  title: string
  /** One sentence: what this screen answers. */
  description: string
  icon: LucideIcon
}

export const NAV_ITEMS: NavItem[] = [
  {
    id: 'dashboard',
    label: 'Tunnel',
    title: 'Tunnel',
    description: 'État de la passerelle, contrôle de l’interface et journal en temps réel.',
    icon: LayoutDashboard,
  },
  {
    id: 'telemetry',
    label: 'Télémétrie',
    title: 'Télémétrie réseau',
    description: 'Compteurs de débit relevés seconde par seconde sur l’interface WAN.',
    icon: Activity,
  },
  {
    id: 'wireguard',
    label: 'WireGuard',
    title: 'WireGuard',
    description: 'Interface serveur, clients admis et négociation de clé post-quantique.',
    icon: RadioTower,
  },
  {
    id: 'firewall',
    label: 'Pare-feu',
    title: 'Pare-feu · Kill-switch',
    description:
      'Architecture fail-closed : DROP par défaut, le trafic LAN ne passe que tant qu’un handshake date de moins de 150 s.',
    icon: Shield,
  },
  {
    id: 'trust',
    label: 'Confiance',
    title: 'Ancre de confiance',
    description:
      'Ce que ce binaire exige d’un artefact éditeur avant de l’accepter — billets TPM et manifestes Helios.',
    icon: ShieldCheck,
  },
  {
    id: 'update',
    label: 'Mise à jour',
    title: 'Mise à jour applicative',
    description:
      'Transfert et activation d’un binaire heliosd dont le manifeste porte les deux signatures exigées.',
    icon: RefreshCw,
  },
  {
    id: 'settings',
    label: 'Paramètres',
    title: 'Paramètres',
    description: 'Configuration résolue de la passerelle et routes de split-tunnel.',
    icon: Settings2,
  },
]

export function navItem(id: NavId): NavItem {
  const found = NAV_ITEMS.find(item => item.id === id)
  // Unreachable while `NavId` and `NAV_ITEMS` are edited together — which the
  // type system does not enforce, hence the explicit failure rather than a
  // silent fallback to the dashboard.
  if (!found) throw new Error(`destination inconnue : ${id}`)
  return found
}
