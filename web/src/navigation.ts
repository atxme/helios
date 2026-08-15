import { Gauge, Server, ShieldCheck, Users } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

/**
 * The console's four destinations.
 *
 * There were seven. Two of them existed for content that never changes —
 * compile-time trust constants — and two more re-displayed, in a different
 * order, figures already shown elsewhere. A destination has to earn its slot
 * by being a place an operator *goes to do something*; the rest is a panel
 * inside one of these four.
 *
 * The order is the order of frequency, not of importance: an operator opens
 * this console to check that the tunnel is up, then to see who is connected.
 * Everything else is occasional.
 */
export type NavId = 'overview' | 'clients' | 'security' | 'system'

export interface NavItem {
  id: NavId
  /** Under the icon in the rail — must stay on one line. */
  label: string
  /** The heading of the view. */
  title: string
  /** One short line: what this screen is for. */
  description: string
  icon: LucideIcon
}

export const NAV_ITEMS: NavItem[] = [
  {
    id: 'overview',
    label: 'Aperçu',
    title: 'Vue d’ensemble',
    description: 'État de la passerelle, trafic en direct et derniers événements.',
    icon: Gauge,
  },
  {
    id: 'clients',
    label: 'Clients',
    title: 'Clients',
    description: 'Qui est connecté, depuis quand, et par quelle protection.',
    icon: Users,
  },
  {
    id: 'security',
    label: 'Sécurité',
    title: 'Sécurité',
    description: 'Kill-switch, politique appliquée et ancre de confiance.',
    icon: ShieldCheck,
  },
  {
    id: 'system',
    label: 'Système',
    title: 'Système',
    description: 'Santé de la machine, configuration, mise à jour et journal.',
    icon: Server,
  },
]

export function navItem(id: NavId): NavItem {
  const found = NAV_ITEMS.find(item => item.id === id)
  // Unreachable while `NavId` and `NAV_ITEMS` are edited together — which the
  // type system does not enforce, hence an explicit failure rather than a
  // silent fallback to the first destination.
  if (!found) throw new Error(`destination inconnue : ${id}`)
  return found
}
