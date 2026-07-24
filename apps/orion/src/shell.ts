/**
 * Verrouillage du shell WebView : Orion est une application, pas une page web.
 *
 * WebView2 apporte ses réflexes de navigateur — menu contextuel avec
 * « Actualiser », F5, Ctrl+R. Recharger n'y est pas anodin : le frontend est la
 * seule source de vérité sur ce que l'utilisateur voit du tunnel, et un
 * rechargement le remet à zéro sans rien dire au cœur Rust. Un profil en cours
 * d'édition disparaît, le journal de la session est perdu, la nature du PSK
 * négocié — jamais persistée, par construction — n'est plus connue de personne.
 * Le tunnel, lui, reste monté : l'IHM se rouvre en affirmant « Déconnecté » sur
 * un adaptateur bien vivant. C'est un mensonge d'interface sur l'objet même
 * dont elle rend compte.
 *
 * ## Ce qui reste permis, et pourquoi
 *
 * Le menu contextuel survit dans les **champs de saisie**. Coller une clé
 * WireGuard de 44 caractères au clic droit est un geste normal, et WebView2 y
 * présente le menu d'édition — couper/copier/coller —, pas celui de la page :
 * « Actualiser » n'y figure pas. Le supprimer partout coûterait cette ergonomie
 * sans rien fermer de plus.
 *
 * Ailleurs, le texte reste sélectionnable et Ctrl+C fonctionne ; le journal a de
 * toute façon ses boutons « Copier » et « Exporter », qui ne dépendent pas du
 * presse-papiers du navigateur.
 *
 * ## Forme du module
 *
 * La décision est isolée dans deux prédicats purs et la cible d'écoute est un
 * paramètre. Le module se teste donc entièrement sans DOM — le projet n'embarque
 * pas de jsdom, et ce verrou ne justifie pas d'en ajouter un.
 */

/** Sélecteur des contextes où le menu natif est un menu d'édition. */
const EDITABLE =
  'input, textarea, [contenteditable=""], [contenteditable="true"]'

/**
 * Cible d'écoute : `window` en production, un double dans les tests.
 *
 * Volontairement plus étroit que `Window` — ce module n'a besoin que de poser
 * et retirer deux écouteurs.
 */
export interface ShellTarget {
  addEventListener(
    type: string,
    handler: (event: Event) => void,
    options?: AddEventListenerOptions,
  ): void
  removeEventListener(
    type: string,
    handler: (event: Event) => void,
    options?: EventListenerOptions,
  ): void
}

/**
 * Le clic droit doit-il garder le menu natif ?
 *
 * Duck-typé sur `closest` plutôt que sur `instanceof Element` : la question est
 * « cette cible sait-elle remonter ses ancêtres ? », et la poser ainsi rend le
 * prédicat vérifiable sans DOM.
 */
export function keepsNativeContextMenu(target: unknown): boolean {
  const node = target as { closest?: (selector: string) => unknown } | null
  if (typeof node?.closest !== 'function') return false
  return node.closest(EDITABLE) != null
}

/**
 * L'événement clavier demande-t-il un rechargement ?
 *
 * Couvre les quatre chords : F5, Ctrl+F5, Ctrl+R et Ctrl+Shift+R. `metaKey`
 * assure la parité macOS, même si Orion n'y est pas livré aujourd'hui.
 */
export function isReloadChord(event: {
  key: string
  ctrlKey?: boolean
  metaKey?: boolean
}): boolean {
  if (event.key === 'F5') return true
  return Boolean(event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'r'
}

/**
 * Installe les garde-fous et renvoie de quoi les retirer.
 *
 * Le retour n'est pas décoratif : il rend le verrou réversible, donc testable,
 * et laisse React nettoyer proprement là où `StrictMode` monte deux fois.
 */
export function lockShell(target: ShellTarget): () => void {
  const onContextMenu = (event: Event) => {
    if (!keepsNativeContextMenu(event.target)) event.preventDefault()
  }

  const onKeyDown = (event: Event) => {
    if (isReloadChord(event as KeyboardEvent)) event.preventDefault()
  }

  // `capture` : intercepter avant qu'un champ de saisie ou MUI ne réagisse.
  target.addEventListener('contextmenu', onContextMenu)
  target.addEventListener('keydown', onKeyDown, { capture: true })

  return () => {
    target.removeEventListener('contextmenu', onContextMenu)
    target.removeEventListener('keydown', onKeyDown, { capture: true })
  }
}
