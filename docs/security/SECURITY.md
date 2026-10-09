# Sécurité et dette suivie

Ce document complète les ADR et la stratégie de test. Il ne remplace pas un
audit externe.

## Contrôles automatisés

- RustSec via `cargo audit` ; toute vulnérabilité fait échouer la CI ;
- `npm audit --audit-level=moderate` sur les deux interfaces ;
- Clippy/tests avec toutes les features ;
- tests adversariaux de signature, TPM, API, CSP, IPC, secrets et fail-closed ;
- lockfiles obligatoires (`Cargo.lock`, `package-lock.json`).

Le 2026-07-19, l’audit a conduit aux mises à jour suivantes :

- `quick-xml 0.39.4` → `0.41.0` via `plist 1.10.0`, corrigeant
  RUSTSEC-2026-0194 et RUSTSEC-2026-0195 ;
- `quinn-proto 0.11.14` → `0.11.15`, corrigeant RUSTSEC-2026-0185 ;
- `anyhow 1.0.102` → `1.0.103`, corrigeant RUSTSEC-2026-0190.

## Avis informatifs non résolus

Le chemin Linux de Tauri dépend encore de bindings GTK3 0.18 non maintenus et
de `glib 0.18`, concerné par RUSTSEC-2024-0429 sur
`VariantStrIter`. Ces dépendances sont transitives de Tauri/WebKitGTK ; le code
Helios/Orion n’utilise pas directement `VariantStrIter`.

Mesures :

- conserver les versions Tauri verrouillées et surveiller chaque mise à jour ;
- ne pas ignorer ces avis dans la sortie CI ;
- valider prioritairement le package Windows, cible principale d’Orion ;
- migrer dès que Tauri/Wry fournit un chemin Linux sans ces bindings ;
- ne jamais présenter `cargo audit` vert comme l’absence de dette : son succès
  signifie « aucune vulnérabilité bloquante », les warnings restent visibles.

Les avis `unmaintained` de `paste`, `proc-macro-error` et `unic-*` sont également
transitifs. Ils restent surveillés par la même campagne.

## Surface réseau

L’API Helios est filtrée sur l’interface WireGuard d’administration. Les
mutations exigent du JSON et aucun CORS permissif n’est publié. Les lectures
réseau sont expurgées des clés privées et PSK. L’identité réseau est résolue
depuis l’adresse source réelle de la connexion vers l’unique VIP IPv4 `/32`
d’un pair configuré ; aucun en-tête de proxy ne sert d’autorité. Les routes
d’administration exigent le drapeau `admin` de ce pair et, pour les requêtes
de navigateur portant `Origin`, une origine correspondant exactement à `Host`.
Un pair non administrateur n’accède qu’aux routes ouvertes aux pairs
authentifiés. Une source inconnue ou une VIP ambiguë est refusée
([`auth.rs`](../../crates/helios-api/src/auth.rs)).

## Secrets et racines de confiance

- les clés privées éditeur restent hors gateway ;
- les releases refusent tout trousseau marqué `development` ;
- les clés WireGuard/PSK ne doivent apparaître ni dans `Debug`, ni dans les
  réponses GET, ni dans les logs ;
- les profils Orion sont persistés dans un coffre HVLT chiffré : sous Windows,
  la clé racine est protégée par le TPM puis DPAPI utilisateur. Le mode dégradé
  explicite `danger_allow_software_keystore` utilise DPAPI seul. Hors Windows,
  le stockage protégé est refusé. La migration du fichier hérité en clair ne
  protège pas ses anciennes copies ; la rotation des clés concernées est recommandée
  ([ADR-006](../adr/ADR-006-SECRETS-AU-REPOS.md)) ;
- le compteur anti-rejeu de récupération n’est pas arbitré : le lot 3 de
  l’ADR-002 demeure bloqué.

## Signalement

Ne pas ouvrir publiquement un ticket contenant un secret, une clé ou un exploit
non corrigé. Fournir au mainteneur : version/commit, plateforme, préconditions,
impact, reproduction minimale et proposition de test de non-régression.
