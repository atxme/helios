# Stratégie de test et de sécurité

La commande de référence est :

```sh
bash scripts/regression.sh
```

Elle doit être verte avant fusion ou livraison. Elle utilise les lockfiles,
interdit les avertissements Clippy et couvre les features matérielles au niveau
compilation/tests sans exécuter d’effet réel.

## Matrice automatisée

| Couche | Contrôles |
|---|---|
| Rust | `fmt`, Clippy `--all-targets --all-features`, tests workspace `--all-features`, doc-tests |
| Dépendances Rust | `cargo audit` : vulnérabilités bloquantes, avis informatifs suivis |
| Helios/Orion web | `npm ci`, `npm audit --audit-level=moderate`, Vitest, TypeScript et build Vite |
| Signatures | hybride AND, anti-downgrade, époque signée, domaines, JSON strict, Ed25519 faible/non canonique |
| TPM | anti-rejeu, PCR facultatif, rejet v1, ordre authentification → compteur → PCR |
| API | routeur complet, absence de secrets, JSON obligatoire pour les mutations, absence de CORS permissif |
| Tauri | commandes IPC, CSP, prototypes figés et capability minimale |
| Éditeur | permissions 0700/0600, auto-vérification, clés cohérentes et refus d’écrasement |
| Réseau | états, expiration de handshake, règles fail-closed et transaction préparée avant application |
| Provisioning PQ | tour ML-KEM complet via l’endpoint, PSK posé avant d’être annoncé, refus fail-closed si la pose échoue, annulation en mémoire et restauration du PSK précédent, adaptateur client jamais démonté |
| OTA | index absent/invalide/identique/nouveau, non-exécution de RAUC si déjà à jour, et lecture du slot booté dans `rauc status --output-format=json` (parsing seul) |

`cargo-audit` est un prérequis local :

```sh
cargo install cargo-audit --locked
```

La CI l’installe explicitement. Les vulnérabilités RustSec font échouer la
campagne. Les avis informatifs `unmaintained`/`unsound` transitifs sont affichés
et suivis dans [SECURITY.md](SECURITY.md), car `--deny warnings` rendrait la CI
inexécutable tant que Tauri Linux dépend de GTK3. Les audits ne détectent pas une
erreur de conception ; les tests d’invariants restent obligatoires.

## Invariants de sécurité verrouillés

1. Seul `TunnelState::Up` autorise le trafic gateway.
2. Le kill-switch précède tout réseau et reste engagé à l’arrêt.
3. Un mode réel sans backend noyau opérationnel échoue au démarrage.
4. Le ruleset Netlink est atomique ; une traduction incomplète n’est pas envoyée.
5. Orion ne démonte son adaptateur qu’après déconnexion explicite.
6. Un backend Orion réel indisponible ne retombe pas sur le dry-run.
7. `GET /api/network` ne sérialise jamais clé privée ni PSK.
8. Une mutation HTTP sans JSON est refusée et aucun CORS wildcard n’est publié.
9. Ed25519 et ML-DSA-65 sont toutes deux obligatoires ; `key_epoch` est signé.
10. Une release ne compile pas avec le trousseau éditeur de développement, même
   si son chemin est fourni explicitement.
11. Le billet TPM v1 ne bénéficie d’aucune période de compatibilité.

Lorsqu’un bug de sécurité est corrigé, ajouter d’abord un test qui échoue avec
l’ancien comportement et le garder comme test de non-régression.

## Tests matériels obligatoires

Les tests automatisés ne peuvent pas promettre la fiabilité du matériel absent.
Sur une gateway de laboratoire, compiler puis exercer :

```sh
HELIOS_PUBLISHER_KEYRING_PATH=/chemin/public/publisher-keyring.json \
  cargo build --release -p heliosd --features netlink,wireguard,tpm,embed-ui
```

Valider avec accès console :

- démarrage fail-closed avant création de l’interface ;
- handshake réel, passage `connecting` → `up`, puis expiration ;
- absence de trafic LAN dans tous les états sauf `up` ;
- erreur Netlink laissant intacte la politique précédente ;
- API inaccessible depuis le WAN et accessible via `helios0` ;
- Orion : adaptateur/routes maintenus sur panne UDP, retrait sur déconnexion ;
- PCR correct et incorrect, billet signé valide, rejoué, altéré et PCR optionnel ;
- provisioning PQ : un client Orion réel obtient son PSK dans le tunnel, le
  handshake suivant (≤ 2 min) réussit avec `PresharedKey` posé des deux côtés,
  et `wg show` confirme le slot renseigné sur la gateway comme sur le client ;
- provisioning PQ, chemin dégradé : gateway dont `sync_peers` échoue — le client
  doit rester en tunnel classique opérationnel, sans PSK orphelin ;
- RAUC : installation slot inactif, boot sain, `mark-good`, boot cassé et rollback ;
- RAUC : `heliosd check-update` après un rollback rapporte bien la version du
  slot effectivement booté, et la divergence avec la version compilée est
  journalisée en `warn` si le slot status a été altéré.

Ces essais modifient le pare-feu, les routes, le TPM et les slots de boot : ne
jamais les lancer contre une appliance de production.

## Campagne de provisioning post-quantique

`helios-ctl campaign` joue les mêmes scénarios en dry-run et sur la cible. Il
agit en **vrai client** : il emprunte `orion_core::provision`, le code
qu'embarque Orion. Une campagne qui tombe accuse donc le daemon *ou* le client.

Trois catégories, selon ce qu'elles exigent de l'environnement :

| Catégorie | Exige | Ce qu'elle établit |
| --- | --- | --- |
| `client` | rien | validation côté client : gateway usurpée, ciphertext malformé, version inconnue |
| `protocole` | un daemon joignable | tour ML-KEM complet, PSK frais par session, VIP stable, refus d’un pair non admis, absence de secret dans l’API |
| `plan-de-donnees` | `wg` et un noyau réel | le PSK est **réellement** dans le slot WireGuard, et le handshake a survécu à sa pose |

### Dry-run

```sh
bash scripts/campaign.sh            # daemon isolé, campagne, démontage
bash scripts/campaign.sh --repeat 20  # endurance
```

Le script monte son propre `heliosd --dev` sur une configuration temporaire :
il ne touche jamais `/var/lib/helios`. Il est joué par `scripts/regression.sh`.

### Cible

Le dry-run ne prouve rien du plan de données : `DryRunBackend` accepte un PSK
sans qu'aucun paquet ne soit chiffré. Seule la catégorie `plan-de-donnees`
tranche, et elle exige la cible.

Déclarer d’abord le pair de campagne sur la gateway (l’admission reste hors
bande — la campagne ne s’auto-admet jamais) :

```sh
helios-ctl campaign --generate-keys     # imprime le bloc [[peers]] à coller
```

Puis, **depuis le client**, tunnel classique monté :

```sh
helios-ctl --url http://100.64.0.1:8080 campaign \
  --client-key <privée du client> --gateway-key <publique de la gateway>
```

Enfin, **depuis la gateway**, la catégorie que le dry-run ne peut pas jouer :

```sh
helios-ctl campaign --only plan-de-donnees --wg-iface helios0 \
  --client-key <privée du client> --gateway-key <publique de la gateway>
```

Attendre au moins un handshake (≤ 2 min) entre le provisioning et cette
dernière commande : c’est précisément l’intervalle où un PSK posé d’un seul
côté se manifesterait, et le scénario `handshake vivant avec PSK` est là pour
l’attraper.

## Limites connues

- le backend réel dépend du noyau, des pilotes et des privilèges de chaque OS ;
- le flux PSK ML-KEM n’est pas encore installé atomiquement de bout en bout ;
- la récupération signée attend l’arbitrage du compteur monotone ;
- le chemin Tauri Linux ne valide pas Windows/WireGuard-NT ;
- une campagne verte réduit le risque de régression, elle ne constitue ni audit
  externe ni preuve formelle.

La recette interactive est dans [MANUAL-TESTING.md](MANUAL-TESTING.md).
