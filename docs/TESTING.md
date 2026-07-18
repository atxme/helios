# Tests de non-régression

La commande de référence avant chaque version est :

```sh
bash scripts/regression.sh
```

Elle exécute, avec les dépendances JavaScript verrouillées (`npm ci`) :

1. le formatage, Clippy en mode `-D warnings`, les tests unitaires et les doc-tests Rust ;
2. les tests de contrat REST du serveur Helios et les scénarios d’orchestration WireGuard en `dry-run` ;
3. les tests unitaires des deux interfaces React ;
4. la vérification TypeScript et le build de production de `web` et d’Orion.

La même campagne est obligatoire sur chaque push et pull request via
`.github/workflows/regression.yml`. Une version ne doit être taguée que si ce
job est vert.

## Ce qui requiert la cible matérielle

Les backends `netlink`, WireGuard noyau et TPM compilent dans la campagne mais
ne sont pas exécutables sous WSL2. Avant une livraison destinée à une gateway,
effectuer aussi sur une machine Linux cible :

```sh
cargo build -p heliosd --features netlink,wireguard,tpm
cargo run -p heliosd --features netlink,wireguard -- status
```

Puis valider le scénario de déploiement avec un pair de test dédié : montée,
handshake, transfert, perte de handshake et déconnexion. Le kill-switch doit
rester engagé avant la montée, après la perte de handshake et après l’arrêt.
Ne pas automatiser cette dernière étape contre une gateway de production : elle
modifie réellement son pare-feu et son interface WireGuard.
