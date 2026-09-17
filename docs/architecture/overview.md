# Vue d'ensemble de l'architecture

Cette page décrit l'architecture observée dans le dépôt. Elle ne propose pas
de nouvelle organisation ; les décisions et leur historique sont dans
[`docs/adr/`](../adr/).

## Composants

```text
Orion (React/Tauri, orion-core)
        │ QUIC/mTLS avant le tunnel
        ▼
heliosd ── helios-key-negotiation ── helios-provisioning
   │
   ├── helios-api ── web (React/MUI)
   ├── helios-wireguard ── WireGuard du noyau ou backend configuré
   ├── helios-firewall ── nftables
   ├── astra / aether
   ├── helios-tpm / helios-vault / helios-escrow
   └── helios-update
```

- `aether` fournit les types, états, politiques et contrats crypto/protocole
  partagés.
- `heliosd` orchestre le démarrage de la gateway, la configuration, le plan de
  données, l'API et les services associés.
- `helios-wireguard` configure les pairs et observe l'état WireGuard ;
  `helios-firewall` construit et applique les règles nftables.
- `helios-provisioning` gère l'admission, l'IPAM et les sessions ML-KEM ;
  `helios-key-negotiation` porte le transport QUIC/mTLS de négociation v5.
- `helios-api` expose l'API Axum/WebSocket et l'interface web embarquée ; `web`
  est la console React/MUI.
- `astra` coordonne le cycle de vie des certificats et la confiance ;
  `helios-tpm`, `helios-vault` et `helios-escrow` gèrent respectivement le
  matériel TPM, les secrets chiffrés et le séquestre opérateur WireGuard.
- `helios-update` traite les mises à jour signées et le rollback.
- `orion-core` porte la logique cliente portable ; `apps/orion` fournit le shell
  React/Tauri et les intégrations de plateforme.
- `helios-ctl`, `astra-signer`, `helios-publisher`, `helios-installer` et
  `xtask` sont les outils opérateur, éditeur, installation et build.

## Dépendances et flux principaux

Le workspace Cargo relie les crates partagées aux services de la gateway, aux
outils et au shell Tauri. Les deux interfaces JavaScript ont chacune leur
`package.json` et leur lockfile.

Avant le trafic WireGuard, Orion utilise le service de négociation QUIC/mTLS.
Le trafic et l'administration passent ensuite par WireGuard. La gateway
observe les handshakes du plan de données et applique une politique réseau
fail-closed ; les détails normatifs figurent dans les ADR et spécifications
existants.
