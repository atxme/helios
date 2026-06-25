# helios-client (app Tauri)

Client VPN Helios : **vrai client IPsec autonome**. Le backend Rust monte lui-même
le tunnel IKEv2 vers la gateway (par son **endpoint**, IP/FQDN — pas une URL HTTP),
puis ne consomme l'API web de heliosd qu'**une fois le tunnel établi** (le serveur
web vit derrière le tunnel).

## Architecture

- **`apps/helios-client/src-tauri`** — shell Tauri (commandes `invoke`, `emit` des
  événements). Lie `webkit2gtk-4.1` → **ne compile pas sur WSL2** sans les libs système.
- **`crates/helios-client-core`** — toute la logique (profils, backend IPsec,
  télémétrie). **Sans dépendance Tauri**, donc testable partout : `cargo test -p helios-client-core`.

## Développement

```sh
# Logique pure (testable sur WSL2, aucune lib système) :
cargo test -p helios-client-core

# Frontend seul (tsc + vite, pas de webkit) :
npm install && npm run build

# App complète en dev (dry-run par défaut — aucune pile IKEv2 requise).
# Prérequis Linux : sudo apt install libwebkit2gtk-4.1-dev libgtk-3-dev \
#   librsvg2-dev patchelf libayatana-appindicator3-dev
npm run tauri dev
```

## Backends IPsec réels (target-only)

Comme la feature `netlink` côté heliosd, les piles réelles sont derrière des features
et ne se valident que sur la cible (privilèges root/admin requis) :

```sh
cargo build -p helios-client --features linux-strongswan   # strongSwan swanctl/charon
cargo build -p helios-client --features native-windows     # IKEv2 natif Windows
cargo build -p helios-client --features native-macos       # IKEv2 natif macOS
```

> **Post-quantique** : les piles IKEv2 **natives Windows/macOS** ne supportent pas
> l'échange hybride ML-KEM (RFC 9370). Les profils `hybrid`/`full-pqc` exigent
> strongSwan ≥ 6 côté client ; sinon, utiliser le profil `classic`.
