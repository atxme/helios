# Développer sur WSL2

Le kernel Microsoft de WSL2 n'embarque pas tout le plan de données IPsec. Ce
document liste ce qui se teste ici et ce qui doit attendre la machine dédiée.

## Diagnostic constaté sur cette machine

| Élément                         | WSL2            | Conséquence                          |
|---------------------------------|-----------------|--------------------------------------|
| `xfrm_user`, `/proc/net/xfrm_stat` | présents     | l'interface de contrôle XFRM existe  |
| modules `esp4` / `esp6`         | non chargés     | pas de chiffrement ESP réel          |
| `nf_tables`                     | absent          | pas de kill-switch réel              |
| `nft`, `swanctl`, `charon`      | non installés   | pas de plan de contrôle réel         |

## Ce qui se teste sur WSL2 (≈ 80 % du code)

- la **machine à états** du tunnel (`helios-core`) ;
- le **codec VICI** complet, par round-trip (`helios-vici`) ;
- le **rendu des règles** du kill-switch selon l'état (`helios-firewall`) ;
- toute l'**orchestration** en `dry_run` (`heliosd`), y compris la simulation de
  montée du tunnel et la boucle OTA simulée.

```sh
cargo test                                          # 13 tests, 0 dépendance système
cargo run -p heliosd -- --config config/helios.toml run
```

## Ce qui exige la machine dédiée

- le backend **Netlink** réel (`--features netlink`, nécessite `libnftnl`/`libmnl`) ;
- la **négociation IKE** réelle via charon ;
- le **tunnel chiffré** de bout en bout (XFRM/ESP) ;
- la mesure de **performance** Gigabit (IRQ, Realtek RTL8111HS) ;
- l'**OTA RAUC** réel (slots A/B, bootloader).

Bascule : mettre `dry_run = false` dans `helios.toml` et compiler
`--features netlink`. Voir [`scripts/setup-target.sh`](../scripts/setup-target.sh).
