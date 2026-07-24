# AGENTS.md

Instructions pour les agents de code travaillant dans ce dépôt.

## État courant

Helios est une gateway WireGuard Linux ; Orion est son client Tauri ; `aether`
porte les types et contrats communs. La rupture avec IKEv2 est terminée dans le
code. [ADR-001](docs/adr/ADR-001-WIREGUARD.md) conserve le raisonnement de migration
et [ADR-002](docs/adr/ADR-002-SIGNATURES-PQ.md) fixe la signature hybride des
artefacts éditeur. [ADR-004](docs/adr/ADR-004-CHAINE-DE-LIVRAISON.md) fixe le
cycle de vie des secrets et la chaîne de livraison. En cas de doute, le code et
les ADR acceptés font foi.

Le provisioning ML-KEM, l’IPAM et les backends WireGuard existent. Le PSK
post-quantique est négocié et posé de bout en bout : la gateway l’installe sur
le plan de données **avant** de l’annoncer au client, et refuse la demande si
la pose échoue. Trois limites restent explicites : la VIP dérivée par l’IPAM
n’est pas réconciliée avec l’adresse déclarée en config (chaque bout garde la
sienne, l’écart est journalisé) ; le fichier de récupération signé est bloqué
jusqu’au choix du compteur anti-rejeu fichier ou NV TPM ; le **DNS d’un client
n’est pas tunnelé**, même `allow_client_internet` actif — ses requêtes sortent
hors du tunnel (voir le doc-comment de `helios-firewall::ruleset`).

L’outillage d’exploitation existe (ADR-004, lot 1) : `heliosd init-identity`
crée l’identité WireGuard scellée sans jamais l’écrire en clair, `heliosd peer`
et `helios-ctl peer` admettent les clients par le **même** code
(`helios-provisioning::admission`), `helios-ctl profile emit` produit le
document `orion-profile` que l’import Orion consomme, et `helios-ctl escrow`
expose enfin le séquestre.

La gateway se livre en binaires (ADR-004, lot 2) : `cargo xtask bundle` assemble,
`helios-publisher bundle` signe hors ligne, `cargo xtask pack` archive, et
`helios-installer bootstrap` vérifie tout avant d’écrire. `setup-target.sh` ne
compile plus rien. Les installateurs Orion (lot 3) restent à faire.

Le câblage PSK est validé en dry-run seulement. Aucun essai noyau n’a encore eu
lieu — voir [docs/testing/TESTING.md](docs/testing/TESTING.md).

## Invariants de sécurité

- Gateway : seul `TunnelState::Up` autorise le trafic. Engager le kill-switch
  avant tout réseau et le laisser engagé à l’arrêt.
- Hors `--dev`, un backend noyau absent est une erreur de démarrage ; aucun
  repli implicite vers un backend simulé.
- Netlink : traduire tout le ruleset puis envoyer une transaction atomique ; ne
  jamais appliquer règle par règle. Le NAT entre dans la **même** transaction
  que le filtrage : un masquerade qui survivrait au kill-switch laisserait
  sortir en clair ce qu’il vient de couper.
- Orion : lire le doc-comment de `orion-core/src/backend/mod.rs` avant toute
  modification. L’adaptateur reste monté sur échec et `down()` n’est appelé que
  sur déconnexion explicite.
- Un Orion compilé avec `wireguard` refuse de démarrer si le backend réel est
  indisponible ; aucun repli implicite vers le dry-run.
- L’API vit derrière `admin_iface` (`helios0`). Elle ne monte jamais le tunnel
  initial. Toutes les mutations exigent du JSON, aucun CORS permissif, et les
  lectures ne doivent jamais sérialiser clé privée ou PSK.
- PSK post-quantique : toujours posé sur le plan de données **avant** d’être
  annoncé au client, et jamais persisté sur disque. Un slot PSK renseigné d’un
  seul côté fait échouer tous les handshakes, sans canal de rattrapage.
- Billets TPM : Ed25519 **et** ML-DSA-65 obligatoires, `key_epoch` signé,
  trousseau compilé, v1 refusé. Compteur strictement croissant ; PCR facultatif.
- Identité de la gateway : elle naît **sur** la gateway (`heliosd
  init-identity`), scellée au TPM. `wg_private_key` en clair dans
  `network.toml` est un repli hérité, pas un chemin d’installation.
- Admission : jamais de *read-modify-write* de `network.toml` depuis la vue
  expurgée de l’API — les PSK des autres pairs y seraient effacés. Passer par
  `helios_provisioning::admission`, et persister sans clé privée ni PSK.
- Clé privée de séquestre : sur le poste opérateur, jamais sur la gateway
  qu’elle secourt.
- Une release exige `HELIOS_PUBLISHER_KEYRING_PATH`. Les secrets éditeur ne
  doivent jamais entrer dans une gateway ni dans le dépôt.

## Interdiction des TODO

Aucun marqueur `TODO`, `FIXME`, `XXX`, `HACK`, `TBD`, `todo!()` ni
`unimplemented!()` ne doit être introduit dans ce dépôt. Un marqueur est une
dette invisible : il ne compile aucun test, ne bloque aucune release et sort du
champ de vision dès la revue suivante.

Face à une fonctionnalité incomplète, trois issues seulement :

1. **La développer** — c’est le défaut. Si la tâche est faisable, la faire
   plutôt que de la baliser.
2. **La refuser explicitement dans le type** — variante d’erreur nommée et
   documentée (modèle : `helio_tpm::TpmError::NotImplemented`), testée, qui
   échoue franchement à l’exécution. Jamais un chemin silencieux ou dégradé.
3. **La documenter comme limite connue** — section « Limite connue » dans le
   doc-comment du module, plus une ligne dans l’ADR concerné si elle engage
   l’architecture. Le texte doit dire *pourquoi* c’est hors périmètre et *ce
   qui débloquerait*, pas seulement que ça manque.

Un blocage qui attend un arbitrage humain (ADR-002 amendement 2) relève du
point 3, pas d’un `TODO`. Une limite matérielle non vérifiable en WSL2 relève
du point 3 et de [docs/testing/TESTING.md](docs/testing/TESTING.md).

Si une limite documentée est visible par l’utilisateur, l’IHM doit la dire —
c’est déjà la pratique dans `web/src/views/Firewall.tsx` et
`apps/orion/src/views/ProfilesView.tsx`.

## Workspace

- `aether` : états, config, politique, ML-KEM, protocole et signatures hybrides.
- `helios-firewall` : ruleset structuré, dry-run, backend Netlink.
- `helios-wireguard` : interface gateway et table de pairs.
- `helios-provisioning` : IPAM CGNAT et rotation/protocole ML-KEM.
- `helios-api` : Axum REST/WS, provisioning et IHM embarquée.
- `helio-tpm` : scellement PCR, séquestre et billets de rescellement.
- `helios-update` : mises à jour applicatives signées (ADR-003).
- `heliosd` : orchestration gateway.
- `orion-core` / `apps/orion` : cœur client et shell Tauri React.
- `xtask` : fabrique de bundles d’installation (poste de build, jamais la
  gateway) — `cargo xtask bundle`, `cargo xtask pack`.
- `helios-ctl` : outil du **poste opérateur** — diagnostic, campagnes de bout en
  bout (`campaign`, agit en vrai client via `orion-core`), admission (`peer`),
  profils clients (`profile`) et séquestre (`escrow`) ;
  `helios-publisher` : outil du **poste éditeur**, hors gateway.

## Développement et validation

```sh
bash scripts/regression.sh
bash scripts/campaign.sh          # campagnes PQ, mise à jour signée et bundle
bash scripts/lab.sh --keep        # banc complet : gateway + client admis + profil
./scripts/deploy.sh               # construit, signe, copie et installe sur la gateway
cargo test --workspace --all-features
cargo run -p heliosd -- run --dev
npm run dev --prefix web
```

`scripts/regression.sh` est la référence : fmt, Clippy/tests toutes features,
audits Cargo/npm, Vitest et builds frontend.

**Langue.** Tout ce qui est du code est en **anglais** : noms de fonctions, de
types, de champs et de variables (`render`, `assign_vip`, `verify_manifest`),
mais aussi les commentaires, les doc-comments, les messages de journal et les
noms de tests. Seule la documentation sous `docs/` (ADR, guides, `TESTING.md`)
reste en **français**.

`scripts/deploy.sh` enchaîne ce que l'ADR-004 sépare en trois outils — construire,
signer hors ligne, archiver — puis copie et installe. La séparation garde son
sens pour une release publique ; pour un opérateur qui détient les trois rôles,
la retaper à chaque fois n'apporte rien. La séquence de release est un
horodatage : l'anti-rollback exige une valeur strictement croissante, et un
compteur local se désynchronise dès qu'on déploie depuis une autre machine.

`scripts/lab.sh` monte un banc jetable avec les **mêmes outils qu'en
production** — `helios-ctl peer add`, `helios-ctl profile emit` — et non un
chemin de test parallèle : il éprouve donc l'outillage d'exploitation en même
temps qu'il sert au développement. Il produit un profil directement importable
dans Orion. Il ne fait pas partie de la régression : celle-ci vérifie des
invariants, elle ne lance pas d'environnements.

WSL2 compile les features `netlink`, `wireguard` et `tpm` si leurs dépendances
sont installées, mais ne prouve pas leurs effets réels. Les essais noyau, TPM,
WireGuard-NT et l'installation d'une release sont target-only ; suivre
[docs/testing/TESTING.md](docs/testing/TESTING.md).

Features matérielles :

```sh
cargo build -p heliosd --features netlink,wireguard,tpm,embed-ui
cargo build -p orion --features wireguard
```

Une release gateway se construit seulement après le frontend et avec le
trousseau public éditeur :

```sh
npm run build --prefix web
HELIOS_PUBLISHER_KEYRING_PATH=/chemin/public/publisher-keyring.json \
  cargo build --release -p heliosd --features netlink,wireguard,tpm,embed-ui
```

Ne pas « compléter » le lot récupération de l’ADR-002 tant que l’amendement 2
n’a pas été arbitré. Ne jamais présenter une compilation WSL2 comme une
validation matérielle.
