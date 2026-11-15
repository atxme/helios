# F14 lot 7 : retrait d'`astra-signer` et de `helios enroll document`

*Conception du 15 novembre 2026. Dernier lot de F14 (spec
`2026-10-27-orion-seul-client-design.md`, §7, lot 7), après F14-e et F14-f, fusionnés
(`main` à Helios 3.5.0 / Orion 4.5.0). Branche `feat/f14-lot7-retrait-astra-signer`.*

## 1. Intention

Règle du 24 octobre 2026 : côté poste, opérateur compris, aucun binaire livré à part
d'Orion. Les lots 1 à 6c, F14-e, F14-f et F14-g ont porté dans Orion toutes les
cérémonies d'`astra-signer` dont un composant du dépôt lit le résultat. Le lot 7 retire
`tools/astra-signer` et la sous-commande `helios enroll document`, et fait disparaître
toute indication qui renvoie encore à eux.

Un trou subsiste, trouvé pendant la conception : **Orion ne signe le document `.orion`
d'un poste que tunnel monté** (`draft_delivery`, `ceremony.rs` : « aucune gateway n'est
connectée pour lire sa matière »). Sans gateway joignable, l'acceptation s'arrête après
les feuilles et `admission.txt`, et « Reprendre » s'arrête au même endroit. Le premier
administrateur d'un domaine n'a pas de tunnel : aujourd'hui `target-bootstrap.sh` le fait
passer par `astra-signer enroll accept`, puis `helios enroll document` hors ligne
(certificats lus par SSH, VIP, `heliosd show-trust-enrolment`), puis `astra-signer enroll
sign-document`. **Choix de l'utilisateur (option A, approche 1)** : « Reprendre » sans
gateway accepte un fichier unique que la gateway imprime, et Orion signe le document.

## 2. Objectifs, non-objectifs, anti-objectifs

**Objectifs**

- Le premier administrateur s'enrôle depuis Orion seul, sans tunnel : invitation (feuille
  PQ par fichier, déjà livré), acceptation (s'arrête après les feuilles), `heliosd peer
  add --admin` puis la nouvelle commande d'export sur la gateway, « Reprendre » avec ce
  fichier.
- `tools/astra-signer` et `helios enroll document` n'existent plus : ni crate, ni
  sous-commande, ni entrée de CI, ni dépendance.
- Plus aucun message montré à une personne (console d'Astra, `heliosd`, Orion, scripts)
  ne dit de lancer `astra-signer` ou `helios enroll document` ; chacun nomme le geste
  d'Orion qui le remplace.
- La documentation décrit l'état après retrait.

**Non-objectifs**

- Porter les modes qu'aucun composant ne lit, ou qui n'ont pas d'usage sans
  `astra-signer` ; ils disparaissent avec lui (§4.4).
- Changer un format signé, une constante de séparation de domaine, ou la lecture des
  fichiers qu'un ancien `astra-signer` a laissés à côté du coffre.
- Retirer des commandes de `heliosd` autres que `show-trust-enrolment` : les
  `install-*` restent le recours sur la gateway (F14-e écrit encore un fichier pour
  `install-ca-transition`, la console d'Astra rend des décisions à appliquer).
- Une origine HTTPS publique pour les cérémonies d'Orion : elles passent par le tunnel,
  comme depuis le lot 5a.

**Anti-objectifs**

- Aucun secret dans le fichier d'export : il ne contient que des valeurs publiques, et
  rien ne le lit avant la vérification de §4.2.
- Un document signé hors ligne n'est jamais moins vérifié qu'en ligne : mêmes contrôles,
  même épingle de l'invitation.
- Aucune régression de la reprise en ligne, ni de l'enrôlement par l'API.

## 3. Approches considérées

Pour le premier administrateur :

- **A, un fichier imprimé par la gateway, lu par « Reprendre »** — retenue par
  l'utilisateur.
- B, documenter un autre chemin donnant un tunnel au poste : il n'y en a pas dans le
  dépôt.

Pour la forme du fichier :

1. **Une commande `heliosd`, un seul fichier** — retenue par l'utilisateur : rien à
   retaper, le port de négociation est connu, `show-trust-enrolment` est remplacé.
2. Les quatre entrées séparées de `helios enroll document` (deux certificats, VIP tapée,
   bloc de confiance) : quatre choix à l'écran, VIP mal tapée découverte à la connexion,
   port de négociation inconnu. Écartée.

## 4. Conception

### 4.1 L'export d'enrôlement (`heliosd`)

- Nouvelle commande **`heliosd export-enrolment --public-key <clé WireGuard du pair,
  base64>`** *(nom : mon choix)*. Elle imprime sur la sortie standard un JSON public,
  sans démon ni réseau, depuis les fichiers locaux de la gateway, comme
  `show-trust-enrolment` aujourd'hui.
- Contenu, **les mêmes valeurs que la lecture en ligne** (`orion_core::gateway_admin::
  gateway_material`, qui lit `/api/key-negotiation`, la vue réseau et
  `/api/key-negotiation/trust-enrolment/<clé>`), construites par les mêmes fonctions que
  ces routes *(mon choix : une seule source pour les deux chemins)*. Les sources locales
  existent : la matière de négociation vient des fichiers
  `/var/lib/helios/key-negotiation-cert.der` et `key-negotiation-pq-cert.json` (comme
  `key_negotiation_get`, `helios-api/src/routes/status.rs`) et le port de
  `network.toml` ; l'admission vient de `network.toml` (`NetworkConfig`, que
  `heliosd peer add` écrit, même démon arrêté) ; le bloc du registre de certificats, comme
  `show-trust-enrolment`. Contenu :
  - la matière de la gateway : `server_name`, certificat TLS de négociation (DER, base64),
    feuille PQ (JSON), clé publique WireGuard, empreinte SHA-256 de la feuille PQ, port de
    négociation ;
  - l'admission du pair : `address`, `address_v6` si le pair en a une, l'URL de l'API dans
    le tunnel (`heliosd_url`, dérivée de l'adresse WireGuard de la gateway comme en ligne) ;
  - le bloc de confiance du §19 (`TrustEnrolmentView`), **obligatoire** : sans domaine de
    confiance, ou pour un pair que le registre ne connaît pas, la commande refuse avec la
    phrase de `show-trust-enrolment` *(mon choix : `build_draft` refuse déjà un brouillon
    sans bloc, `enrollment_draft.rs:78`, donc un export sans bloc ne servirait à rien)*.
- **Identité WireGuard de la gateway** : en ligne, `negotiate` compare la clé que lie la
  feuille PQ à celle de la vue réseau, dérivée de la clé privée en cours. Hors démon, la
  clé privée peut être scellée et illisible : l'export porte la clé que lie la feuille PQ
  (signée sous `CA-PQ`), et la commande la compare à `network.toml` seulement si la clé
  privée s'y lit en clair, refus si elles diffèrent *(mon choix)*. Orion la contrôle
  ensuite contre l'épingle de l'invitation (§4.2).
- Le JSON porte un champ `format` à valeur fixe (`"helios-enrolment-export-v1"`, *mon
  choix*), refusé s'il diffère. Champs inconnus refusés. Le type vit dans un crate que
  `heliosd` et `orion-core` partagent déjà (lieu laissé au constructeur), un seul type pour
  écrire et lire.
- Refus : clé illisible ; pair absent de `network.toml` (« admettez-le d'abord, avec
  `heliosd peer add` ») ; matière de négociation absente (`heliosd init-key-negotiation`
  pas fait). Messages en anglais, comme le reste de `heliosd`.
- **`heliosd show-trust-enrolment` est retiré** : son seul lecteur était
  `helios enroll document`. Le bloc de confiance est dans l'export.

### 4.2 « Reprendre » avec le fichier d'export (Orion)

- `EnrollmentGesture::Resume` gagne le contenu facultatif d'un fichier d'export, choisi
  par le même mécanisme que la feuille PQ de l'invitation : la WebView lit le fichier
  public et en passe le texte (`EnrollmentOperatorPanel.tsx`, comme `gateway_pq_certificate`
  pour « Inviter un poste… »). Le dialogue de « Reprendre » offre ce choix de fichier, avec
  une phrase : « Sans tunnel : le fichier de `heliosd export-enrolment`. » *(texte : mon
  choix)* ; `types.ts`, `api.ts` et leurs tests suivent.
- **Tunnel monté** : rien ne change ; le fichier, s'il est fourni, est ignoré *(mon
  choix : la gateway connectée fait foi)*.
- **Sans gateway, avec le fichier** : la reprise lit la matière et l'admission dans le
  fichier au lieu de l'API, puis suit exactement le chemin en ligne :
  - `GatewayPin::check` : la clé WireGuard et le nom de service du fichier sont ceux que
    l'invitation épingle, sinon refus avant toute clé ;
  - la feuille PQ du fichier est vérifiée sous la `CA-PQ` du relais, et son empreinte
    recalculée, avant toute clé ;
  - la clé WireGuard du pair dans l'export est celle de la demande acceptée, sinon refus ;
  - le bloc de confiance est contrôlé comme en ligne (domaine et `CA-PQ` du relais) ;
  - l'admission est sautée, par le chemin existant d'un pair déjà admis (`admit: false`) :
    la présence du pair dans l'export prouve qu'il est admis ;
  - le brouillon est construit par le même `build_draft`, depuis la même matière et la
    même admission, que la source soit l'API ou le fichier (la forme interne de
    `Delivery` est laissée au constructeur) ;
  - puis une clé, la signature du brouillon sous `CA-PQ` et le dépôt du `.orion`, comme
    en ligne.
- **Sans gateway ni fichier** : comme aujourd'hui, arrêt avec les feuilles et
  `admission.txt`.
- Les refus réutilisent les classes existantes (gateway différente de l'invitation,
  `DocumentNotSigned`) ; un fichier illisible ou d'un autre format dit « Ce fichier n'est
  pas un export d'enrôlement de `heliosd export-enrolment`. » *(texte : mon choix)*.
- **`admission.txt`** contient, après la ligne `heliosd peer add …`, la ligne
  `heliosd export-enrolment --public-key <clé> > <nom>.enrolment.json` et une phrase :
  ajouter `--admin` pour le premier administrateur, puis « Reprendre » avec ce fichier.
- La WebView ne reçoit que l'état de la cérémonie et le document produit, comme
  aujourd'hui ; le fichier d'export, public, ne contient aucun secret.
- **Ce que le fichier peut tromper** : la feuille PQ et la clé WireGuard sont liées par
  `CA-PQ` et l'épingle de l'invitation. Le certificat TLS de négociation, le port et
  `heliosd_url` ne sont liés à rien de signé, ni en ligne ni dans l'ancien
  `helios enroll document` hors ligne, qui lisait le même certificat par SSH. Un fichier
  faux sur ces trois valeurs donne un poste qui ne se connecte pas (la négociation v5
  authentifie la gateway par sa feuille PQ), pas un poste détourné. Aucune liaison
  nouvelle *(mon choix)* ; la limite est écrite dans OPERATOR-TOOLING.

### 4.3 Ce qui est retiré

- `tools/astra-signer` : le crate, son entrée dans `Cargo.toml` (membres du workspace),
  `Cargo.lock`, `scripts/ci-plan.py`, la ligne d'`AGENTS.md` qui le liste parmi les
  outils.
- `helios enroll document` : `tools/helios/src/enroll.rs`, la sous-commande et ses tests.
  Le reste de la CLI `helios` reste. `orion_core::enrollment_draft` reste (Orion s'en
  sert).
- `heliosd show-trust-enrolment` (§4.1).
- Les dépendances que seul `astra-signer` tirait, s'il y en a (à constater dans
  `Cargo.lock`) ; une dépendance qu'un autre crate utilise reste.

### 4.4 Ce qui disparaît sans successeur, et pourquoi

- `devices` : diagnostic HID ; Orion passe par l'API du système.
- `approve` par fichier, hors tunnel, et `approve-campaign` hors ligne : aucun composant
  ne lit leur fichier (lot 4).
- Le transport HTTPS public (`--authority-url`) de `recover` et des campagnes : Orion
  passe par le tunnel (lot 5a).
- Une acceptation faite par la CLI ne se reprend pas dans Orion (déjà vrai) : son
  invitation est à refaire.
- Le recours `astra-signer rotate-ca-pq` sur un journal CA-PQ adopté du fichier d'un
  ancien `astra-signer` et en désaccord avec le domaine : la phrase d'arrêt d'Orion devient
  « Domaine en désaccord. Intervention manuelle requise. », comme pour les autres journaux
  *(mon choix)*. Le champ `offline` de la vue de journal reste (il commande d'autres
  comportements) ; seuls sa documentation et cette phrase changent.

### 4.5 Messages qui renvoient à `astra-signer`

Chaque message montré à une personne qui nomme `astra-signer` ou `helios enroll
document` nomme à la place le geste d'Orion, par son onglet et son bouton. Inventaire de
départ (à compléter par recherche, hors `docs/audits` et hors commentaires historiques des
journaux) :

- console d'Astra : `commands/campaign.rs`, `commands/gateway_identity.rs`,
  `commands/revocation.rs`, `commands/issuer.rs`, `door/mod.rs`, `daemon.rs`,
  `renewal/mod.rs` ;
- `heliosd` : aide d'`init-trust-domain` (ancre CA-PQ, feuille PQ, RP ID, CA-TLS),
  `install-astra-credentials` ;
- `tools/helios/src/profile.rs` (« `helios enroll document`, puis … ») et
  `tools/helios/src/main.rs` (aide qui cite `show-trust-enrolment`) ;
- `crates/orion-core/src/config.rs` (« Le réimprimer avec `heliosd show-trust-enrolment
  --public-key <clé>` » devient `heliosd export-enrolment --public-key <clé>`) et son test
  `config/tests.rs` ;
- `crates/heliosd/src/commands/trust.rs` (commentaires et messages autour de
  `show-trust-enrolment`) ; `crates/astra/src/main.rs` (aide qui cite `astra-signer
  issue-ca-tls`) ;
- Orion : `DomainCreated.tsx` (`astra-signer issue-gateway-bootstrap`), `rotationRows.ts`
  (§4.4) ;
- scripts : `deploy.sh`, `provision-client.sh`, `key-negotiation-setup.sh`,
  `target-bootstrap.sh`, `setup-dev.sh` (commentaire `hidapi`), `deploy/astra/Dockerfile`,
  `deploy/astra/compose.yaml`.

Les commentaires de code qui expliquent un format laissé par un ancien `astra-signer`
(journaux, fichiers adoptés) restent, au passé. La constante
`helios-astra-signer-request-v5` ne change pas (séparation de domaine signée).

## 5. Ce qui ne change pas

Formats signés et fichiers à côté du coffre ; lecture des journaux laissés par un ancien
`astra-signer` ; enrôlement en ligne ; commandes `heliosd install-*` ; CLI `helios` hors
`enroll document` ; `orion_core::enrollment_draft`.

## 6. Documentation

- `OPERATOR-TOOLING.md` : la section « CLI transitoire » disparaît ; l'enrôlement du
  premier administrateur sans tunnel est décrit (export, « Reprendre » avec le fichier) ;
  « Hors périmètre » mis à jour.
- `RENOUVELLEMENT-CERTIFICATS.md`, `DEPLOIEMENT-ASTRA.md`, `ROTATION-CERTIFICATS.md`,
  `NEGOCIATION-DE-CLE-V5.md`, ADR-008, `CRATE-REORGANIZATION.md`, `overview.md`,
  `TESTING.md` : les recettes en ligne de commande `astra-signer` sont remplacées par le
  geste d'Orion ou retirées ; les exemples `heliosd install-*` restent avec la source
  du fichier (Orion, console d'Astra).
- `MANUAL-TESTING.md` : section « N. Lot 7 » (premier administrateur sans tunnel ; refus
  d'un export d'une autre gateway ; d'un export d'un autre pair ; reprise en ligne
  inchangée), et les étapes qui lancent `astra-signer` sont réécrites.
- `ROADMAP.md` : F14 complet (lot 7 livré sur sa branche) ; la ligne F14-f dit qu'il est
  fusionné (15 novembre 2026, Helios 3.5.0 / Orion 4.5.0).
- Spec F14 (`2026-10-27-orion-seul-client-design.md`) : amendement du 15 novembre 2026
  sous le lot 7 (export d'enrôlement).
- `docs/audits` n'est pas touché.

## 7. Tests attendus

- `heliosd export-enrolment` : un pair admis donne un export dont la matière et
  l'admission sont égales à ce que lisent les routes en ligne pour le même état ; pair
  absent refusé ; sans domaine de confiance, refusé ; clé illisible refusée ; feuille PQ
  qui ne lie pas la clé de `network.toml` lisible en clair, refusée.
- Lecture de l'export : `format` différent refusé, champ inconnu refusé, aller-retour
  exact.
- Reprise Orion sans gateway avec export : document signé, égal à celui de la reprise en
  ligne pour le même état (même brouillon) ; export d'une autre gateway refusé avant toute
  clé ; export d'un autre pair refusé avant toute clé ; feuille PQ qui ne vérifie pas sous
  `CA-PQ` refusée avant toute clé ; bloc de confiance d'un autre domaine refusé ; sans
  fichier, arrêt avec les feuilles comme avant ; tunnel monté, le fichier ignoré.
- `admission.txt` porte la ligne d'export.
- Plus aucune mention d'`astra-signer` ni de `helios enroll document` dans un message
  montré à une personne (recherche dans la CI ou un test, *mon choix*, hors commentaires
  et `docs/audits`) ; le workspace se construit sans `tools/astra-signer`.

## 8. Laissé au constructeur

Noms internes, crate du type d'export, placement des tests, découpage des commits, texte
exact des messages de console d'Astra (en anglais ou en français selon le fichier, comme
aujourd'hui), forme de la recherche qui garde les messages.
