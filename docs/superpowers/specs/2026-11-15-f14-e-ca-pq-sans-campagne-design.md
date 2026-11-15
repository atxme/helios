# F14-e — Remplacer la CA-PQ sans campagne, dans Orion

Conception du 15 novembre 2026. Suivi F14-e de la ROADMAP (spec 5b, amendement
du 7 novembre 2026). Branche `feat/f14-e-ca-pq-sans-campagne`.

## 1. Intention

Le lot 7 retire `astra-signer`. Sa commande `rotate-ca-pq` a deux formes :

- **en campagne** (`--authority-url --operation-id`) : Orion la remplace depuis
  le lot 5b (« Remplacer la CA-PQ », onglet *Rotations*), et il reprend même les
  journaux qu'elle laisse en lisant Astra d'abord ;
- **hors campagne** : pour un domaine dont le relais ne nomme aucune origine
  Astra. Deux clés, la signature, puis le coffre, les credentials et le relais
  avancent, et la transition est écrite dans un fichier qu'on installe sur la
  gateway (`heliosd install-ca-transition`, écran *Certificats*, ou
  `POST /api/certificates/ca-transition`). Sa reprise fait avancer le coffre
  sans parole d'Astra, par le geste voulu de l'opérateur : c'est l'exception à
  « le coffre ne bouge qu'après l'acceptation » notée en spec 5b.

Orion n'a aucun équivalent de la forme hors campagne. Décision de l'utilisateur
(15 novembre 2026) : **après le lot 7, un domaine sans Astra doit encore pouvoir
changer d'ancre CA-PQ**, depuis Orion. F14-e nomme et livre ce successeur.

Le précédent est le lot 4 : « Signer une délégation sans campagne » a été porté
parce que c'était le seul chemin d'un domaine sans origine joignable, offert
seulement sans origine dans le relais et sous avertissement ; l'approbation hors
ligne ne l'a pas été, parce que rien ne lisait son fichier. La transition
`CA-PQ`, elle, est lue par la gateway : le premier cas s'applique.

## 2. Buts, non-buts, anti-buts

**Buts**

- Un geste « Remplacer la CA-PQ sans campagne… » dans *Rotations*, offert
  seulement quand le relais ne nomme **aucune** origine Astra.
- Deux clés distinctes, la signature, le journal, puis le coffre, les
  credentials et le relais avancent par le geste de l'opérateur ; Orion pose
  ensuite la transition sur la gateway **par le tunnel**
  (`Tunnel::install_ca_transition`, déjà utilisé au lot 5b).
- La reprise d'une rotation sans campagne interrompue, sans clé, avec la même
  table que le lot 5b à partir de l'étape « Accepté ».
- La reprise d'un journal **hors campagne** laissé par `astra-signer
  rotate-ca-pq` (`legacy_ca_pq_path_beside`) dans un domaine sans origine.
- Le fichier de transition reste téléchargeable tant que le journal sans
  campagne existe, pour le cas où le tunnel tombe après l'application locale.
- La documentation nomme ce successeur ; F14-e est levé.

**Non-buts**

- Rien ne change pour un domaine **avec** origine Astra : « Remplacer la CA-PQ »
  y reste en campagne, et la reprise y lit Astra d'abord.
- Pas de CA TLS sans campagne : `astra-signer rotate-ca-tls` exige déjà
  `--operation-id`, il n'a pas de forme hors campagne.
- Pas d'« Appliquer quand même » contre Astra : forcer contre une autorité qui
  en sert une autre casserait le parc.
- Le retrait d'`astra-signer` lui-même reste au lot 7. F14-f (copie du coffre)
  est traité à part.

**Anti-buts** (ce qui ferait de F14-e un échec même si le code marche)

- Le bouton ou la cérémonie sans campagne joignable dans un domaine qui nomme
  une origine Astra, même illisible (règle « fail closed » du lot 4).
- Une reprise sans campagne qui lirait Astra, ou attendrait une réponse d'Astra,
  dans un domaine sans origine : elle ne finirait jamais.
- Un journal sans campagne confondu avec un journal « Accepté sans dépôt »
  adopté d'`astra-signer` **en campagne**, qui doit, lui, lire Astra d'abord.
- Un secret (PIN, `Opened`, octets du coffre, clé privée) dans la WebView ou un
  journal de logs.

## 3. Contraintes

- ADR-008 et la spec ROTATION-CERTIFICATS §9.1 : deux clés distinctes pour une
  rotation d'ancre ; les key-slots ne bougent pas.
- Spec 5b : table de reprise §5.4 (§10.3 telle que livrée) ; « le coffre ne
  bouge qu'après l'acceptation » reste la règle pour tout domaine avec origine.
  L'exception de la forme sans campagne est assumée et écrite.
- Lot 5c : le coffre garde la clé `CA-PQ` sortante jusqu'à « Terminer la
  rotation CA-PQ ». Ce geste marche déjà sans Astra (l'envoi de la copie du
  coffre qui le suit tolère un échec).
- `prepare_days` borne la fenêtre où un poste peut revenir chercher la
  transition ; mêmes durées réglables que la rotation en campagne.
- Règles du dépôt : code, commentaires et logs en anglais ; textes à l'écran et
  documentation en français, courts, qui nomment la cause.

## 4. Approches

L'utilisateur a choisi **A** le 15 novembre 2026.

- **A. Par le tunnel (retenue).** Même cérémonie que la rotation du lot 5b, sans
  campagne ni dépôt ; Orion pose la transition par le tunnel ; la reprise sait,
  en lisant la gateway, si elle tient la nouvelle ancre. Coût : un état de plus
  dans la cérémonie de rotation et dans le journal.
- **B. Par fichier seulement** (calque du CLI et du lot 4) : Orion remet
  `ca-pq-transition.json`, l'opérateur l'installe à la main. Plus court, mais le
  coffre a avancé sans que la gateway le sache, et rien ne le signale. Écartée.
- **C. « Appliquer quand même »** pour un domaine avec Astra. Écartée : la
  reprise du lot 5b lit déjà Astra, et forcer contre elle casse le parc.

## 5. Conception

### 5.1 Quand le geste est offert

« Remplacer la CA-PQ sans campagne… » est une ligne de *Rotations*, à côté de
« Remplacer la CA-PQ », offerte **seulement si `relay.astra_authority_url` est
absent**. Avec une origine, même illisible, la ligne n'apparaît pas, et la
cérémonie, si elle était ouverte quand même, refuse avant le choix de clé (même
règle que `IssuerRefusal::OriginRecorded`).

Ses prérequis, lus sans Astra :

- le tunnel est monté (la pose de la transition passe par lui) ;
- aucun journal de rotation n'est en cours (`ensure_nothing_outstanding`) ;
- aucun recouvrement `CA-PQ` n'est ouvert : le coffre ne garde pas de `CA-PQ`
  sortante (`retained_outgoing_ca_pq_public`), sinon « Terminer la rotation
  CA-PQ » d'abord ;
- la gateway ne nomme pas déjà une ancre `CA-PQ` suivante ;
- l'ancre `CA-PQ` courante de la gateway est celle que le coffre détient.

Ces deux lectures de la gateway remplacent, sans origine, les contrôles
`ensure_no_overlap` et `ensure_same_anchors` qui lisent Astra. Elles comparent
des empreintes d'ancre, comme le reste de la rotation. `gateway_next_anchor`
ne suffit pas (il rend `next.unwrap_or(current)`) : il faut une lecture qui
distingue l'ancre courante de la suivante (*mon choix : une méthode de plus sur
`RotationRemote`, à partir de l'identité que la gateway sert déjà*).

**Sans document de credentials.** Un domaine sans Astra n'a en général jamais
émis de document de credentials (le CLI ne l'exige qu'en campagne). La rotation
sans campagne l'accepte absent, comme `signing::rotate_ca_pq` (registre
`Option`) : il n'y a alors pas de document suivant à écrire. Présent, il est
re-signé comme aujourd'hui. *Mon choix : sans cela, le geste exclurait les
domaines qu'il sert.*

Avertissement visible avant les clés, du ton de la délégation sans campagne :
« Aucune autorité ne vérifie ce remplacement : le coffre avance sur votre seul
geste. À réserver à un domaine sans Astra. »

### 5.2 La cérémonie

Même déroulé et même écran que la rotation `CA-PQ` du lot 5b, moins la campagne :

1. Durées (préparation, recouvrement), comme aujourd'hui.
2. Deux clés distinctes validées, comme aujourd'hui, mais **sans assertion
   d'approbation** : il n'y a pas de campagne à approuver. Le contrôle des deux
   clés distinctes et autorisées reste.
3. Signature `signing::rotate_ca_pq` ; le journal est écrit **à l'étape
   « Accepté », sans dépôt, marqué sans campagne** (voir §5.3) : c'est le geste
   de l'opérateur qui tient lieu d'acceptation.
4. Application locale (coffre, credentials, relais), puis lecture de la gateway
   et pose de la transition par le tunnel, puis fin : le journal est effacé,
   **sans envoi de la copie du coffre à Astra** (il n'y en a pas).
5. L'écran final montre l'empreinte de l'ancre entrante (comme au lot 5b, §10.2).

L'ordre reste celui du lot 5b : le coffre d'abord, la gateway ensuite. Le coffre
garde la `CA-PQ` sortante jusqu'à « Terminer la rotation CA-PQ » (lot 5c), donc
une gateway restée sur l'ancienne ancre ne perd rien de ce que le coffre signe.

**Le fichier de transition.** `ca-pq-transition.json` est tiré de
`journal.transition` : il est offert en téléchargement (`OperatorArtifact`)
**tant que le journal sans campagne existe**, c'est-à-dire quand la pose sur la
gateway n'a pas abouti (tunnel tombé, arrêt `GatewayOutdated` ou
`InstallDeadlinePassed`). Une pose réussie efface le journal, et le fichier
n'a plus d'usage. *Mon choix : aucun fichier persistant de plus, aucun état
« en cours » nouveau.*

**Une pose qui échoue après l'application locale.** Le journal reste, la reprise
le rejoue, et les arrêts `GatewayOutdated` et `InstallDeadlinePassed` se lisent
comme au lot 5b, le fichier offert en plus. Passé `activation_at`, la réparation
est celle de F14-a, hors de ce suivi.

### 5.3 Le journal et la reprise

Le journal de rotation porte une marque « sans campagne » (le nom et la forme
sont au constructeur ; un champ absent se lit « en campagne », pour que les
journaux existants ne changent pas de sens). Avec cette marque :

| État du journal | Reprise | Clé ? |
| --- | --- | --- |
| Accepté, sans campagne | applique le coffre, les credentials et le relais (`ApplyLocal`), **sans lire Astra** | non |
| Appliqué | inchangé : lit la gateway, installe, `GatewayOutdated` ou `InstallDeadlinePassed` comme au lot 5b | non |
| (après la pose, sans campagne) | **fin** : le journal est effacé, sans écrire « Installé » ni envoyer de copie du coffre | non |

Sans la marque, la table du lot 5b est inchangée : un journal « Accepté sans
dépôt » adopté d'`astra-signer` en campagne lit Astra d'abord.

La marque est un champ explicite : « sans dépôt » ne suffit pas, puisque c'est
déjà la forme d'un journal adopté en attente de confirmation
(`awaits_confirmation`). Avec la marque, `awaits_confirmation` est faux ; chaque
usage d'`awaits_confirmation` et de `deposit.is_none()` est revu
(`next_step_of_accepted`, `is_deposited`, `apply_local`, `adopt_legacy`,
`ensure_ca_pq_may_run`). Un Orion antérieur qui lirait ce journal le refuse
(`deny_unknown_fields`) plutôt que de le lire en campagne : *mon choix, c'est
l'échec sûr*.

**Journal hors campagne laissé par `astra-signer`.** Le CLI hors campagne
écrit son journal à `legacy_ca_pq_path_beside` (format `CaPqRotationJournal`)
avant d'appliquer. Dans un domaine **sans origine**, Orion l'adopte comme un
journal sans campagne (donc `ApplyLocal` sans lire Astra) ; le fichier de
transition qu'il nomme n'est pas requis, Orion pose la transition par le tunnel.
« Sans origine » se lit sur le relais **en place** à côté du coffre (le CLI ne
change jamais l'origine). Dans un domaine avec origine, l'adoption reste celle
d'aujourd'hui (lecture d'Astra, `DomainConflict` si elle ne tient pas l'ancre).

Une reprise sans campagne n'appelle jamais Astra : aucune lecture de
l'autorité, aucun dépôt, aucune copie du coffre.

### 5.4 Ce qui ne change pas

« Terminer la rotation CA-PQ » (lot 5c), après `not_after`, sert aussi la
rotation sans campagne, tel quel. « Renouveler les postes » reste bloqué
pendant un recouvrement `CA-PQ` (F14-c). La rotation en campagne et son écran
ne changent pas.

### 5.5 Documentation

- `RENOUVELLEMENT-CERTIFICATS.md` : la forme hors campagne de « Remplacer la
  CA-PQ » passe dans Orion ; la limite « Le recours en ligne de commande » dit
  que le successeur est ce geste, et que l'exception à « le coffre ne bouge
  qu'après l'acceptation » ne vaut que sans origine Astra.
- `DEPLOIEMENT-ASTRA.md` et la spec 5b (amendement) : même mention.
- `MANUAL-TESTING.md` : une section de recette pour la rotation sans campagne,
  sa reprise après une coupure du tunnel, et le refus avec une origine.
- `ROADMAP.md` : F14-g se lit fusionné le 14 novembre 2026 (Helios 3.4.0,
  Orion 4.3.0) ; F14-e levé sur la branche.

## 6. Laissé au constructeur

- Le nom et la forme de la marque « sans campagne » dans le journal, et si elle
  demande une version de format (le journal doit rester lisible par la reprise
  du lot 5b).
- Comment l'ouverture sans campagne partage le code de `open_with` sans en
  affaiblir les contrôles (Astra n'est pas lue ; les contrôles d'ancre se font
  contre la gateway et le coffre).
- Les phrases exactes des refus nouveaux, en français, courtes, qui nomment la
  cause.
