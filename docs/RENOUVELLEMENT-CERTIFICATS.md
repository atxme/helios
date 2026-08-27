# Renouveler un certificat Helios : toutes les commandes

Aide-mémoire d'exploitation. Chaque section couvre **un** objet du domaine :
ce qui le fait tourner, qui doit être présent, et ce qui se passe si on ne fait
rien. La référence normative reste
[ROTATION-CERTIFICATS.md](specification/ROTATION-CERTIFICATS.md) ; ce document
ne décide rien, il ordonne des gestes.

## Ce qui n'a besoin d'aucune commande

Quatre choses tournent sans qu'un opérateur intervienne, et c'est voulu :

- **la feuille cliente d'un poste allumé.** À 80 % de sa vie, Orion propose
  « Renouveler maintenant » ; l'utilisateur clique, un opérateur approuve, le
  poste committe. C'est le chemin ordinaire du §7 ;
- **la confiance d'un client en retard.** À chaque montée de tunnel, Orion
  demande une fois à la gateway s'il lui manque quelque chose. Ce qui revient
  est signé, ordonné, et n'est appliqué qu'entier ;
- **la purge** des étapes de staging qu'aucun client n'a committées.
- **la promotion d'une identité gateway publiée.** Un redémarrage dans le
  recouvrement charge la candidate ; à `not_after`, la maintenance synchronise
  la génération active puis détruit définitivement l'ancienne clé scellée.

Tout le reste ci-dessous est une action délibérée.

## 1. Renouveler la feuille d'un poste (§7.1 → §7.3)

Le cas courant. Rien à faire côté gateway.

**Sur le poste**, dans Orion, destination *Certificats* : « Renouveler
maintenant ». Orion affiche un identifiant d'opération et la ligne de commande
exacte du compagnon.

**Sur le poste de l'opérateur**, avec la clé de sécurité :

```sh
astra-signer approve --heliosd-url https://<gateway-dans-le-tunnel> \
  --operation-id <identifiant>
```

Puis, dans Orion, cliquer une seconde fois sur « Renouveler maintenant » : la
session reprend et committe. Un second clic ne rouvre jamais une deuxième
opération — c'est ce que la session en mémoire garantit.

Pour avancer **tous** les profils Helios de l'appareil d'un pas :
« Renouveler tous les profils Helios de cet appareil ». Chaque profil garde sa
propre attente ; le refus de l'un n'arrête pas les autres.

## 2. Renouveler tout un parc en une fois (§7.6)

Une campagne autorise des rotations à l'avance. Elle **ne renouvelle pas** les
postes : elle dispense chaque poste couvert de redemander une approbation.

**Sur la gateway**, dans le conteneur Astra :

```sh
astra campaign open --scope fleet-leafs \
  --reason "campagne trimestrielle" --requested-by "prénom.nom" \
  --window-secs 300
# → imprime un identifiant d'opération
```

**Sur le poste de l'opérateur** :

```sh
astra-signer approve-campaign --authority-url https://astra.exemple \
  --operation-id <identifiant>
```

Ensuite, chaque poste couvert qui envoie sa demande dans la fenêtre est
renouvelé sans qu'on lui redemande rien — la campagne surcharge aussi le seuil
de 80 %, ce qui est précisément à quoi sert une action manuelle.

**La fenêtre est de 300 secondes au plus.** Un poste éteint pendant ces cinq
minutes n'est pas renouvelé : l'opérateur rouvre une campagne. Une autorisation
qui survivrait au texte que son opérateur a lu ne serait plus la même chose.

## 3. Faire tourner l'ancre `CA-PQ` (§9.1)

L'opération la plus lourde du domaine : tout ce qui est signé sous l'ancienne
ancre cesse de vérifier à la fin du recouvrement. Deux clés de sécurité
distinctes sont exigées.

**Sur la gateway** :

```sh
astra campaign open --scope trust-authorities \
  --reason "rotation annuelle de l'ancre" --requested-by "prénom.nom"
# → imprime un identifiant d'opération
```

**Sur le poste de l'opérateur** :

```sh
astra-signer rotate-ca-pq --out ca-pq-transition.json \
  --authority-url https://astra.exemple --operation-id <identifiant> \
  --prepare-days 7 --overlap-days 30
```

Le compagnon compare la cible de la campagne à l'ancre de son propre coffre
avant de demander quoi que ce soit : deux moitiés du domaine qui se
contredisent sur ce qui est courant s'arrêtent, elles ne se réconcilient pas
par une rotation. Les deux clés restent branchées pour leurs deux gestes
chacune.

**`--prepare-days` est la fenêtre dont chaque poste dispose pour revenir.**
§8.1.1 refuse une transaction passée sa première activation : un poste qui se
connecte après ce délai ne recevra plus la transition et se répare par
l'opérateur. Sept jours est un défaut raisonnable pour un parc dont une part
n'est pas allumée tous les jours ; un jour ne l'est pas.

**Limite connue** : le domaine n'adopte pas de lui-même l'ancre distribuée. Les
clients l'appliquent ; le registre Astra et l'épinglage de la gateway restent
sur l'ancre sortante jusqu'à ce que l'opérateur les avance.

## 4. Renouveler la délégation d'émission Astra (§9.5)

L'émetteur délégué est ce qui permet à Astra de renouveler les feuilles
clientes **en ligne**, sans ouvrir le coffre. Il porte sa propre échéance.

**Sur la gateway** :

```sh
astra issuer request --out issuer-request.json
```

**Sur le poste de l'opérateur** (le fichier voyage par un canal quelconque —
il est public) :

```sh
astra-signer authorize-issuer --request issuer-request.json \
  --out issuer-authorization.json --days 30 --leaf-days 90
```

**Sur la gateway** :

```sh
astra issuer install --authorization issuer-authorization.json
```

Chaque installation doit faire **avancer** l'époque : réinstaller une époque
déjà employée ferait revenir un intermédiaire retiré sous une signature encore
parfaitement valide.

**Limite connue** : ce geste ne porte encore aucune campagne, donc il passe par
des fichiers plutôt que par les routes à jeton du §8.2.

## 5. Récupérer une identité expirée (§7.5)

Quand un poste est resté éteint trop longtemps, sa feuille a expiré : plus
aucun tunnel, donc plus aucun chemin de renouvellement ordinaire. La
récupération est le seul retour, et elle exige que **la clé privée expirée
existe encore**.

**Sur le poste**, dans Orion : « Récupérer le certificat expiré ». Orion
affiche un identifiant. Il n'y a plus aucun canal automatique entre le poste et
l'opérateur — l'identifiant se lit à voix haute, se copie dans un message, peu
importe : il n'autorise rien à lui seul.

**Sur le poste de l'opérateur** :

```sh
astra-signer recover --authority-url https://astra.exemple \
  --operation-id <identifiant> --validity-days 365
```

Le compagnon affiche le pair, la génération et depuis combien de temps elle est
expirée, **avant** de demander le toucher. Puis, dans Orion, cliquer une
seconde fois : le poste installe sa nouvelle génération et son commit repart
par Astra, qui le relaie à la gateway sur le canal privé.

**Si la clé privée expirée a disparu** avec le stockage protégé qui la tenait,
Orion le dit et s'arrête : il reste une réadmission opérateur à deux clés, qui
crée une continuité neuve au lieu d'en prolonger une.

## 6. Marquer une clé de sécurité perdue ou la réactiver (§2.4)

Une clé qu'on ne retrouve pas n'approuve plus rien, et son key-slot ouvre
toujours le coffre. La retirer, elle, est définitif.

```sh
# sur le poste de l'opérateur
astra-signer bindings --lost <key-slot>     # 32 caractères hexadécimaux
astra-signer bindings --active <key-slot>   # la remettre en service
```

Le document réémis est à copier dans le volume d'état d'Astra : c'est lui qui
décide quelles rangées peuvent répondre à une approbation.

## 7. Révoquer une identité compromise (§10)

Une révocation n'est pas un renouvellement. Elle retire les feuilles actives
immédiatement, annule tout staging concurrent et laisse l'identité dans l'état
terminal `revoked` : le poste devra être réadmis, pas rétabli.

**Sur la gateway**, dans le conteneur Astra :

```sh
astra revocation open --scope client --peer <clé-wg-base64> \
  --reason "poste volé" --requested-by "prénom.nom"
# → imprime l'identifiant et la commande complète à coller
```

Astra résout la cible contre son registre. La campagne courte fige l'identité,
la génération, les deux empreintes actives et le prochain compteur de
révocation. Une autorité en ligne compromise ne peut donc pas substituer une
autre leaf sous le toucher de l'opérateur.

**Sur le poste de l'opérateur**, exécuter la ligne imprimée :

```sh
astra-signer revoke --authority-url https://astra.exemple \
  --operation-id <identifiant> --not-after <échéance>
# --halves tls|pq|both (défaut : both)
# --reason key-compromise|suspected-compromise|cessation|superseded
```

Le compagnon vérifie la demande sous la clé de service épinglée, affiche
l'identité, les feuilles et le compteur avant le toucher, ouvre le coffre puis
signe la décision sous `CA-PQ`. Le dépôt est unique : l'approbation WebAuthn et
la révocation signée partent ensemble.

À l'arrivée, Astra revalide la signature, le compteur, les empreintes et
l'échéance contre l'état qu'elle détient déjà. Elle marque alors le pair
`revoked`, refuse ses renouvellements suivants, relaie la décision à la
gateway sur le canal privé et la distribue aux clients qui reviennent jusqu'à
la dernière échéance signée. Un dépôt identique est idempotent et peut rejouer
le relais après une panne transitoire du canal privé.

`--not-after` est recopié depuis la commande produite par Astra parce que le
format partagé `CampaignTarget` ne porte pas l'échéance. Une valeur altérée ne
révoque pas la mauvaise chose : Astra refuse le dépôt entier en la comparant à
la génération active.

**Limite connue** : `--scope gateway` est refusé. Le registre Astra connaît la
clé WireGuard et le nom de service de la gateway, mais pas ses feuilles
actives ; il ne peut donc pas lier leurs empreintes et échéances exactes à la
décision. Cette limitation est explicite plutôt que remplacée par des valeurs
retapées.

## 8. Préparer le renouvellement de l'identité gateway (§5)

La gateway génère et scelle sa propre clé suivante, puis exporte une demande.
Aucune clé privée gateway ne quitte jamais la machine qui l'a créée : ce qui
part est une clé publique et deux preuves.

**Sur la gateway**, depuis la console — *Sécurité → Certificats* — avec
« Préparer la demande ». C'est le chemin normal : la console passe par le
démon, qui **détient** le registre.

En ligne de commande, pour un démon arrêté :

```sh
heliosd prepare-gateway-certificate
# ajouter --rotate-tls pour remplacer aussi la feuille TLS auto-signée
# → imprime le chemin, l'époque, l'identifiant et l'empreinte de la demande
```

**Ces trois commandes sont celles d'un démon arrêté.** Un `heliosd` en marche
tient le registre en mémoire et le réécrit à chacune de ses propres mutations :
une écriture faite à côté peut être recouverte par la suivante. Deux écrivains
sur un fichier est précisément ce que ce module évite partout ailleurs.

La clé candidate est scellée **à côté** de l'identité en service, jamais
par-dessus : la feuille active continue de monter les tunnels pendant toute la
cérémonie, puis pendant le recouvrement du §4.1.

**Relancer la commande est une reprise, pas une seconde tentative.** Une
demande encore valide pour la même époque est rendue telle quelle — l'opérateur
tient déjà une empreinte, et en produire une seconde ne se distingue pas d'une
substitution. Une demande qui a dépassé les 24 heures du §5 est **re-signée sur
la même clé scellée** : la cérémonie n'est pas tenue par cette horloge.
`--new-key` est le seul geste qui remplace la clé candidate elle-même.

`--key-recovery` construit la demande sans signature de continuité, et
seulement après une procédure locale explicite établissant que la clé active a
disparu. Le champ est alors **absent** plutôt que non vérifié, et la transition
qui répond doit porter le motif `key_recovery`.

**Installer ce qui revient de la cérémonie** (§11.1 étape 5) :

Depuis la console, coller la décision signée dans « Appliquer une décision
signée ». En ligne de commande, démon arrêté :

```sh
heliosd install-gateway-transition /chemin/transition.json
```

La transition est vérifiée sous les ancres que cette gateway épingle déjà, et
refusée si la moitié privée d'une des feuilles qu'elle installe n'est pas
scellée ici. C'est le contrôle qu'aucune signature ne fait : `CA-PQ` atteste
qu'une feuille est authentique, jamais que sa clé privée est sur cette machine.
Sans lui, tout paraîtrait correct jusqu'à `activation_at`, puis tous les
tunnels tomberaient d'un coup, l'ancienne identité déjà retirée.

**L'installation ne change pas l'identité servie.** Le basculement appartient
à `activation_at` et demande le redémarrage de l'étape 7 du §11.1. Avant cette
date, `heliosd` charge encore l'active ; à partir de cette date, il charge la
candidate seulement si Astra a déjà persisté `published`. À `not_after`, la
maintenance promeut d'abord le registre, remplace ensuite atomiquement le
coffre actif et détruit l'ancien slot. Une coupure entre ces écritures reprend
la même transition au démarrage suivant.

**Annuler avant publication** (§6.3) :

```sh
heliosd abort-gateway-transition /chemin/avortement.json
```

Accepté seulement tant que la transition est `staged`, qu'aucun octet n'est
parti et qu'`activation_at` est encore devant — sur l'horloge locale autant que
dans le document, donc antidater n'ouvre rien. L'identité candidate est
détruite et **l'époque reste consommée** : un parc ne doit jamais avoir à
choisir entre deux décisions portant le même numéro.

### La cérémonie qui répond (§11.1 étapes 3 à 6)

**Sur la gateway**, dans le conteneur Astra :

```sh
astra gateway-identity open --reason "rotation annuelle" --requested-by "prénom.nom"
# → imprime l'identifiant, les deux empreintes en service, et les deux
#   lignes de commande à coller
```

La campagne lit l'identité **en direct sur le canal privé**, auprès du démon
qui la sert. Astra enregistre la génération de chaque client ; elle n'a jamais
détenu les feuilles de la gateway, et le §11.1 étape 3 en exige les empreintes
exactes. Une valeur retapée produirait une campagne que le compagnon signe et
que la gateway refuse — au moment précis où un renouvellement est en cours.

La commande exporte aussi la feuille en service : le compagnon ne peut pas
vérifier la signature de continuité du §5 sans la clé qui signe réellement.

**Sur le poste de l'opérateur** :

```sh
astra-signer sign-gateway-transition --authority-url https://astra.exemple \
  --operation-id <identifiant> --request demande.json \
  --active-certificate gateway-active-certificate.json --out transition.json
# --tls-certificate <der> si la feuille TLS change aussi
# --prepare-days 7 --overlap-days 7 --validity-days 365
```

Le compagnon émet la feuille sous `CA-PQ` **et** signe la transition dans le
même geste : la signature lie la feuille exacte, et une transition signée
autour d'une feuille émise à part lierait celle qui traînait sur le disque.

Le fichier produit se rapporte sur la gateway (`heliosd
install-gateway-transition`), et la décision est aussi déposée chez Astra.

**Puis, une fois l'installation faite** :

```sh
astra gateway-identity publish --epoch <n>
```

C'est l'étape 6, et le dernier instant où un avortement est encore légitime
est **avant** cette commande. Après, un client peut détenir la décision,
repartir hors ligne et promouvoir seul à `not_after` : annuler sur la seule
gateway laisserait deux vérités dans le parc. La marque est persistée avant
d'être relayée, et la commande est rejouable — une seconde exécution termine
un relais que la première n'a pas pu confirmer.

Pour annuler, tant que rien n'est publié : rouvrir une campagne
(`astra gateway-identity open`), puis

```sh
astra-signer abort-gateway-transition --authority-url https://astra.exemple \
  --operation-id <identifiant> --transition transition.json --out avortement.json
```

**Limite connue** : un client qui n'a jamais reçu la transition reste à
l'époque précédente et refusera correctement le saut vers la suivante (§6.3),
sans pouvoir récupérer ce tombstone par la distribution. Lui servir un
avortement qu'il ne peut pas appliquer ferait échouer toute la transaction
plutôt qu'une partie.

**Limite connue** : `--tls-certificate` voyage à part. La demande du §5 ne
porte pas de champ TLS, donc la feuille candidate se copie depuis la gateway.
Une feuille substituée est refusée à l'installation — la gateway seule sait
laquelle elle a scellée.

## 9. Ce qui n'a pas encore de commande

Nommé plutôt que passé sous silence : chacune de ces lignes est un geste qu'un
opérateur pourrait avoir besoin de faire aujourd'hui, et qu'aucune commande ne
fait.

- **Révoquer la gateway** (§10). Le chemin client est livré en section 7 ; la
  gateway reste refusée faute de feuilles gateway dans le registre Astra.
- **`CA-TLS` cliente** (§9.4) : aucun geste ne la fait tourner, et le registre
  la refuserait — il épingle l'époque de cette ancre sans épingler l'ancre.
- **Le retour à l'identité précédente** : l'ancien slot reste scellé pendant
  le recouvrement, mais aucune commande ne demande encore à `heliosd` de le
  resservir temporairement.
- **Les campagnes depuis la console** : « Renouveler les leafs du parc »,
  « toute la chaîne » et « Tourner les autorités » ouvrent une campagne Astra,
  et §11.6 garde cette résolution locale — une campagne est l'inventaire du
  domaine. La console les nomme avec leur commande ; elles se lancent dans le
  conteneur Astra.
- **L'adoption d'une ancre distribuée** par Astra et par la gateway.

## Vérifier où en est le domaine

```sh
astra status --expected-audit-head <empreinte notée à la dernière opération>
heliosd show-trust-enrolment <clé-du-pair>
astra-signer list          # les key-slots du coffre, sans clé de sécurité
```

`astra status` refuse une chaîne d'audit qui bifurque : une sauvegarde qui se
vérifie toute seule mais finit ailleurs est une fourche, et une autorité qui la
continuerait émettrait sous deux histoires à la fois.
