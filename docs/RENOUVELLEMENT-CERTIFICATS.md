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

**Sur le poste de l'opérateur**, l'onglet Astra d'Orion s'allume et montre le
motif, le demandeur, les cibles et l'empreinte avant de demander les clés — une
à la fois, parce que deux touchers d'un même jeton sont refusés et qu'il vaut
mieux l'apprendre à la seconde invite qu'après les deux.

Si la clé est ailleurs, l'adaptateur en ligne de commande exécute la même
cérémonie :

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

**Puis sur la gateway**, avec la transition rapportée — écran *Certificats*,
ou `POST /api/certificates/ca-transition` :

```sh
# ou, démon arrêté :
heliosd install-ca-transition ca-pq-transition.json
```

L'ancre ne bouge pas là. Les deux `CA-PQ` vérifient à partir de
`activation_at`, et la sortante est retirée à `not_after` — par la même passe
d'entretien qui promeut les générations clientes et la CA TLS, dans la même
écriture. Un redémarrage qui trouverait une ancre avancée et l'autre non
accepterait une chaîne que le domaine a retirée, ou refuserait une chaîne sous
laquelle il émet encore ; laquelle des deux dépendrait de l'endroit où la
panne est tombée.

**Comparer l'empreinte entrante** avec celle qu'affiche le compagnon. Le §9.1
en fait le contrôle : la double signature prouve la continuité, pas que
l'ancre affichée est celle que l'opérateur a créée. La console la montre à
côté de l'époque.

**Limite connue** : le registre Astra reste sur l'ancre sortante jusqu'à ce
qu'un opérateur l'avance. Les clients l'appliquent, la gateway aussi
désormais ; l'autorité, non — sa campagne suivante repartirait donc de l'ancre
retirée.

## 4. Renouveler la délégation d'émission Astra (§9.5)

L'émetteur délégué est ce qui permet à Astra de renouveler les feuilles
clientes **en ligne**, sans ouvrir le coffre. Il porte sa propre échéance.

**Sur la gateway** — la demande et sa campagne, en un seul geste :

```sh
astra issuer request --out issuer-request.json \
  --reason "délégation trimestrielle" --requested-by "prénom.nom"
```

La demande sort sur la sortie standard et dans le fichier ; l'identifiant
d'opération s'affiche sur l'erreur standard, avec la commande à recopier. Les
deux clés privées naissent dans le volume d'Astra et n'en sortent pas.

**Sur le poste de l'opérateur**, clé branchée :

```sh
astra-signer authorize-issuer --request issuer-request.json \
  --authority-url https://astra.example --operation-id <identifiant> \
  --days 30 --leaf-days 90
```

Le compagnon vérifie la campagne sous la clé de service qu'il épingle déjà,
compare la demande à ce que la campagne nomme — l'époque, la clé ML-DSA-87 et
la clé publique dont la PKCS#10 prouve la possession —, affiche le tout, prend
l'assertion, signe et **redépose** la délégation. Astra l'enregistre après
avoir prouvé que les deux moitiés privées scellées dans son volume
correspondent. Il reste à le redémarrer pour qu'il émette dessous.

Le fichier de demande voyage toujours par un canal quelconque : il est public,
et c'est la campagne qui l'authentifie. Une demande substituée est refusée
avant même que le coffre s'ouvre.

Chaque installation doit faire **avancer** l'époque : réinstaller une époque
déjà employée avec une *autre* délégation ferait revenir un intermédiaire
retiré sous une signature encore parfaitement valide. Redéposer la **même**
délégation est un rejeu sans effet, ce qui répare une réponse perdue.

**Hors campagne**, pour un domaine dont l'origine publique n'est pas
joignable :

```sh
astra issuer request --out issuer-request.json
astra-signer authorize-issuer --request issuer-request.json \
  --out issuer-authorization.json --days 30 --leaf-days 90
astra issuer install --authorization issuer-authorization.json
```

Une demande de délégation ne porte **aucune signature**. Par ce chemin, le
compagnon signe donc le fichier qu'on lui présente, et rien ne le rattache à
cette autorité : c'est la forme de repli, pas la forme ordinaire.

## 5. Récupérer une identité expirée (§7.5)

Quand un poste est resté éteint trop longtemps, sa feuille a expiré : plus
aucun tunnel, donc plus aucun chemin de renouvellement ordinaire. La
récupération est le seul retour, et elle exige que **la clé privée expirée
existe encore**.

**Sur le poste**, dans Orion : « Récupérer le certificat expiré ». Orion
affiche un identifiant. Il n'y a plus aucun canal automatique entre le poste et
l'opérateur — l'identifiant se lit à voix haute, se copie dans un message, peu
importe : il n'autorise rien à lui seul.

**Sur le poste de l'opérateur**, si c'est le même poste, la ligne « Approuver
ici avec la clé » ouvre la cérémonie dans l'onglet Astra. Sinon, l'adaptateur
en ligne de commande fait la même chose :

```sh
astra-signer recover --authority-url https://astra.exemple \
  --operation-id <identifiant>
```

L'un comme l'autre affichent le pair, la génération et depuis combien de temps
elle est expirée, **avant** de demander le toucher. Les durées ne sont plus
demandées : une génération récupérée vit un an et ne recouvre qu'un jour —
l'ancienne a déjà expiré, il n'y a rien à recouvrir. Puis, dans Orion, cliquer une
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

**Révoquer la gateway elle-même** — même cérémonie, une résolution en plus :

```sh
astra revocation open --scope gateway \
  --reason "clé de service compromise" --requested-by "prénom.nom"
# → imprime les deux empreintes, leurs deux échéances, et la ligne à coller
astra-signer revoke --scope gateway --authority-url https://astra.exemple \
  --operation-id <identifiant> --pq-not-after <…> --tls-not-after <…>
```

Le registre Astra n'a jamais détenu les feuilles de la gateway — il transcrit
des admissions, il ne tient pas l'identité que tous les clients épinglent.
Elles sont donc lues **en direct** sur le canal privé, auprès du démon qui les
sert, avec leurs échéances signées : §10.1 les exige exactes, et une valeur
retapée produirait un objet refusé par tous ses destinataires pendant
l'incident.

Les deux feuilles gateway n'expirent pas ensemble, contrairement à une
génération cliente : leurs échéances se nomment séparément, et une moitié sans
la sienne est refusée plutôt que complétée d'office.

**C'est terminal, sauf pour un document exact.** Une gateway révoquée n'offre
plus de feuille acceptable : les clients refusent la négociation au lieu de
traiter avec une identité que l'autorité a retirée. Aucune clé de sécurité ne
relève cet état — seule la transition que la révocation elle-même a nommée
s'installe ensuite.

### 7.1 Remplacer l'identité retirée (§6.1, motif `emergency_replacement`)

Sans cette suite, une révocation gateway est une panne de service définitive :
plus aucune transition ne s'installe, sur aucun détenteur, et il faut
reconstruire le domaine. Le champ `replacement_transition_fingerprint` du
§10.1 existe pour ça.

L'ordre est imposé, et par la machine à états plutôt que par la consigne.

**1. Préparer la clé suivante, sur la gateway** — avant ou après la
révocation, mais toujours en récupération de clé :

```sh
heliosd prepare-gateway-certificate --key-recovery
```

Une identité révoquée ne signe pas pour sa suivante : la signature de
continuité du §5 est exactement le droit qu'un retrait supprime. Sans
`--key-recovery`, la commande refuse et le dit.

**2. Signer la transition de remplacement** — campagne `gateway-identity` :

```sh
astra-signer sign-gateway-transition --emergency-replacement \
  --authority-url https://astra.exemple --operation-id <identifiant> \
  --request gateway-certificate-request.json --out remplacement.json \
  --key-recovery
```

**3. Signer la révocation, en la nommant** — campagne `emergency-revocation` :

```sh
astra-signer revoke --scope gateway --authority-url https://astra.exemple \
  --operation-id <identifiant> --pq-not-after <…> --tls-not-after <…> \
  --replacement-transition remplacement.json
```

Le fichier est lu, pas l'empreinte saisie. Une valeur retapée de travers
laisserait une gateway qui attend un document que plus personne ne peut
produire.

**4. Appliquer, dans cet ordre** : la révocation d'abord — c'est elle qui
inscrit ce que l'état acceptera —, la transition ensuite.

La transition de remplacement est **servie immédiatement**, sans fenêtre : il
n'y a plus d'identité sortante avec laquelle se recouvrir, et l'étager
laisserait le service à terre jusqu'à `activation_at` alors qu'il l'est déjà.
Le compteur de révocation, lui, garde sa valeur — c'est un axe distinct
(§4.2), et le faire redescendre rendrait une décision déjà consommée
livrable une seconde fois. Les feuilles retirées ne reviennent jamais : le
registre des tombstones les refuse avant même que le document nommé soit
consulté.

Le motif `emergency_replacement` n'est accepté **que** là. Proposé à une
identité saine, il serait une bascule immédiate et non planifiée dont aucun
client n'a été prévenu ; il est refusé, et la réciproque aussi — une gateway
révoquée n'accepte pas un document ordinaire à la place de celui qu'on lui a
nommé.

**Limite connue** : préparer la clé de remplacement sur la machine qui vient
d'être révoquée n'a de sens que si l'hôte est sain. Après une compromission de
clé, c'est précisément ce qu'il ne faut pas faire — la décision reste celle de
l'opérateur, et rien ici ne peut la prendre à sa place.

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

### 8.1 Revenir temporairement à l'ancienne identité (§11.1 étape 8)

Pendant le chevauchement — et là seulement —, la gateway peut resservir la
feuille sortante. C'est un rollback **de service**, pas d'état : aucun compteur
ne bouge, le slot suivant reste scellé, et sa promotion a lieu à `not_after`
comme prévu.

Au poste opérateur :

```sh
astra-signer sign-gateway-rollback --transition transition.json \
  --out rollback.json --hours 24 --reason … --requested-by …
```

Puis sur la gateway, depuis l'écran *Certificats* (ou
`POST /api/certificates/gateway-transition/rollback`), coller l'autorisation,
**et redémarrer `heliosd`**.

Le redémarrage n'est pas un détail : la feuille en service est descellée au
démarrage et tenue pour la vie du processus. Installer l'autorisation
enregistre la décision ; c'est le démarrage suivant qui l'applique.

**Hors campagne Astra, délibérément.** Tous les autres gestes gateway passent
par l'autorité parce qu'ils produisent un objet que le domaine distribue. Un
rollback n'en produit aucun : aucun client ne le voit, c'est ce que veut dire
« de service » au §4.4. Le garde d'Astra le confirme par construction — le
résultat d'une campagne `gateway_identity` doit porter exactement un objet de
mise à jour de confiance, si bien que déposer celui-ci obligerait à inventer
une forme distribuable d'une décision qui ne doit jamais être distribuée. La
campagne est donc résolue localement depuis la transition signée elle-même
(§11.6 garde de toute façon cette résolution locale), affichée en entier, et
attestée par une clé autorisée avant que `CA-PQ` ne signe.

**Ce que le geste refuse**, et pourquoi :

| Moment | Refus |
| --- | --- |
| avant `activation_at` | l'ancienne feuille est déjà celle qui sert. Pour annuler la décision, c'est l'avortement du §6.3 |
| transition non publiée | idem : rien n'a basculé, et l'époque peut encore être rendue |
| après `not_after` | ramener la feuille sortante serait un rollback d'**état**, que le §4.4 interdit |
| une autre feuille que la sortante | l'autorisation nomme l'empreinte que la transition désigne, jamais une saisie d'opérateur |
| identité révoquée | une gateway révoquée n'offre aucune feuille acceptable |

L'expiration est répondue par l'horloge : la sélection cesse d'être servie à la
seconde où elle expire, sans qu'aucune écriture n'ait à passer.

**Limite connue** : rien ne redémarre `heliosd` à votre place, et rien ne le
redémarre non plus quand la sélection expire. Un rollback posé pour 24 h laisse
la gateway sur l'ancienne feuille jusqu'au redémarrage suivant, même après
l'expiration — ce qui la lèverait est un superviseur qui relance le démon sur
changement d'état, et il n'y en a pas.

## 9. Faire tourner la CA TLS cliente (§9.4)

`CA-TLS` authentifie le transport mTLS **avant** qu'aucune signature PQ soit
vérifiée. Sa rotation se prépare donc sur la gateway avant qu'une feuille
cliente soit émise sous la nouvelle ancre.

**Une fois, si le domaine est antérieur à cet épinglage** — dans le conteneur
Astra :

```sh
astra pin-ca-tls --fingerprint <sha256-hex>
```

Sans cette valeur, l'autorité épingle l'*époque* de cette ancre sans épingler
l'ancre : elle ne pourrait vérifier une transition que contre une empreinte
portée par l'objet lui-même, ce qui ne vérifie rien. La commande refuse de
remplacer une ancre déjà épinglée — remplacer une ancre est une rotation, et
une rotation se signe. Les domaines neufs la reçoivent par
`astra bootstrap --ca-tls-fingerprint`.

**La rotation** :

```sh
astra campaign open --scope trust-authorities --reason … --requested-by …
astra-signer rotate-ca-tls --authority-url https://astra.exemple \
  --operation-id <identifiant> --out ca-tls-transition.json
# --prepare-days 7 --overlap-days 30 --validity-days 1825
heliosd install-client-tls-ca ca-tls-transition.json

# à not_after, une fois le recouvrement écoulé :
astra-signer promote-ca-tls
```

L'ancre entrante est créée au compagnon, auto-signée pour prouver qu'elle
détient sa clé — cette auto-signature ne remplace jamais la signature `CA-PQ`
comme autorisation. `CA-PQ`, elle, ne bouge pas.

**Le coffre ne bascule pas à la cérémonie.** La clé suivante est scellée *à
côté* de celle qui émet, dans le rôle `successor`. C'est ce que demandent le
§9.4 — la gateway est préparée avant qu'une feuille soit émise sous la
nouvelle ancre — et le §4.1, qui place un `activation_at` entre la décision et
son effet. Un coffre qui aurait échangé les clés au moment de la signature
aurait certifié des feuilles que le parc n'accepte pas encore.

`promote-ca-tls` referme la fenêtre, en une seule réécriture scellée :

| Moment | Ce que la commande fait |
| --- | --- |
| avant `not_after` | rien, et elle dit quelle seconde elle attend |
| à `not_after` | la clé suivante devient celle qui émet, l'ancienne clé privée cesse d'exister, le relais de domaine passe à la nouvelle époque, la fenêtre se referme |

**Pourquoi l'autorité émet sous l'ancre sortante pendant tout le
recouvrement** : une génération cliente porte `ca_tls_epoch`, et la gateway le
compare **à l'identique** à son propre `ca_tls_epoch`, qu'elle n'avance qu'à
`retire_active_at` — c'est-à-dire `not_after`, pas `activation_at`. Une
autorité qui se serait mise à estampiller la génération suivante dès
l'activation aurait vu refuser **toutes** les émissions du recouvrement,
pendant toute sa durée. Les deux côtés basculent donc à la même seconde.

**Conserver n'est pas détruire, et le successeur ne certifie rien.** Le §9.2
n'autorise la destruction de l'ancienne clé privée qu'après la fin de la
fenêtre et la publication durable de la transition ; la détruire à la
cérémonie laisserait un domaine ayant annoncé un successeur qu'aucune gateway
n'a encore installé sans aucun retour possible. Symétriquement, la clé
entrante n'est jamais `ca_tls_private_key` — le seul champ que lisent les
gestes de signature — avant que `promote-ca-tls` ne l'y déplace.

**La décision est écrite avant d'être annoncée.** La cérémonie scelle le
successeur, puis écrit `astra-prepared.json` à côté du coffre — les octets
exacts du dépôt, la fenêtre, et le fichier de transition —, et seulement
ensuite dépose auprès d'Astra. Une machine qui s'arrête entre les deux se
reprend par :

```sh
astra-signer resume-rotation --authority-url https://astra.exemple
```

Astra traite un résultat identique comme le même (§8.2) : la reprise ne
redemande aucune clé, parce qu'elle n'approuve rien de neuf. Tant que ce
fichier existe, `rotate-ca-tls` refuse d'ouvrir une seconde fenêtre.

**Pendant le chevauchement, les deux chaînes sont acceptées.** C'est tout
l'objet de la fenêtre : les feuilles clientes émises sous l'ancienne ancre
continuent de monter des tunnels le temps que le parc soit ré-émis. À
`not_after`, l'ancienne est retirée dans la même écriture que les promotions
de générations — une purge qui déplacerait l'une sans l'autre laisserait
accepter une chaîne que le domaine a retirée.

**Astra adopte le pin qu'il distribue.** Le dépôt signé ouvre dans son registre
un slot entrant portant l'empreinte, la génération et la fenêtre. La passe
horodatée du service ne le promeut pas à `activation_at` : à `not_after`, elle
avance l'époque et l'empreinte actives, referme le slot et oublie la transition
consommée dans une seule écriture atomique. Une campagne
`trust-authorities` suivante décrit donc bien l'ancre désormais active ;
`pin-ca-tls` reste incapable de la remplacer.

**Limite connue** : la rotation ne ré-émet pas les feuilles clientes. Elles
restent valides sous l'ancienne ancre jusqu'à `not_after`, et c'est une
campagne `fleet_leafs` — ou le renouvellement ordinaire à 80 % — qui les fait
passer sous la nouvelle. Un chevauchement plus court que ce que le parc met à
revenir couperait les retardataires.

**Limite connue** : l'intermédiaire de l'émetteur délégué est signé par
l'ancre sortante. Le faire ré-émettre sous la nouvelle est la rotation du
§9.5, qui reste un geste distinct.

**Limite connue** : rien ne lance `promote-ca-tls` à `not_after`. La gateway
avance son époque toute seule à cette seconde ; le compagnon, lui, attend
l'opérateur, et jusque-là il continue d'estampiller l'ancienne — que la
gateway refusera désormais. Le fichier `astra-prepared.json` en garde la trace
et `resume-rotation` la rappelle. Ce qui la lèverait est un ordonnanceur côté
opérateur, qui n'existe pas : le compagnon est une machine hors ligne qu'on
branche.

## 10. Renouveler toute la chaîne (§7.6)

« Toute la chaîne » couvre l'émetteur délégué, la CA TLS cliente, l'identité
gateway et les feuilles du parc — **pas `CA-PQ`**, qui a sa propre cérémonie
(§3 de cette note).

Ce n'est pas une campagne, c'est un **plan de quatre campagnes ordonnées**. Ces
quatre choses appartiennent à quatre familles d'objets signés, et une famille
refuse les trois autres dans les deux sens : c'est ce qui empêche une campagne
d'autoriser quelque chose que l'opérateur n'a pas lu. Une campagne unique
portant les quatre transformerait chacune de ces gardes en un contrôle de
sous-ensemble.

```sh
astra chain open --reason "renouvellement annuel" --requested-by "prénom.nom" \
  --issuer-request-out issuer-request.json
```

La première étape est déposée. Ensuite, pour chacune des suivantes :

```sh
# depuis le poste opérateur : approuver l'étape en cours, avec sa commande
# propre (astra-signer authorize-issuer, rotate-ca-tls,
# sign-gateway-transition, approve-campaign).

# puis, sur la gateway :
astra chain next \
  --gateway-channel <adresse-veth> --gateway-certificate <certificat>
```

`astra chain next` **refuse d'avancer** tant que l'effet de l'étape en cours
n'apparaît pas dans le registre : l'époque de l'émetteur a bougé, l'ancre TLS a
un successeur, la décision gateway a été stockée. Ce n'est pas « l'opérateur a
approuvé » — une approbation dont l'objet n'a jamais atterri n'a pas déplacé le
domaine, et résoudre la campagne suivante contre cet état figerait une
situation que personne n'a atteinte.

`--gateway-channel` et `--gateway-certificate` ne servent qu'à l'étape
d'identité gateway : cette campagne est résolue sur les feuilles que le démon
sert réellement, qu'Astra n'a jamais détenues.

```sh
astra chain status     # où en est le plan
astra chain abandon    # l'abandonner ; ce qui est approuvé garde son effet
```

**L'ordre n'est pas une préférence.** L'émetteur signe les feuilles clientes,
l'ancre TLS est ce à quoi elles se chaînent, l'identité gateway est ce que
chaque client épingle. Commencer par les feuilles les émettrait sous un
émetteur et une ancre sur le point d'être remplacés, et chaque pair reviendrait
une seconde fois.

**Limite connue** : la dernière étape n'a aucun effet observable. Une campagne
de parc autorise des rotations, et chaque pair dépense cette autorisation en
revenant, dans la fenêtre de cinq minutes du §7.6. Le plan le dit au lieu de
rapporter une réussite qu'il n'a pas vue. **Quatre touchers**, aussi : c'est le
prix de l'ordonnancement, puisque la fenêtre de campagne interdit de résoudre
les étapes suivantes d'avance.

## 11. Ce qui n'a pas de commande, par décision

Le cycle de vie est complet ; ces trois gestes restent manuels **exprès**, et
chacun dit pourquoi. Nommés plutôt que passés sous silence, pour qu'aucun ne
soit pris pour un manque à combler.

- **Les campagnes depuis la console** : « Renouveler les leafs du parc »,
  « toute la chaîne » et « Tourner les autorités » ouvrent une campagne Astra,
  et §11.6 garde cette résolution locale — une campagne est l'inventaire du
  domaine, et une route publique non authentifiée qui la résoudrait la
  répondrait à n'importe quel appelant. La console les nomme avec leur
  commande ; elles se lancent dans le conteneur Astra.
- **Le redémarrage après une bascule.** L'identité servie est descellée une
  seule fois et tenue pour la vie du processus : la recharger reconstruirait le
  point d'accès QUIC pendant que des négociations y détiennent des PSK. Toute
  bascule est donc un redémarrage — `activation_at`, `not_after`, et
  l'expiration d'un rollback de service. Le démon le **dit** désormais, dans
  son journal et sur l'écran *Certificats*, mais rien ne le redémarre à la
  place de l'opérateur.
- **La bascule de confiance du §13.2**, pour un parc v5 déjà déployé : la
  première installation de `CA-PQ` est un amorçage, pas une rotation, et elle
  exige une confirmation d'empreinte hors bande. C'est une procédure
  opérateur, et aucune commande ne peut la remplacer.

## Vérifier où en est le domaine

```sh
astra status --expected-audit-head <empreinte notée à la dernière opération>
heliosd show-trust-enrolment <clé-du-pair>
astra-signer list          # les key-slots du coffre, sans clé de sécurité
```

`astra status` refuse une chaîne d'audit qui bifurque : une sauvegarde qui se
vérifie toute seule mais finit ailleurs est une fourche, et une autorité qui la
continuerait émettrait sous deux histoires à la fois.
