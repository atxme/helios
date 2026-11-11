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

## Le chemin par défaut : Orion (F14, lots 5b et 6b)

Depuis le lot 5b, les rotations se font **depuis Orion**, sur un poste
administrateur du tunnel : onglet *Astra* › *Rotations*, une liste d'actions
avec leur état. Ce qui est à faire passe en premier. Les commandes de ce
document (`astra campaign open`, `astra-signer rotate-ca-pq`, `heliosd
install-*`, `promote-ca-tls`, `resume-rotation`) restent décrites comme
**recours** : elles servent quand Orion ne peut pas, jamais par défaut. Orion ne
lance plus `astra-signer`.

Depuis le lot 6b, l'identité de la gateway se gère aussi depuis Orion, par le
tunnel, sans fichier ni commande (§7.1, §8, §8.1). Les commandes gateway de ce
document (`astra-signer sign-gateway-transition`, `sign-gateway-rollback`,
`revoke --scope gateway`, `astra gateway-identity …`) restent le recours jusqu'au
lot 7. « Tout renouveler » n'est pas encore dans Orion (§10).

| Ligne | Ce qu'elle fait | Section |
| --- | --- | --- |
| Terminer la rotation CA TLS | remplace `promote-ca-tls` ; visible dès `not_after` | §9 |
| Reprendre une rotation | reprend une rotation signée qui n'est pas allée au bout ; automatique à la montée du tunnel | §3, §9 |
| Renouveler les postes | ouvre la campagne de parc et enchaîne les touchers | §2 |
| Remplacer la CA-PQ | ouvre `trust_authorities`, signe, dépose, installe sur la gateway | §3 |
| Remplacer la CA TLS | idem pour la CA TLS | §9 |
| Renouveler la délégation | délégation de l'émetteur, sans fichier ni redémarrage | §4 |
| Révoquer un poste | onglet *Postes* : coupe le poste tout de suite, puis signe la révocation (lot 5c) | §7 |
| Identité de la gateway | bloc en tête de *Rotations* : renouvelle, annule, revient à l'ancienne identité, révoque la gateway ; reprend ou jette une décision en attente (lot 6b) | §7.1, §8, §8.1 |

Orion vérifie des **prérequis** avant toute ouverture (tunnel, administrateur,
service Astra, coffre, deux clés, copie du coffre, domaine concordant) et dit
quoi corriger ; tant qu'un seul est rouge, rien n'est ouvert. Pour une rotation
de CA, les deux clés sont validées une par une avant l'ouverture, puis il reste
un toucher d'approbation par clé. La copie du coffre se renvoie à Astra depuis
Orion (« Envoyer »), sans clé. Les limites connues sont en fin de document :
« Limites connues des rotations dans Orion ».

## Les commandes `astra` de ce document

Elles se lancent **dans le conteneur Astra en marche**, par `compose exec`
(tableau « en marche » de [DEPLOIEMENT-ASTRA](DEPLOIEMENT-ASTRA.md)) :

```sh
cd ~/astra-build && sudo docker compose -f deploy/astra/compose.yaml \
  --env-file /var/lib/helios/astra-compose.env \
  exec -T astra /usr/local/bin/astra campaign open …
```

Depuis le lot 5a de F14, Astra tient **une seule porte** d'ouverture
(ROTATION-CERTIFICATS §0.9) : ces commandes n'ouvrent plus rien elles-mêmes,
elles portent la demande au service par son socket local et impriment sa
réponse, comme avant. D'où trois règles :

- **Une ouverture exige le service en marche** — `campaign open`,
  `revocation open`, `gateway-identity open`, `chain open|next|abandon`,
  `issuer request`. Service arrêté, elle répond « le service Astra ne tourne
  pas : rien n'a été ouvert » et n'écrit rien.
- **Une écriture suit le verrou du volume** — `pin-ca-tls`, `issuer install`,
  `gateway-identity publish`. Service arrêté, elle écrit localement ; service en
  marche, elle passe par lui et l'ouverture suivante la voit sans redémarrage.
- **Les refus sont les phrases de la porte**, en français, et la console
  attend la réponse 60 s au plus : au-delà, elle dit que l'échange s'est
  interrompu, et ce qui a été fait, s'il y a lieu, est dans le journal
  d'Astra.

`status` et `chain status` restent des lectures, service arrêté ou non.

Le motif (`--reason`) et le demandeur (`--requested-by`) tiennent sur une
ligne : 1 024 et 256 caractères au plus, sans caractère de contrôle ni de mise
en forme invisible (marques bidirectionnelles, largeur nulle). Les accents et
la ponctuation française passent ; le reste est refusé, quel que soit le
connecteur.

Trois ouvertures se font aussi **depuis un poste administrateur du tunnel**,
sans entrer dans le conteneur : `fleet_leafs` (§2), `trust_authorities` (§3,
§9) et la révocation d'un client (§7), par `POST
/api/certificates/operator/campaigns`. Orion l'emploie depuis le lot 5b pour
les rotations (onglet *Rotations*) et, depuis le lot 5c, pour la révocation d'un
poste (onglet *Postes*, §7) ; la route reste appelable directement pour le
recours. Le tunnel ouvre aussi,
depuis le lot 5b, la délégation d'émetteur avec campagne (§4) et reçoit la copie
du coffre (`POST /api/certificates/operator/vault-copy`).

Depuis le lot 6b, le même tunnel ouvre aussi l'identité de la gateway
(`gateway_identity`, §8), la révocation de la gateway (`gateway_revocation`,
§7.1) et le premier pas du plan (`chain_open`, §10). Il porte la publication
d'une transition (`POST /api/certificates/operator/gateway-identity/publish`) et
les pas suivants du plan (`…/chain/next`, `…/chain/abandon`).

## 1. Renouveler la feuille d'un poste (§7.1 → §7.3)

Le cas courant. Rien à faire côté gateway.

Dans Orion, destination *Certificats* : « Renouveler maintenant ». Orion ouvre
l'opération, lit et affiche tout seul la demande (pair, génération, empreinte,
expiration, nombre de clés éligibles), puis propose « Approuver avec la clé ».
**Brancher la clé de sécurité d'un opérateur sur ce même poste** : l'opération
appartient au poste qui l'a ouverte, aucun autre ne peut la lire ni y déposer
d'approbation. Le dialogue de la clé s'ouvre au-dessus de la fenêtre d'Orion ;
Sous Windows, Orion n'a plus de champ PIN (le dialogue de la plateforme le demande) ; avec une clé HID (Linux) le champ PIN reste, et le PIN ne va jamais au moteur. Le poste
committe ensuite. Il n'y a plus de compagnon ni de commande à recopier.

Après tout échec d'approbation (clé absente, geste annulé, PIN faux, demande
expirée, dépôt échoué), la demande reste affichée, « Approuver avec la clé »
redevient actif et « Relire la demande » est proposé à côté : un nouvel essai est
un clic, et la relecture n'est nécessaire que si l'essai est refusé, car un
dépôt qui échoue consomme la demande vérifiée. Un second clic sur « Renouveler maintenant »
ne rouvre jamais une deuxième opération — c'est ce que la session en mémoire
garantit.

Pour avancer **tous** les profils Helios de l'appareil d'un pas :
« Renouveler tous les profils Helios de cet appareil ». Chaque profil garde sa
propre attente ; le refus de l'un n'arrête pas les autres.

## 2. Renouveler tout un parc en une fois (§7.6)

Une campagne autorise des rotations à l'avance. Elle **ne renouvelle pas** les
postes : elle dispense chaque poste couvert de redemander une approbation.

**Dans Orion** (chemin par défaut) : onglet *Astra* › *Rotations*, ligne
« Renouveler les postes » (nombre de postes, échéance la plus proche, « Expire
bientôt » à 30 jours), bouton « Renouveler ». Orion contrôle les prérequis,
ouvre la campagne au clic, affiche le manifeste vérifié et enchaîne les
touchers. **Pendant un recouvrement CA-PQ, la ligne est désactivée** et dit
pourquoi : Astra refuse après le toucher toute approbation faite sous le
document de credentials local (voir « Limites connues »). Les commandes
ci-dessous sont le recours.

**Sur la gateway**, dans le conteneur Astra :

```sh
astra campaign open --scope fleet-leafs \
  --reason "campagne trimestrielle" --requested-by "prénom.nom" \
  --window-secs 300
# → imprime un identifiant d'opération
```

Ou, **depuis un poste administrateur du tunnel**, la même ouverture :

```sh
curl --fail --request POST --header 'Content-Type: application/json' \
  --data '{"action":"fleet_leafs","reason":"campagne trimestrielle","requested_by":"prénom.nom"}' \
  http://<VIP de la gateway>:8080/api/certificates/operator/campaigns
# → operation_id, campaign_fingerprint, target_count, expires_at…
```

Le demandeur affiché devant le toucher devient alors
`prénom.nom — pair wireguard:<clé>` : la porte y ajoute la clé WireGuard du
pair qui a réellement ouvert. Un pair non administrateur est refusé avant que
la gateway ne relaie quoi que ce soit. Une seconde campagne de parc ouverte
pendant que la première attend l'opérateur est refusée ; la première figure
dans l'onglet *Approbations*.

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

**Dans Orion** (chemin par défaut) : ligne « Remplacer la CA-PQ » de l'onglet
*Rotations*. Prérequis, puis « Clé 1 » et « Clé 2 » validées l'une après l'autre
(un toucher chacune, la même clé deux fois est refusée), puis « Approuver » : la
campagne s'ouvre à ce clic, parce qu'elle expire en cinq minutes, et un toucher
d'approbation par clé suit (dans n'importe quel ordre). Les durées (préparation
7 jours, recouvrement 30 jours) sont derrière « Modifier » ; moins d'un jour de
préparation est refusé. Orion dépose le résultat, installe la transition sur la
gateway par le tunnel, sans fichier, puis renvoie la copie du coffre. **Le coffre
local ne bouge qu'après l'acceptation d'Astra.** Fermer Orion en route ne perd
rien : la rotation se reprend seule, sans clé, à la montée du tunnel vers la
gateway du domaine ; derrière l'écran terminé de l'opérateur lui-même, elle
attend un clic sur la fermeture de cet écran. La ligne montre la date de fin de
rotation et, pendant le recouvrement, « Ancre entrante … » : **comparer cette
empreinte à celle que l'on a créée**, car elle n'existe pas avant la signature
et ne se montre donc qu'après. Les commandes suivantes sont le recours.

**Sur la gateway** :

```sh
astra campaign open --scope trust-authorities \
  --reason "rotation annuelle de l'ancre" --requested-by "prénom.nom"
# → imprime un identifiant d'opération
```

Ou par le tunnel, comme au §2, avec `"action":"trust_authorities"`.

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

*Limite levée (vérifiée le 7 novembre 2026).* Ce paragraphe disait que le
registre Astra reste sur l'ancre sortante jusqu'à ce qu'un opérateur l'avance.
C'est périmé : Astra adopte la transition à son dépôt (`ca_rotation`) et sa
passe d'entretien promeut l'ancre à `not_after` (`forget_expired_transitions`),
dans la même écriture que les promotions de générations. La campagne suivante
décrit donc bien l'ancre active, sans geste de l'opérateur.

**Limite connue** : tant que le recouvrement dure, le coffre local est déjà sous
la nouvelle ancre et Astra garde l'ancien document de credentials jusqu'à
`not_after`. Toute approbation faite sous le document local est refusée après le
toucher : Orion désactive donc « Renouveler les postes », chaque lancement
d'*Approbations*, la récupération et la délégation pendant le recouvrement.

## 4. Renouveler la délégation d'émission Astra (§9.5)

L'émetteur délégué est ce qui permet à Astra de renouveler les feuilles
clientes **en ligne**, sans ouvrir le coffre. Il porte sa propre échéance.

**Dans Orion** (chemin par défaut) : ligne « Renouveler la délégation ». Elle
passe à « À faire » quand la délégation expire bientôt (30 jours) ou ne suit
plus les époques de la CA, une fois le coffre au niveau de la gateway : à partir
de `not_after` après une rotation CA-PQ, après « Terminer » pour la CA TLS.
Pendant un recouvrement CA-PQ le bouton est désactivé (pendant celui d'une CA
TLS, il ne l'est que si le coffre a une époque d'avance sur la gateway). Orion
ouvre la campagne par le tunnel ; Astra génère les clés dans son volume et
renvoie la demande dans la réponse, sans fichier ; une clé approuve puis ouvre
le coffre ; la délégation est déposée et **Astra l'adopte sans redémarrer**
(Orion ne redémarre jamais Astra). Si l'adoption échoue, Astra le journalise et
l'émetteur en place reste servi ; la réponse de dépôt reste un succès, et Orion
ne le montre qu'indirectement, par la ligne de délégation (« époque servie X,
inscrite Y »). Une délégation ouverte dont la réponse s'est perdue ne se reprend
pas : « Opération ouverte jusqu'au … », puis une nouvelle ouverture une fois la
fenêtre close. Les commandes ci-dessous sont le recours.

**Sur la gateway** — la demande et sa campagne, en un seul geste :

```sh
astra issuer request --out issuer-request.json \
  --reason "délégation trimestrielle" --requested-by "prénom.nom"
```

La demande sort sur la sortie standard et dans le fichier ; l'identifiant
d'opération s'affiche sur l'erreur standard, avec la commande à recopier. Les
deux clés privées sont tirées par le service Astra, dans son volume, et n'en
sortent pas : la commande exige donc le service en marche, avec ou sans
campagne. `--out` est ouvert avant la demande, si bien qu'un chemin où l'on ne
peut pas écrire est refusé avant qu'aucune campagne ne soit ouverte.

**Sur le poste de l'opérateur**, dans Orion : onglet Astra › Approbations, la
campagne `issuer_delegation` › « Ouvrir la cérémonie », puis choisir le fichier
`issuer-request.json` (256 Kio au plus). Délégation de 30 jours, leaf de 90 jours
au plus, ramenée au plafond de la politique épinglée avant la clé ; une seule clé,
qui approuve la campagne puis ouvre le coffre. Avant de la demander, Orion refuse
une CA-TLS expirée, trop proche de son expiration ou qui n'est pas une autorité
(« la renouveler d'abord »), et une demande que la campagne ne nomme pas.
`astra-signer authorize-issuer` reste livré à titre transitoire, jusqu'au lot 7.

Orion vérifie la campagne sous la clé de service qu'il épingle déjà,
compare la demande à ce que la campagne nomme — l'époque, la clé ML-DSA-87 et
la clé publique dont la PKCS#10 prouve la possession —, affiche le tout, prend
l'assertion, signe et **redépose** la délégation (« Délégation enregistrée par
Astra. »). Astra l'enregistre après avoir prouvé que les deux moitiés privées
scellées dans son volume correspondent, puis **l'adopte en place** : aucun
redémarrage n'est plus nécessaire depuis le lot 5b. Si l'adoption échoue, seul le
journal d'Astra le dit (« delegation recorded but not adopted ») et l'émetteur
précédent reste servi ; dans Orion, la ligne de délégation montre alors une
époque servie différente de l'époque inscrite.

Le fichier de demande voyage toujours par un canal quelconque : il est public,
et c'est la campagne qui l'authentifie. Une demande substituée est refusée
avant même que le coffre s'ouvre.

Chaque installation doit faire **avancer** l'époque : réinstaller une époque
déjà employée avec une *autre* délégation ferait revenir un intermédiaire
retiré sous une signature encore parfaitement valide. Redéposer la **même**
délégation est un rejeu sans effet, ce qui répare une réponse perdue.

**Hors campagne**, pour un domaine dont le relais ne nomme aucune origine Astra :

```sh
astra issuer request --out issuer-request.json
# dans Orion : Approbations › « Signer une délégation sans campagne… »,
# choisir issuer-request.json, enregistrer issuer-authorization.json
astra issuer install --authorization issuer-authorization.json
```

Orion n'offre ce bouton que sans origine Astra dans le relais ; sinon le passage
par une campagne s'impose. Une demande de délégation ne porte **aucune
signature**. Par ce chemin, Orion signe donc le fichier qu'on lui présente, et
rien ne le rattache à cette autorité (« il vaut ce que vaut son transport ») :
c'est la forme de repli, pas la forme ordinaire.

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
ici avec la clé » ouvre la cérémonie dans l'onglet Astra. Sinon, dans l'Orion de
l'opérateur : onglet Astra › Approbations › « Approuver une récupération »,
saisir l'identifiant d'opération (32 caractères hexadécimaux), « Ouvrir la
cérémonie ». Cet Orion approuve sans finaliser : « Récupération approuvée. Le
poste concerné reprend de son côté. » Seul l'Orion qui a ouvert la récupération
depuis *Certificats* l'achève localement.

La cérémonie affiche le pair, la génération et depuis combien de temps
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

**Dans Orion** (chemin par défaut) : onglet Astra › *Coffre et clés*, « Marquer
perdue » ou « Réactiver » sur la clé, relais nommant la gateway. Orion réémet le
document de credentials, puis envoie aussitôt la copie du coffre à Astra par le
tunnel en y joignant ce document, qu'Astra adopte en mémoire, sans redémarrage.
La ligne qui suit le geste dit ce qui est parti : « Copie du coffre et document
de credentials envoyés à Astra », « Copie retenue par une opération en cours · à
renvoyer ensuite », ou l'erreur avec « Réessayer l'envoi ». L'ajout et le
retrait d'une clé suivent le même chemin.

Pour vérifier, tunnel monté : la ligne « Copie du coffre » du bloc *Astra* de
*Coffre et clés* compare l'époque du document local à celle qu'Astra sert.
« Document ancien » ou « Ancienne » veut dire qu'Astra tient encore l'ancienne
liste : « Envoyer » la lui porte. Pendant un recouvrement `CA-PQ`, Astra garde
l'ancien document jusqu'à `not_after` : la ligne dit « Copie envoyée · document
de credentials en attente (rotation en cours) », la clé perdue reste admise par
Astra d'ici là, et « Envoyer » est à refaire après `not_after` (voir « Limites
connues des rotations dans Orion »). Une clé perdue ne coupe pas le poste qui la
porte : pour couper le poste, voir §7.

Le recours, hors d'Orion :

```sh
# sur le poste de l'opérateur
astra-signer bindings --lost <key-slot>     # 32 caractères hexadécimaux
astra-signer bindings --active <key-slot>   # la remettre en service
```

Le document réémis est alors à copier dans le volume d'état d'Astra, puis Astra
à redémarrer (il le lit au démarrage) : c'est lui qui décide quelles rangées
peuvent répondre à une approbation.

## 7. Révoquer une identité compromise (§10)

Une révocation n'est pas un renouvellement. Elle retire les feuilles actives
immédiatement, annule tout staging concurrent et laisse l'identité dans l'état
terminal `revoked` : le poste devra être réadmis, pas rétabli.

**Depuis Orion (chemin par défaut, lot 5c).** Onglet *Astra* › *Postes*, une
ligne par poste du domaine. Pour un poste client :

1. **« Révoquer »** sur la ligne, puis un motif : « Volé ou perdu »
   (`suspected_compromise`), « Compromis » (`key_compromise`), « Plus utilisé »
   (`cessation`) ou « Remplacé » (`superseded`).
2. La confirmation : « Révoquer PORTABLE ? Le poste sera coupé tout de suite.
   C'est définitif. »
3. **La coupure, d'abord.** Orion lit l'admission de la gateway (`/api/network`)
   et vérifie que le nom désigne la clé WireGuard du poste. Sinon, il refuse
   et ne coupe rien : « Ce nom ne désigne pas ce poste sur la gateway. Rien n'a
   été coupé. » Sinon, il retire l'admission par `POST /api/peers/revoke`, par le
   tunnel. Cette étape n'attend ni Astra, ni le coffre, ni une clé.
4. **La signature.** Les clés que la campagne d'Astra demande, une par une, avec
   leur état affiché ; puis « Révoquer ». La décision est signée sous `CA-PQ` et
   déposée à Astra, qui marque le poste `revoked` et le relaie à la gateway.

Après la coupure, tout refus ou annulation est suivi de la phrase « Le poste est
coupé ; la révocation reste à signer. ». La ligne reste « Coupé, révocation à
signer », avec « Reprendre ». « Reprendre » ne refait pas la coupure. Une décision
déjà signée, et non confirmée, se redépose sans clé tant que sa campagne vit ;
passé ce délai, elle est jetée, et une nouvelle campagne s'ouvre avec ses clés.

Les états sont calculés à chaque ouverture de l'onglet, au bouton ↻ et après
chaque geste, à partir de la gateway et d'Astra ; rien n'est enregistré sur le
poste. Astra recopie les postes admis par la gateway, par un balayage toutes les
60 s, et à l'ouverture d'une révocation pour un poste qu'elle ne connaît pas
encore. Un poste que la gateway ne connaît pas non plus est refusé par son nom.

| État | Sens |
| --- | --- |
| Actif | admis à la gateway, non révoqué chez Astra |
| Renouvellement en cours | comme « Actif », avec un renouvellement du certificat en cours |
| Coupé, révocation à signer | plus admis à la gateway, non révoqué chez Astra |
| Révoqué | révoqué chez Astra et au registre de la gateway |
| Révoqué, gateway pas encore informée | révoqué chez Astra, pas encore appliqué par la gateway : le registre de la gateway ne le tient pas révoqué, ou le poste est encore admis ; Astra renvoie la révocation à la gateway jusqu'à son accusé |

**Le poste où tourne Orion** n'a pas de bouton « Révoquer » : sa ligne porte
« Ce poste » et la phrase « Se coupe sur la gateway : helios peer revoke `<nom>`. ».
Il ne se coupe pas depuis lui-même : la coupure se fait sur la gateway, par
l'outil `helios`, puis la révocation se signe depuis un autre poste
administrateur, où la ligne apparaît « Coupé, révocation à signer ».

**Pendant un recouvrement `CA-PQ`.** Le coffre garde la clé `CA-PQ` sortante, à
partir de la signature de la rotation, jusqu'à « Terminer la rotation CA-PQ »,
offert dès `not_after` et confirmé par une clé. Une révocation se signe sous
l'ancre qu'Astra vérifie : pendant le recouvrement, la clé sortante. Cette
signature est refusée à moins d'une heure de `not_after` (« Révocation possible
après … »). Une rotation faite avant le lot 5c ne garde pas sa clé sortante : la
signature y reste refusée jusqu'à `not_after`.

**Recours en ligne de commande** (jusqu'au lot 7). `astra-signer revoke` refuse
pendant un recouvrement `CA-PQ` : « Changement de CA-PQ en cours : révoquer ce
poste depuis Orion. Rien n'a été signé. ». Les commandes suivantes restent le
recours, dans le conteneur Astra :

```sh
astra revocation open --scope client --peer <clé-wg-base64> \
  --reason "poste volé" --requested-by "prénom.nom"
# → imprime l'identifiant et la commande complète à coller
```

Ou, depuis un poste administrateur du tunnel, comme au §2 avec
`"action":"client_revocation","peer":"<clé-wg-base64>"` : la réponse porte
l'identifiant d'opération et l'échéance signée (`revocation_expiries`).

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

`--not-after` n'est plus retapé : la réponse d'ouverture porte l'échéance
signée, et la console l'imprime dans la ligne à coller ; par le tunnel, elle
est dans `revocation_expiries`. Elle voyage hors de la campagne signée, parce
que le format partagé `CampaignTarget` ne porte pas l'échéance. Une valeur
altérée en route ne révoque pas la mauvaise chose : Astra refuse le dépôt
entier en la comparant à la génération active.

Deux révocations de deux postes différents peuvent attendre l'opérateur en
même temps ; une seconde révocation du **même** poste est refusée tant que la
première attend.

**Révoquer la gateway elle-même** — recours en ligne de commande (jusqu'au lot 7) ;
la voie d'Orion est au §7.1. Même cérémonie, une résolution en plus :

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

Ce canal est celui du service (`ASTRA_GATEWAY_CHANNEL` et
`ASTRA_GATEWAY_CERTIFICATE` d'`astra run`, que `deploy.sh` renseigne) : la
commande ne prend plus d'adresse, et sans canal privé dans le service elle est
refusée par son nom. Depuis le lot 6b, Orion ouvre aussi cette révocation par
le tunnel (§7.1) ; la commande ci-dessus reste le recours.

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

**Dans Orion (chemin par défaut, lot 6b).** Onglet *Rotations*, bloc « Identité
de la gateway », bouton « Révoquer la gateway ». Le motif est celui du poste
(§7) : « Volé ou perdu », « Compromis », « Plus utilisé » ou « Remplacé ». Puis
le remplaçant : « Avec remplaçant » (par défaut) ou « Sans remplaçant ».

- **Avec remplaçant : deux séries de touches**, annoncées avant de commencer
  (« Deux séries de touches : le remplaçant, puis la révocation. »).
  1. Campagne « Identité de remplacement de la gateway, avant sa révocation » :
     la transition de remplacement est signée en récupération de clé, avec des
     termes fixes de 7 jours, 7 jours et 365 jours, et les deux feuilles
     remplacées. Elle est déposée chez Astra, sans clé, puis enregistrée à côté
     du coffre (`pending-gateway-revocation.json`).
  2. La révocation, sous son propre libellé. Son manifeste affiche l'empreinte
     du remplaçant, lue sur l'objet signé et non saisie. Les deux moitiés, TLS et
     PQ, sont révoquées.
  Le remplaçant est installé après la révocation, dans cet ordre (étape 4 ci-dessous).
- **Sans remplaçant : une série de touches.** La confirmation dit « La gateway
  ne servira plus. Le domaine devra être reconstruit. » ; la case « Je confirme
  la révocation sans remplaçant » doit être cochée.

**Refus avant toute clé.**

- Pendant un recouvrement `CA-PQ`, le remplaçant est refusé, avec la date de fin
  du recouvrement quand elle est connue : « le remplacement de la gateway est
  possible après le …. La révocation sans remplaçant reste possible. ». Si la fin
  est déjà passée sur l'horloge du poste, la phrase ne donne pas de date.
- La révocation **sans** remplaçant pendant un recouvrement suit la règle du
  poste (§7) : elle est refusée avec « révocation possible après le … » dans la
  dernière heure avant la fin, ou pour une rotation qui n'a pas gardé sa clé sortante.

**Reprise.**

- Un remplaçant déposé dont la révocation n'est pas encore signée : Orion affiche
  « Révocation à signer » avec « Révoquer la gateway » (et non « Reprendre »), et
  la phrase « Le remplaçant est déposé ; la révocation reste à signer. Rien n'a
  été révoqué. ». La reprise, si elle est appelée, refuse sans rien appeler avec
  « La révocation reste à signer : choisir « Révoquer la gateway ». Rien n'a été
  révoqué. ».
- **Dépôt de la révocation refusé définitivement par Astra** (réponse HTTP autre
  que 429, 500 ou 503, par exemple 409) : la révocation est retirée du registre, le
  remplaçant reste déposé, et l'état devient « Révocation à signer ». « Révoquer la
  gateway » signe une nouvelle révocation. Sans remplaçant, il ne reste rien et le
  registre est effacé. Un dépôt sans réponse (429, 500, 503, ou injoignable) garde
  au contraire la révocation : « Reprendre » la redépose, sans clé, avec les mêmes
  octets.
- Une campagne de révocation expirée sans réponse : « Reprendre » tente d'installer
  le remplaçant, sans clé. Accepté, les deux étapes sont faites. Refusé
  définitivement par la gateway, la révocation n'a pas été appliquée : elle est
  retirée, et l'état redevient « Révocation à signer ». Injoignable, le registre
  est gardé pour une reprise. Sans remplaçant, la révocation expirée est jetée
  (« la campagne de la révocation a expiré avant le dépôt : la révocation est
  jetée. Reprendre la préparation. »).
- « Jeter la décision en attente » retire le registre sans clé, après la
  confirmation « La décision signée sera perdue. L'époque reste consommée. ».
  Orion ne le propose que lorsqu'un registre attend, et ne l'exécute pas pendant
  une cérémonie ouverte. Il est **refusé** tant qu'il reste un travail à finir ; la
  phrase du refus dit ce qui reste et se termine par « Rien n'a été jeté. » :
  - décision de renouvellement installée sur la gateway, non publiée :
    « la décision est installée sur la gateway mais pas encore publiée : la
    reprendre pour la publier. Rien n'a été jeté. » ;
  - révocation signée, non appliquée, ou dont le remplaçant n'est pas encore installé
    (le registre ne dit pas si un dépôt sans réponse est arrivé à Astra) :
    « la révocation de la gateway n'est pas finie : la reprendre pour la terminer.
    Rien n'a été jeté. ».
  Une annulation ne publie rien : elle se jette. Un remplaçant seul, déposé ou non,
  se jette, mais le remplaçant déjà déposé chez Astra n'y est pas annulé.

Deux cas sans issue par Orion. Le registre reste en place : il ne se reprend
pas et ne se jette pas, car jeter ne donnerait à la gateway rien qu'elle accepte.
Orion continue d'afficher le registre jusqu'à la reconstruction du domaine.

- **Remplaçant refusé définitivement** : une gateway révoquée refuse pour de bon le
  remplaçant qui lui est nommé. La révocation est appliquée, le remplaçant ne
  s'installe pas (`gateway_revocation.rs:297`, installation du remplaçant dans
  `carry_revocation`).
  Ce n'est pas réparable, comme une révocation sans remplaçant : la gateway ne
  servira plus, et le domaine doit être reconstruit.
- **Publication refusée définitivement** : une décision de renouvellement installée
  sur la gateway, dont la publication est refusée pour de bon (`carry`,
  `gateway_identity.rs:677-679`). Le registre reste, installé et non publié : ni
  reprise qui aboutisse, ni jet.

**Recours en ligne de commande** (jusqu'au lot 7). Les quatre étapes suivantes
sont celles de la machine à états, en commandes.

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

### Dans Orion (chemin par défaut, lot 6b)

Onglet *Rotations*, bloc « Identité de la gateway » en tête. Le bouton
« Renouveler l'identité de la gateway » ouvre deux options, décochées par défaut :

- « Remplacer aussi la feuille TLS » ;
- « La clé de la gateway est perdue », avec « Aucune preuve de continuité.
  Réservé à une clé disparue. » et la case « Je confirme la perte de la clé ».

Les termes sont fixes dans l'IHM : préparation 7 jours, recouvrement 7 jours,
validité 365 jours. « Continuer » lance la cérémonie. Les prérequis sont ceux de
*Rotations* : tunnel, administrateur, service Astra, coffre, domaine concordant.

Déroulé :

1. **Refus avant toute clé** : une décision ou une révocation en attente, une
   transition gateway déjà en cours, ou un recouvrement `CA-PQ` (le bouton est
   alors désactivé, avec « Recouvrement CA-PQ en cours »).
2. **Préparation et campagne.** La gateway prépare sa demande sur sa clé scellée,
   sans nouvelle clé (`new_key` est toujours faux). Astra ouvre la campagne
   `gateway_identity` par le tunnel. Orion vérifie, avant la première clé, que la
   feuille PQ en service est celle que la campagne fige, que la signature de
   continuité la couvre (sauf clé perdue), que la demande annoncée correspond, et
   que la feuille TLS candidate est présente si et seulement si la case est
   cochée. Une différence arrête le geste (« la feuille gateway en service n'est
   pas celle que la campagne fige », « la demande de la gateway ne correspond pas
   à la campagne », ou « la campagne d'Astra ne nomme pas cette gateway »).
3. **Cérémonie.** Une approbation par clé demandée (« Approuver avec la clé »).
   Le coffre émet la feuille PQ suivante et signe la transition dans le même
   geste. La décision est enregistrée à côté du coffre
   (`pending-gateway-decision.json`) avant tout dépôt.
4. **Dépôt, installation, publication.** La décision est déposée chez Astra, puis
   installée sur la gateway, qui la vérifie sous ses ancres et la refuse si la
   clé privée d'une feuille n'est pas scellée chez elle. Enfin Astra la publie
   (`gateway-identity/publish`). Une publication non confirmée se reprend.

Après publication, la ligne affiche « Bascule le … ». La transition ne prend
effet qu'à la date d'activation, et ce basculement demande le redémarrage de
`heliosd` (§11).

**Reprise.** Une décision enregistrée et non déposée, dont la campagne a expiré,
est jetée à la lecture : la préparation repart de zéro. Une décision déposée
attend l'installation et la publication, quelle que soit l'heure. « Reprendre »
ne demande aucune clé.

**États de la ligne**, lus à chaque ouverture, au bouton ↻ et après chaque geste :

| État | Sens et actions |
| --- | --- |
| À faire | une échéance de feuille gateway est à moins de 30 jours. « Renouveler », « Révoquer la gateway » |
| Échéance le … | la plus proche des deux échéances, au-delà de 30 jours. « Renouveler », « Révoquer la gateway » |
| Échéance inconnue | aucune échéance lue. « Renouveler », « Révoquer la gateway » |
| Installée, publication à faire | transition installée, non publiée. « Annuler » tant que l'activation n'est pas atteinte |
| Décision à reprendre | décision en attente non installée. « Reprendre », « Jeter la décision en attente » |
| Annulation à reprendre | annulation en attente. « Reprendre », « Jeter la décision en attente » ; jamais une nouvelle annulation |
| Bascule le … | publiée, avant l'activation. « Révoquer la gateway » |
| Recouvrement jusqu'au … | l'ancienne et la nouvelle identité servent. « Revenir à l'ancienne identité », « Révoquer la gateway » |
| Révocation à signer | remplaçant déposé, révocation à signer. « Révoquer la gateway », « Jeter la décision en attente » |
| Révocation à reprendre | révocation en attente, non appliquée. « Reprendre », « Jeter la décision en attente » |
| Révocation appliquée, reprise à faire | révocation appliquée, remplaçant à installer. « Reprendre », « Jeter la décision en attente » |

« Jeter la décision en attente » est refusé tant qu'un travail reste à finir. Pour
une décision installée et non publiée : « la décision est installée sur la gateway
mais pas encore publiée : la reprendre pour la publier. Rien n'a été jeté. » (§7.1
pour les révocations).

Quand la gateway signale un redémarrage à faire (`gateway_restart_due`), la ligne
affiche « Redémarrer heliosd sur la gateway. », avec la raison donnée par la
gateway en « Détail technique : … ». Rien ne redémarre à sa place.

**Limites de cette version.** La réponse « demande reprise » de la gateway n'est
pas affichée dans Orion. Les termes ne se règlent pas dans l'IHM ; le backend
d'Orion accepte pourtant des durées de 1 à 3650 jours.

### Recours en ligne de commande (jusqu'au lot 7)

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

La campagne lit l'identité **en direct sur le canal privé** du service
(`ASTRA_GATEWAY_CHANNEL`, comme au §7), auprès du démon qui la sert. Astra
enregistre la génération de chaque client ; elle n'a jamais détenu les feuilles
de la gateway, et le §11.1 étape 3 en exige les empreintes exactes. Une valeur retapée produirait une campagne que le compagnon signe et
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
un relais que la première n'a pas pu confirmer ; tant que la gateway n'a pas
confirmé, la commande se termine en erreur et demande d'être relancée.

Service en marche, la publication passe par lui. Service arrêté, elle s'écrit
localement sous le verrou du volume et relaie par le canal que le service
emploierait : elle lit alors `ASTRA_GATEWAY_CHANNEL` et
`ASTRA_GATEWAY_CERTIFICATE` dans son environnement, et refuse sans eux.

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

**Dans Orion (chemin par défaut, lot 6b).** Le bouton « Revenir à l'ancienne
identité » n'apparaît que pendant le recouvrement, entre l'activation et la fin
du recouvrement. Deux saisies :

- la durée, en heures, de 1 à 168, 24 par défaut ; la durée ne dépasse jamais la
  fin du recouvrement ;
- le motif, de 1 à 200 caractères.

Les bornes sont vérifiées avant tout appel. Le demandeur est le nom du poste
connecté. Aucune campagne Astra ne s'ouvre : la sélection est résolue depuis la
transition que la gateway tient, affichée en entier, puis signée après un
toucher par clé demandée. La pose se fait par la gateway elle-même.

Refus avant toute clé :

- transition non publiée, avant l'activation, ou après la fin du recouvrement :
  « aucun recouvrement en cours : l'ancienne identité n'est pas celle qui sert.
  Rien n'a été signé. » ;
- une révocation de la gateway en attente : « une révocation de la gateway attend
  dans le registre : la reprendre ou la jeter avant d'ouvrir une autre décision. »

Après la pose, la ligne affiche « Retour arrière jusqu'au … » tant que la
sélection tient. Si Orion affiche « Redémarrer heliosd sur la gateway. », le
redémarrage reste à faire par l'opérateur (§11).

**Recours en ligne de commande** (jusqu'au lot 7) :

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

**Dans Orion** (chemin par défaut) : ligne « Remplacer la CA TLS » (expiration
de la CA lue dans le coffre si elle se lit sans l'ouvrir), même déroulé qu'au §3
(prérequis, deux clés validées, « Approuver », dépôt, installation par la route
`POST /api/certificates/client-tls-ca-transition` que la gateway vérifie sous sa
`CA-PQ`). La validité par défaut est de 1825 jours. Deux rotations de CA ne
tournent pas ensemble : pendant le recouvrement de l'une, les deux boutons
« Remplacer » sont désactivés. **À `not_after`, la ligne « Terminer la rotation
CA TLS » apparaît en tête** et remplace `promote-ca-tls` (une clé, sans nouvelle
autorisation) ; Orion n'a pas d'ordonnanceur, donc elle attend l'ouverture de
l'onglet, et la gateway a déjà avancé son époque pendant ce temps. Les commandes
suivantes sont le recours.

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
`astra bootstrap --ca-tls-fingerprint`. Service en marche, l'épinglage passe
par lui, et la campagne `trust-authorities` suivante montre la ligne CA-TLS
sans redémarrage ; service arrêté, il s'écrit localement, sous le verrou du
volume — c'est le chemin de `deploy.sh`.

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
fichier existe, `rotate-ca-tls` refuse d'ouvrir une seconde fenêtre. Orion
adopte un tel enregistrement une fois (marqueur posé après l'écriture de son
journal) et le reprend comme sa propre rotation.

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

**Limite connue** : rien ne lance la fin de rotation à `not_after`. La gateway
avance son époque toute seule à cette seconde ; le coffre, lui, attend
l'opérateur, et jusque-là il continue d'estampiller l'ancienne — que la
gateway refusera désormais. Dans Orion, « Terminer la rotation CA TLS » reste
« À faire » en tête de liste tant que ce n'est pas fait, mais seulement à
l'ouverture de l'onglet : Orion n'a ni ordonnanceur ni notification. Avec la
commande, le fichier `astra-prepared.json` en garde la trace et
`resume-rotation` la rappelle.

## 10. Renouveler toute la chaîne (§7.6)

« Toute la chaîne » couvre l'émetteur délégué, la CA TLS cliente, l'identité
gateway et les feuilles du parc — **pas `CA-PQ`**, qui a sa propre cérémonie
(§3 de cette note).

**Dans Orion : pas encore.** « Tout renouveler » n'est pas dans Orion : le lot 6b
l'a détaché, parce que chaque geste du plan devrait être contrôlé avant l'ouverture
du plan, ce qui change la conception (suivi F14-g dans [ROADMAP.md](ROADMAP.md)).
Le plan se joue sur la console d'Astra, comme ci-dessous. Le tunnel porte déjà les
routes du plan (`POST /api/certificates/operator/chain/next` et `…/chain/abandon`,
et l'ouverture `chain_open`) ; Orion ne les appelle pas. Le statut lu par le
tunnel (`GET /api/certificates/operator/status`) nomme le plan en cours (`chain`).

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

La première étape est ouverte. Ensuite, pour chacune des suivantes :

```sh
# depuis le poste opérateur : approuver l'étape en cours, avec sa commande
# propre (astra-signer authorize-issuer, rotate-ca-tls,
# sign-gateway-transition, approve-campaign).

# puis, sur la gateway :
astra chain next
```

`astra chain next` **refuse d'avancer** tant que l'effet de l'étape en cours
n'apparaît pas dans le registre : l'époque de l'émetteur a bougé, l'ancre TLS a
un successeur, la décision gateway a été stockée. Ce n'est pas « l'opérateur a
approuvé » — une approbation dont l'objet n'a jamais atterri n'a pas déplacé le
domaine, et résoudre la campagne suivante contre cet état figerait une
situation que personne n'a atteinte.

L'étape d'identité gateway est résolue sur les feuilles que le démon sert
réellement, qu'Astra n'a jamais détenues, lues par le canal privé du service
(`ASTRA_GATEWAY_CHANNEL`, comme au §7) : `chain next` ne prend plus d'adresse
de gateway. Le plan reste dans le volume d'état, et le service seul l'écrit.

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
  et §11.6 garde cette résolution dans Astra — une campagne est l'inventaire du
  domaine, et une route publique non authentifiée qui la résoudrait la
  répondrait à n'importe quel appelant. La console les nomme avec leur
  commande ; elles se lancent dans le conteneur Astra, ou, pour le parc et les
  autorités, par la route du tunnel (voir « Les commandes `astra` de ce
  document »).
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

## Limites connues des rotations dans Orion

À connaître avant de lancer une rotation. Les suivis sont
dans [ROADMAP.md](ROADMAP.md) (F14-a à F14-f).

- **« Délai dépassé » n'a pas de réparation.** La gateway refuse une transition
  une fois `activation_at` passé (7 jours après la signature par défaut, 1 jour
  au moins), et le coffre local ne peut plus en signer une autre : la clé
  sortante n'y est plus. L'écran affiche « Délai dépassé », la date de coupure
  (`not_after`, où Astra avance seul et la gateway reste sur l'ancienne ancre)
  et « Intervention manuelle requise » quand une reprise le constate auprès de
  la gateway ; avant, d'après les seules données du poste, la ligne dit « Délai
  d'installation passé : à vérifier à la connexion », car le journal peut encore
  se reprendre sans dommage. Éviter le cas : laisser Orion installer aussitôt
  après l'acceptation, et se connecter dans la semaine.
- **De `Applied` à `not_after` (37 jours au plus par défaut), une révocation
  n'est signable que si la rotation garde la clé sortante.** Depuis le lot 5c,
  une rotation `CA-PQ` signée depuis ce lot garde sa clé sortante au coffre
  jusqu'à « Terminer la rotation CA-PQ ». Une rotation antérieure ne la garde
  pas : la révocation d'un poste y est refusée jusqu'à `not_after`, après la
  coupure (§7).
- **De `not_after` à la re-délégation (§4), l'émission en ligne est refusée.**
  Les feuilles déjà émises restent valides jusqu'à leur échéance ; rien ne
  prévient hors d'Orion.
- **Pendant un recouvrement CA-PQ, rien ne s'approuve sous le document local,
  sauf la révocation d'un poste.** « Renouveler les postes », tout lancement
  d'*Approbations*, la récupération et la délégation sont désactivés, avec la
  raison. La révocation d'un poste s'approuve sous le document que sert Astra
  (§7). Le renouvellement d'une feuille cliente par le moteur d'Orion se lit
  comme toujours possible (testé côté Orion ; côté Astra, non exercé).
  « Renouveler les postes » reste bloqué pendant un recouvrement CA-PQ, décision
  du 8 novembre 2026 : les campagnes de parc ne portent aucune signature de CA,
  et garder l'ancien document pour elles rétablirait le renouvellement du parc
  pendant le recouvrement. « Remplacer la CA-PQ » affiche, à ses prérequis, les
  postes qui expirent pendant le changement : c'est un avertissement, non un
  blocage.
- **Révocation pendant un recouvrement CA-PQ.** La signature se fait sous la clé
  sortante gardée, y compris pendant le recouvrement, « Reprendre » compris. Elle
  est refusée dans la dernière heure avant `not_after`, et pour une rotation qui
  n'a pas gardé sa clé ; dans les deux cas, la coupure reste faite et le refus
  dit « Révocation possible après le … ». Une rotation dont l'ancre n'est pas
  détenue par ce coffre refuse avec « Astra vérifie sous une ancre que ce coffre
  ne détient pas ».
- **Une clé marquée perdue pendant un recouvrement CA-PQ reste admise par Astra
  jusqu'après `not_after`.** Orion n'y joint pas le document de credentials, et
  Astra adopte à `not_after` celui de la rotation, signé avant le marquage.
  « Copie du coffre » passe alors à « Document ancien » : « Envoyer » dans
  *Coffre et clés* porte le document à jour.
- **Un dialogue de clé de la plateforme qui ne revient jamais** n'a pas de borne
  sur les ouvertures gardées en mémoire : seul un redémarrage d'Orion y met fin.
  Rien n'est écrit sur le disque avant la signature. Un GUID d'annulation
  fermerait le cas sous Windows.
- **Le recours en ligne de commande** (`astra-signer rotate-ca-pq`, jusqu'au
  lot 7) : sa reprise déplace le coffre, les credentials et le relais sans parole
  d'Astra, par le geste voulu de l'opérateur ; c'est une exception à la règle
  d'Orion « le coffre ne bouge qu'après l'acceptation d'Astra ». Un journal
  adopté d'un tel enregistrement se lit d'abord auprès d'Astra. Le successeur de
  ce recours, quand F14 absorbe `astra-signer`, reste à nommer.
- **La copie du coffre sur la gateway** : un administrateur du tunnel peut la
  remplacer (Astra n'en lit que le domaine, et ne peut pas l'ouvrir) ; une
  génération précédente est gardée, pas davantage ; une sauvegarde hors de la
  gateway n'est pas couverte. Deux postes tenant un même domaine peuvent écraser
  une copie plus récente d'Astra, seul le domaine étant contrôlé. Une copie
  de plus de 128 Kio est refusée (ce que le téléchargement porte). Une
  copie différente envoyée pendant une opération en attente de l'opérateur
  répond `409` : réessayer après son expiration (300 s au plus). Un document de
  credentials joint pendant une rotation `CA-PQ`, ou avant que la promotion de
  son document soit durable, répond `409` aussi ; Orion renvoie alors le seul
  coffre et dit que le document attend.
- **Un écrasement raté peut effacer un journal à tort.** Si une écriture
  échoue après son renommage et que la campagne meurt avant un rejeu, Orion
  efface son journal alors que le fichier d'Astra tient l'ancre : réparation
  manuelle. Il faut un échec de synchronisation du dossier et 300 s sans rejeu,
  sur un volume déjà défaillant.
- **`write_domain_relay` n'est pas couvert par la garde d'écrasement.** Les
  gestes sur les clés et les renommages sont refusés tant qu'un coffre scellé
  attend d'écraser celui en place (enregistrement `astra-signer` présent,
  journal illisible, ou journal avec coffre suivant) ; l'écriture du relais de
  domaine ne l'est pas.
- **Gateway plus ancienne que le lot** : la reprise affiche qu'il faut mettre la
  gateway à jour, sans rien effacer. Une gateway à jour sans CA TLS configurée
  se lit de même.

## Vérifier où en est le domaine

```sh
astra status --expected-audit-head <empreinte notée à la dernière opération>
heliosd show-trust-enrolment <clé-du-pair>
astra-signer list          # les key-slots du coffre, sans clé de sécurité
```

`astra status` refuse une chaîne d'audit qui bifurque : une sauvegarde qui se
vérifie toute seule mais finit ailleurs est une fourche, et une autorité qui la
continuerait émettrait sous deux histoires à la fois. C'est une lecture pure :
service en marche ou non, elle n'écrit jamais le registre, même pour le migrer
vers un format plus récent — l'écrivain suivant s'en charge.
