# Renouveler un certificat Helios : toutes les commandes

Aide-mémoire d'exploitation. Chaque section couvre **un** objet du domaine :
ce qui le fait tourner, qui doit être présent, et ce qui se passe si on ne fait
rien. La référence normative reste
[ROTATION-CERTIFICATS.md](specification/ROTATION-CERTIFICATS.md) ; ce document
ne décide rien, il ordonne des gestes.

## Ce qui n'a besoin d'aucune commande

Trois choses tournent sans qu'un opérateur intervienne, et c'est voulu :

- **la feuille cliente d'un poste allumé.** À 80 % de sa vie, Orion propose
  « Renouveler maintenant » ; l'utilisateur clique, un opérateur approuve, le
  poste committe. C'est le chemin ordinaire du §7 ;
- **la confiance d'un client en retard.** À chaque montée de tunnel, Orion
  demande une fois à la gateway s'il lui manque quelque chose. Ce qui revient
  est signé, ordonné, et n'est appliqué qu'entier ;
- **la purge** des étapes de staging qu'aucun client n'a committées.

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

## 7. Ce qui n'a pas encore de commande

Nommé plutôt que passé sous silence : chacune de ces lignes est un geste qu'un
opérateur pourrait avoir besoin de faire aujourd'hui, et qu'aucune commande ne
fait.

- **Révoquer une identité** (§10). L'objet et la route privée existent —
  `EmergencyCertificateRevocation`, `POST /internal/v1/certificates/revoke` —
  mais rien ne le signe ni ne le dépose : ni `astra-signer` ni `astra` n'ont de
  sous-commande de révocation. En attendant, un pair se retire par sa
  configuration WireGuard, ce qui coupe l'accès sans produire la décision
  signée que les clients appliqueraient.
- **`CA-TLS` cliente** (§9.4) : aucun geste ne la fait tourner, et le registre
  la refuserait — il épingle l'époque de cette ancre sans épingler l'ancre.
- **L'identité gateway** (§6) : aucun producteur de transition.
- **Le retour à l'identité précédente** : rien ne la conserve, le magasin
  protégé ne garde qu'un lot par nom.
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
