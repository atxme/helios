# F14-f : copie du coffre — refus d'une copie en retard, export, garde du relais

*Conception du 15 novembre 2026. Suit le lot 5b (§5.9 et son amendement du 7 novembre
2026, §10.5, §10.6) et F14-e. Ne bloque pas le lot 7 : `astra-signer` n'a aucune commande
de sauvegarde ni de copie.*

## 1. Intention

Le ROADMAP liste quatre limites sous F14-f (spec 5b, §10, « Copie du coffre ») :

1. un administrateur du tunnel peut remplacer la copie du coffre (une génération précédente
   gardée) ;
2. aucune sauvegarde hors de la gateway ;
3. deux postes tenant un même domaine peuvent écraser une copie plus récente d'Astra (seul le
   domaine est contrôlé) ;
4. `write_domain_relay` n'est pas couvert par la garde d'écrasement.

**Choix de l'utilisateur (option B)** : lever 2, 3 et 4 ; la limite 1 reste documentée. Le
risque visé est un poste honnête en retard qui ramène dans la sauvegarde d'Astra une clé
retirée, ou défait une rotation. Signer chaque copie (option C) aurait fermé la limite 1 au
prix des clés à chaque envoi, contre un adversaire qui administre déjà la gateway : écarté.

## 2. Objectifs, non-objectifs, anti-objectifs

**Objectifs**

- Astra refuse une copie plus ancienne que la sienne, ou divergente, et Orion le dit.
- L'opérateur peut, en connaissance de cause, remplacer quand même la copie d'Astra.
- Orion exporte le coffre chiffré dans un fichier choisi par l'opérateur.
- L'écriture du relais de domaine est refusée tant qu'un coffre scellé attend d'écraser celui
  en place.

**Non-objectifs**

- Authentifier la copie ou son ordre (limite 1, gardée).
- Restaurer un coffre depuis Astra par le réseau. Le recours d'un poste en retard est le coffre
  à jour, exporté depuis le poste qui le tient, puis choisi comme emplacement (geste existant
  « Choisir l'emplacement du coffre »).
- Garder plus d'une génération précédente sur la gateway.

**Anti-objectifs**

- Aucun octet du coffre, PIN ni secret dans la WebView ou le journal : l'export est écrit par
  Rust, le chemin vient de la boîte native, jamais de la WebView.
- Un refus de copie ne remet jamais une rotation en cause (règle du §5.9 : la ligne reste
  « À faire »).
- Un coffre existant, sans compteur, continue de s'ouvrir et de s'envoyer.

## 3. Approches considérées

1. **Compteur de révision en clair dans le coffre** — retenue par l'utilisateur. Un champ
   `revision` augmente à chaque écriture ; hors des données authentifiées du scellement, il
   s'augmente sans clé ; non authentifié, ce qui suffit contre un poste honnête en retard.
2. **Filiation** (chaque coffre retient l'empreinte de son prédécesseur) : refuserait à tort
   un poste qui enchaîne deux gestes sans envoyer. Écartée.
3. **Contrôle de l'ancre CA-PQ seule** : sans changement de format, mais ne couvre pas un ajout
   ou un retrait de clé. Écartée.

## 4. Conception

### 4.1 Le compteur dans le coffre (`crates/astra-operator`)

- `AuthorityVault` gagne `revision: u64`, `#[serde(default, skip_serializing_if = zéro)]` : un
  coffre ancien se lit à 0 et, tant qu'il n'est pas réécrit, reste lisible par un binaire
  antérieur.
- Le champ reste hors de `payload_context` (identifiant du coffre, domaine, empreinte de la
  table des clés) : l'augmenter ne demande pas de rescellement, donc aucune clé.
- `store::save` écrit la révision `max(révision de la valeur, révision du fichier en place) + 1`
  (`saturating_add`), la révision du fichier en place lue sans clé, 0 s'il est absent ou
  illisible. La signature ne change pas. *(Mon choix.)* Ainsi un coffre construit à part — le
  coffre suivant scellé dans un journal de rotation, y compris un journal antérieur au
  compteur — ne repart jamais en dessous du coffre qu'il remplace, et deux écritures
  successives depuis la même valeur donnent N+1 puis N+2. Tous les chemins d'écriture d'un
  coffre existant passent déjà par `save` ; les gestes sur les clés sont refusés tant qu'un
  coffre scellé attend, donc rien ne s'intercale entre le scellement et l'application.
- `store::save_new` écrit un coffre neuf à la révision 1.
- **Compatibilité** : `AuthorityVault` refuse les champs inconnus. Un Orion ou un
  `astra-signer` antérieur ne lit plus un coffre qui porte le compteur ; les deux sont livrés
  ensemble. Limite documentée.

### 4.2 Le refus dans Astra (`crates/astra`, `door/vault_copy.rs`)

- `VaultHeader` lit aussi `revision` (`serde(default)`), sans clé, comme le domaine.
- Règle, sous le verrou du volume et le registre tenu, avant toute écriture, pour une copie
  différente de celle tenue :
  - la copie tenue est à 0 (ancienne, aucune, ou un en-tête illisible) : acceptée, rien pour
    ordonner, comme aujourd'hui *(mon choix)* ;
  - révision envoyée **inférieure** à celle tenue : refusée, « en retard » ;
  - révision **égale**, contenu différent : refusée, « divergente » (deux postes ont avancé
    chacun de leur côté) ; le même coffre mis en page autrement (copie `scp` lisible, forme
    compacte d'Orion) n'est pas une divergence et est accepté.
- Une copie identique passe toujours, comme aujourd'hui.
- **Ordre** : taille, en-tête et domaine, identique, puis le refus `412`, puis le `409` d'une
  opération vivante *(mon choix : le refus définitif d'abord, plutôt qu'une attente de 300 s
  suivie du même refus)*. Avec `replace_newer`, le `409` s'applique comme aujourd'hui.
- **Remplacer quand même** : `OperatorVaultCopy` gagne `replace_newer: bool`
  (`serde(default, skip_serializing_if = faux)`, donc absent d'un envoi ordinaire et
  compatible avec une gateway antérieure). Vrai, la règle ci-dessus est levée ; tout le reste
  vaut (domaine, taille, opération vivante `409`, document de credentials). La copie
  précédente est gardée comme toujours. Le journal d'Astra note l'opérateur, l'empreinte et
  le remplacement forcé. C'est aussi le recours contre un compteur gonflé par un
  administrateur malveillant.
- Nouvelle classe de refus, distincte du `403` indistinct et du `409` : **`412`**, sans
  distinguer en retard et divergente dans la réponse (la phrase reste au journal d'Astra). La
  route ne répond qu'à un administrateur, comme pour le `409`.
- `OperatorAuthorityStatus` gagne `vault_copy_revision: Option<u64>` (`serde(default)`) :
  `None` sans copie ou d'un Astra antérieur.
- Le relais `helios-api` / `heliosd` transmet le `412` tel quel.

### 4.3 Orion

- `tunnel::send_vault_copy` rend `VaultCopySent::Stale` sur un `412`. `advance` (reprise d'une
  rotation) le traite comme un échec de l'envoi : la rotation est finie, la ligne « Copie du
  coffre » reste « À faire » ; rien ne tourne en boucle.
- La ligne « Copie du coffre » de *Coffre et clés* (tunnel monté) compare aussi la révision
  locale, lue sans clé (le coffre se charge sans clé, comme pour le domaine), à
  `vault_copy_revision` : une révision d'Astra plus haute affiche **« Plus récente sur
  Astra »**. Ce statut l'emporte sur « Ancienne » et « Document ancien ». Coffre local
  illisible, ou Astra sans révision : la ligne garde son statut actuel.
- Un `412` sur l'envoi automatique de fin de rotation est voulu : la rotation a avancé le coffre
  local, et Astra en tient un plus haut, donc un autre poste a avancé de son côté ; c'est la
  divergence que la ligne doit montrer.
- Un envoi refusé (`412`) dit : **« Astra tient un coffre plus récent que celui de ce poste,
  ou qui a divergé. Récupérez le coffre à jour sur le poste qui le tient. »**, avec un bouton
  **« Remplacer quand même »** et l'avertissement **« La copie d'Astra sera remplacée par ce
  coffre. À ne faire que si vous savez que la copie d'Astra est fausse. »** Ce bouton renvoie
  la copie avec `replace_newer`, relue sur le disque au moment du clic *(mon choix)*. Il n'est jamais proposé automatiquement ni pendant la
  reprise d'une rotation.
- **« Exporter le coffre »** dans *Coffre et clés*, sans clé ni tunnel : boîte native
  « Enregistrer sous » (même mécanisme que le choix d'emplacement, sous Windows), nom proposé
  `authority-vault-AAAA-MM-JJ.json`. Rust copie les octets du fichier du coffre, écriture
  privée et atomique, et refuse d'écrire sur le fichier du coffre lui-même, chemins
  canonisés comparés *(mon choix ; un lien physique vers le coffre n'est pas détecté)*. La WebView ne
  reçoit que « Coffre exporté » ou l'erreur. Hors Windows, comme le choix d'emplacement.
- L'export ne contient que le coffre : le relais se reconstruit depuis le coffre et la gateway.
  Le document de credentials (`astra-credentials.json`) n'en fait pas partie ; au recouvrement,
  on le copie à la main depuis le coffre à jour, à côté du coffre exporté.

### 4.4 Garde du relais

- `vault_gestures::write_relay` appelle `rotation_journal::ensure_vault_not_awaiting_overwrite`
  avant toute lecture, comme les gestes sur les clés, et refuse avec la même phrase.

## 5. Ce qui ne change pas

Borne de 128 Kio, `409` d'une opération vivante ou d'un document retenu, contrôle du domaine,
une seule génération précédente, envoi automatique en fin de rotation, document de credentials
joint seulement hors recouvrement.

## 6. Documentation

- `RENOUVELLEMENT-CERTIFICATS.md` : limites mises à jour (copie en retard refusée,
  « Remplacer quand même », export, relais gardé ; limite 1 restante ; compatibilité du
  compteur).
- `MANUAL-TESTING.md` : section « M. F14-f ».
- Spec 5b : amendement du 15 novembre 2026 sous « Copie du coffre ».
- `ROADMAP.md` : F14-f levé ; la ligne F14-e dit qu'il est fusionné (15 novembre 2026,
  Helios 3.4.8 / Orion 4.4.0).

## 7. Tests attendus

- Coffre : un coffre ancien se lit à 0 et se réécrit à 1 ; deux `save` successifs depuis la
  même valeur donnent N+1 puis N+2 ; un coffre à 0 écrit sur un fichier à N passe à N+1 ;
  une rotation (`apply_local`) laisse le coffre au-dessus de celui qu'elle remplace ; la
  révision ne change pas l'ouverture.
- Astra : en retard refusé, divergente refusée, identique acceptée, tenue à 0 ou illisible
  acceptée, `412` avant `409`,
  `replace_newer` accepté et précédente gardée, rien écrit sur un refus, statut porte la
  révision.
- Relais : `412` transmis.
- Orion : `Stale` ne bloque pas la reprise ; ligne « Plus récente sur Astra » ; bouton
  « Remplacer quand même » ; export écrit les mêmes octets et refuse le chemin du coffre ;
  `write_relay` refusé pendant un coffre scellé en attente.

## 8. Laissé au constructeur

Noms internes, placement des tests, découpage des commits, forme exacte du message de refus
dans le journal d'Astra.
