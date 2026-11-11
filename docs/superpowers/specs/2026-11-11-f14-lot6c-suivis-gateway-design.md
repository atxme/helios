# F14 lot 6c : les suivis de l'identité de la gateway

Conception du 11 novembre 2026. Suite du lot 6b (identité de la gateway depuis
Orion, `docs/superpowers/specs/2026-11-10-f14-lot6b-identite-gateway-design.md`).
Couvre les suivis F14-h, F14-i et F14-j de `ROADMAP.md`. F14-g (« Tout
renouveler ») a sa propre conception, après ce lot. Branche
`feat/f14-lot6c-suivis-gateway`.

## 1. Intention

Le 6b a livré les gestes de l'identité de la gateway. Il a laissé trois limites,
toutes notées dans `RENOUVELLEMENT-CERTIFICATS.md` §7.1 et §8 :

- **F14-h :** Orion ne dit pas qu'il a repris une demande déjà préparée, et les
  durées de la transition sont fixes (7, 7 et 365 jours) ;
- **F14-i :** la gateway ne dit pas au tunnel qu'elle est révoquée. Le bloc
  propose donc encore des gestes que la gateway refusera ;
- **F14-j :** deux registres n'ont aucune issue (remplaçant refusé
  définitivement, publication refusée définitivement). Une révocation peut aussi
  être abandonnée à tort sur un refus tardif d'Astra.

Ces limites doivent être levées avant le lot 7. Une fois `astra-signer` retiré,
une impasse d'Orion n'aura plus de recours en ligne de commande.

## 2. Décisions de l'utilisateur (11 novembre 2026)

- Finir correctement tous les suivis avant le lot 7.
- L'ordre et le découpage sont délégués au concepteur : le lot 6c regroupe
  F14-h, F14-i et F14-j, qui portent tous sur le bloc « Identité de la
  gateway ». F14-g vient ensuite, puis F14-e, F14-f et le lot 7.
- Les règles des lots 5b et 6b restent valables : prérequis vérifiés avant
  toute clé, libellés courts et neutres sans « tu », aucun état qu'Orion
  « croit », messages d'erreur qui nomment la cause et aucun secret dans la
  WebView.

Toutes les autres décisions de ce document sont des choix du concepteur.

## 3. Objectifs

1. **Demande reprise affichée (F14-h)** : quand la gateway rend une demande déjà
   préparée pour l'époque (`reused`), Orion l'écrit avant les clés.
2. **Durées réglables (F14-h)** : préparation, recouvrement et validité se
   saisissent dans « Renouveler l'identité de la gateway ». Les valeurs par
   défaut restent 7, 7 et 365 jours, et les valeurs sont vérifiées avant toute
   clé.
3. **État « Révoquée » (F14-i)** : la vue du domaine porte la révocation de la
   gateway et le remplaçant qu'elle attend. Le bloc affiche alors « Révoquée »
   et ne propose plus que les gestes que la gateway acceptera.
4. **Sonde avant abandon (F14-j, point 2)** : une révocation dont le dépôt est
   refusé définitivement n'est retirée du registre qu'après lecture de la vue de
   la gateway, qui dit si elle a été appliquée.
5. **Jet forcé (F14-j, point 1)** : les deux registres sans issue se jettent par
   un geste explicite, derrière une confirmation qui nomme la conséquence.
6. Documentation et recette (§8).

## 4. Non-objectifs et anti-objectifs

- **F14-g, F14-e, F14-f, F14-a, F14-d** : hors lot.
- **Réparer une gateway révoquée sans remplaçant, ou une transition non publiée
  au-delà de son activation** : ni le lot ni Orion ne le font. Le domaine se
  reconstruit (RENOUVELLEMENT §7.1, §11). Orion le dit, sans le cacher.
- **Changer la machine à états de la gateway** (`aether`,
  `state/gateway_identity.rs`) : le lot lit `revoked` et
  `awaited_replacement`, il ne modifie aucune règle.
- **Anti-objectif** : le jet forcé n'efface jamais un registre qui peut encore
  aboutir. Il n'est proposé que dans les deux impasses du §5.4, chacune
  constatée par une lecture de la gateway ou par un refus définitif enregistré.
  Il ne remplace pas le jet ordinaire du 6b, qui garde ses refus.
- **Anti-objectif** : aucun drapeau de révocation déduit d'un refus. L'état
  « Révoquée » vient de la vue de la gateway, jamais d'une erreur interprétée
  par Orion.

## 5. Conception

### 5.1 Demande reprise (F14-h)

`GatewayRenewalView.reused` existe déjà (`crates/helios-api/src/certificates/gateway_identity.rs`)
et `heliosd` le remplit. L'ouverture du renouvellement (`open_renewal`,
`crates/astra-operator/src/operations/gateway_identity.rs`) le lit et le garde
dans l'opération ouverte. Le statut de la cérémonie le porte jusqu'à l'IHM.
Avant les clés, l'écran affiche « Demande déjà préparée par la gateway pour
cette époque : elle est reprise, sans nouvelle clé. ».

La révocation avec remplaçant prépare aussi une demande (`open_replacement`,
`gateway_revocation.rs`). La même phrase s'y affiche.

### 5.2 Durées réglables (F14-h)

Le formulaire « Renouveler l'identité de la gateway » remplace la phrase fixe
des termes par trois champs : « Préparation (jours) », « Recouvrement (jours) »
et « Validité (jours) ». Leurs valeurs par défaut sont 7, 7 et 365. Le champ et
sa validation reprennent le modèle des termes du 5b (`RotationSteps.tsx`,
fonction `field` et brouillon `draft`), sans nouveau composant.

- **Bornes** : celles qu'impose déjà la signature (`after`, `RenewalOptions`).
  Le builder les lit dans `astra-operator` et dans l'état de la gateway
  (`GatewayIdentityTransition::verify` et la fenêtre). L'IHM et le backend
  appliquent les mêmes bornes, définies à un seul endroit par crate. Une valeur
  hors bornes est refusée avant toute clé, avec la plage dans le message, comme
  au 5b.
- **Cohérence avec l'ancre** : si la feuille ne peut pas dépasser l'échéance de
  `CA-PQ` (ou si la gateway la refuse dans ce cas), le refus a lieu avant les
  clés et nomme la date. Au builder de vérifier ce que le code impose. Il ne
  faut pas inventer de règle.
- La révocation avec remplaçant garde ses termes fixes (`gateway_revocation.rs:74`).
  C'est un geste d'urgence, et le lot n'y ajoute aucun champ.
- Les termes sont signés dans la décision, pas dans la demande. Une demande
  reprise (§5.1) les accepte donc tels qu'ils sont saisis.

### 5.3 État « Révoquée » (F14-i)

**Côté gateway.** `CertificateDomainView`
(`crates/helios-api/src/certificates/views.rs`, construite dans
`crates/heliosd/src/certificates/views.rs`) gagne deux champs, en
`#[serde(default)]` comme les échéances ajoutées au 6b :

- `gateway_revoked: bool`, lu dans `state.gateway.revoked` ;
- `gateway_awaited_replacement: Option<String>`, l'empreinte en hex minuscule
  lue dans `state.gateway.awaited_replacement`. Ce champ est public : il nomme
  un document signé que la gateway acceptera, ce n'est pas un secret.

Les champs sont ajoutés aux types de la console web et d'Orion. La console web
peut les afficher sans nouvel écran : elle a déjà une ligne d'identité. Au
builder de juger si une ligne suffit. Sinon la console reste telle quelle, et
le lot le note.

**Côté Orion** (`gatewayRow`, `apps/orion/src/views/astra/gatewayRows.ts`).
Quand `gateway_revoked` est vrai, ces états passent avant tous les autres, sauf
un registre de révocation qui attend une reprise :

| Situation | État | Détail | Actions |
| --- | --- | --- | --- |
| révoquée, remplaçant attendu, registre avec ce remplaçant | « Révoquée, remplaçant à installer » | — | « Reprendre » |
| révoquée, remplaçant attendu, aucun registre ou un autre remplaçant | « Révoquée, remplaçant attendu » | « Le remplaçant nommé par la révocation n'est pas sur ce poste. » | jet forcé si un registre attend (§5.4) |
| révoquée, aucun remplaçant attendu | « Révoquée » | « La gateway ne sert plus. Le domaine doit être reconstruit. » | jet forcé si un registre attend (§5.4) |

Sur une gateway révoquée, « Renouveler », « Annuler », « Revenir à l'ancienne
identité » et « Révoquer la gateway » ne sont jamais proposés.
`GatewayRefusal::AlreadyRevoked`, déclaré au 6b sans être produit, l'est
désormais par l'ouverture d'une révocation quand la vue dit `gateway_revoked`
(défense en profondeur derrière l'IHM). `Revoked` couvre les autres gestes de
la même façon.

Une fois le remplaçant installé, la gateway n'est plus révoquée
(`replace_revoked_identity`) et le bloc revient à ses états ordinaires.

### 5.4 Les deux impasses et le jet forcé (F14-j, point 1)

**Impasse A : remplaçant refusé définitivement.** La révocation est appliquée,
mais l'installation du remplaçant est refusée pour de bon. Ce cas est constaté
quand, en même temps, le registre dit `revocation_applied` et pas
`replacement_installed`, et la vue dit `gateway_revoked` avec un
`gateway_awaited_replacement` absent ou différent de l'empreinte du remplaçant
enregistré. La lecture de la vue suffit à le constater. Un refus définitif lors
de la reprise y mène aussi, mais seulement après cette relecture.

**Impasse B : publication refusée définitivement.** Une décision de
renouvellement est installée, mais Astra refuse sa publication pour de bon
(`NoGatewayTransition` ou `GatewayTransitionAborted`, voir
`crates/astra/src/door/write.rs`). Le registre enregistre ce refus définitif
dans un nouveau champ `publication_refused: Option<String>` (la raison, en
`#[serde(default)]`). Il n'est rempli que par un `GatewayRefusal::GatewayRefused`
renvoyé par la publication. Un refus transitoire ou une gateway injoignable
n'y touchent pas.

Pour l'impasse B, l'issue dépend de l'horloge de la gateway :

- **avant `activation_at`** : « Annuler » reste l'issue, comme au 6b
  (l'annulation remplace le registre). Orion le met en premier, avec la phrase
  « La publication est refusée : annuler la transition avant le … ». Il n'y a
  pas de jet forcé, puisqu'une issue existe ;
- **après `activation_at`** : aucune issue sur la gateway (`heliosd` refuse de
  démarrer sur une transition activée et non publiée,
  `key_negotiation/identity.rs`). Le jet forcé est proposé pour débloquer les
  autres gestes, en premier lieu « Révoquer la gateway ».

**Le jet forcé.** C'est une fonction distincte du jet ordinaire dans chacun des
deux modules : `force_discard_pending_revocation` et `force_discard_pending`.
Elle vérifie elle-même que l'impasse est constatée et refuse sinon, avec une
erreur typée qui dit ce qui reste possible. Le jet ordinaire du 6b est
inchangé. La vérification relit la vue de la gateway par le tunnel : un poste
hors tunnel ne force rien.

- Libellé : « Abandonner la décision ».
- Confirmation, impasse A : « La révocation est appliquée ; le remplaçant ne
  sera jamais installé. La gateway ne servira plus et le domaine devra être
  reconstruit. » Une case à cocher, comme pour la révocation sans remplaçant.
- Confirmation, impasse B : « La transition reste installée sur la gateway,
  sans publication. heliosd ne redémarrera plus sur cette identité. Seule une
  révocation de la gateway reste possible. » Même case.
- Après le jet, le bloc relit la vue et affiche l'état du §5.3, ou l'état
  ordinaire.

### 5.5 Sonde avant abandon d'une révocation (F14-j, point 2)

Dans `carry_revocation` (`gateway_revocation.rs`, autour de la ligne 297), un
`GatewayRefused` sur le dépôt de la révocation retire aujourd'hui la révocation
du registre. Or un dépôt dont la réponse a été perdue a pu être accepté avant
le refus : la campagne a été consommée entre la lecture et le nouveau dépôt
(403 ou 409 tardif). Avant de la retirer, la reprise relit donc la vue de la
gateway :

- `gateway_revoked` vrai et `gateway_awaited_replacement` égal au remplaçant
  enregistré : la révocation est appliquée. Le registre passe à
  `revocation_applied` et la reprise continue avec l'installation du remplaçant ;
- `gateway_revoked` vrai sans remplaçant enregistré : la révocation est
  appliquée et le registre est effacé ;
- `gateway_revoked` faux : comportement du 6b, la révocation est retirée et
  l'état redevient « Révocation à signer » ;
- vue illisible (injoignable) : le registre est gardé tel quel, avec l'erreur
  `Unreachable`. Rien n'est retiré.

`probe_expired_revocation` peut s'appuyer sur la même lecture. Sa sonde par
installation reste valable, et le builder choisit s'il l'unifie. Une seule
fonction de sonde doit servir les deux cas, sans dupliquer la logique.

### 5.6 Erreurs

- Mêmes règles que le 6b (§5.7) : `Guidance` pour les phrases écrites pour
  l'opérateur, `Internal` jamais affiché tel quel.
- Un jet forcé refusé dit pourquoi et ce qui reste possible (« Reprendre »,
  « Annuler »), et finit par « Rien n'a été jeté. ».

## 6. Contraintes

- Le tunnel est le seul chemin. La vue du domaine est la seule source de l'état
  révoqué.
- `heliosd` tient seul son registre. Le lot n'ajoute aucune écriture côté
  gateway, seulement deux champs en lecture.
- Ajouter des champs à `CertificateDomainView` reste compatible : `serde(default)`,
  et l'API publique ne retire rien.
- Le registre local d'Orion change de forme (`publication_refused`) :
  `serde(default)`, pour qu'un registre écrit au 6b se relise.
  `deny_unknown_fields` reste.
- Versions : `scripts/version.py merge` à la fusion, jamais à la main.
- `docs/audits` reste intouché.

## 7. Tests

- `heliosd` : la vue porte `gateway_revoked` et `gateway_awaited_replacement`
  pour une gateway révoquée avec ou sans remplaçant, et les champs sont absents
  ou faux sinon.
- `astra-operator` :
  - `reused` atteint l'opération ouverte ;
  - les termes hors bornes sont refusés avant toute clé ;
  - la sonde du §5.5, dans ses quatre cas ;
  - `publication_refused` n'est rempli que sur un refus définitif ;
  - chaque jet forcé est refusé hors de son impasse et accepté dans son impasse ;
  - un registre au format du 6b se relit.
- Orion :
  - `gatewayRow` est testé en table de cas pour les trois états révoqués et
    pour l'impasse B avant et après activation ;
  - `GatewayIdentityBlock` : les champs des termes, leur validation et la
    confirmation du jet forcé ;
  - la phrase de la demande reprise.
- Le chemin de la cérémonie : aucun secret dans ce qui atteint la WebView (test
  existant étendu si le statut gagne un champ).

## 8. Documentation et recette

- `RENOUVELLEMENT-CERTIFICATS.md` §7.1 (le paragraphe « Deux cas sans issue »
  devient le jet forcé), §8 (durées réglables, demande reprise) et la table des
  états de la ligne (« Révoquée »).
- `docs/specification/ROTATION-CERTIFICATS.md` : les deux champs de la vue, s'il
  décrit la vue.
- `MANUAL-TESTING.md` : section « J. Lot 6c », avec des étapes **[cible]**.
- `ROADMAP.md` : F14-h, F14-i et F14-j sont levés. Le lot 6c est ajouté à la
  ligne F14.

## 9. Laissé au builder

- Les bornes exactes des termes (§5.2), lues dans le code existant.
- L'affichage dans la console web des deux champs de la vue (§5.3).
- L'unification des sondes (§5.5).
- Par où la vue de la gateway passe pour `GatewayIdentityRemote`, que ce soit
  une méthode existante ou une nouvelle.
