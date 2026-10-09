# Conception — renouvellement automatique du PSK ML-KEM dans le tunnel

Statut : **conception validée en séance le 2026-10-09**, à relire avant plan
d'implémentation. Ce document décrit le lot F1 de la
[feuille de route](../../ROADMAP.md). Il ne remplace pas la spécification
normative : les amendements listés au §8 sont écrits dans
[NEGOCIATION-DE-CLE-V5](../../specification/NEGOCIATION-DE-CLE-V5.md) avec le
code.

## 1. Objectif

Aujourd'hui, aucun renouvellement de PSK n'existe. Orion journalise la durée de
vie reçue (`orion-core/src/backend/mod.rs`), la gateway retire le slot à 24 h
(`heliosd/src/key_negotiation/transaction.rs`, `MAX_PSK_LIFETIME`), le tunnel
tombe au rekey WireGuard suivant et Orion ne renégocie par le port public
qu'après 150 s sans handshake. Résultat : une coupure de plusieurs minutes par
jour et par tunnel, non planifiée.

Le lot remplace ce comportement par un renouvellement automatique, déclenché
par Orion avant l'échéance, négocié **à l'intérieur du tunnel**, au prix d'une
seule micro-coupure de handshake.

Critère de réussite : les quatre seuils du §12.3 de la spécification v5
(handshake < 5 s, interruption < 1 s, aucune session TCP rompue, 20
renouvellements consécutifs réussis), mesurés sur cible avec le code de
production, sur le noyau Linux et sur WireGuard-NT.

## 2. Décisions

| Sujet | Décision |
| --- | --- |
| Déclencheur | 80 % de la durée de vie **ou** 80 % du plafond d'octets, le premier atteint |
| Durée de vie | 24 h, inchangée et toujours signée (`psk_lifetime_secs`) ; seuil à 19 h 12 (le §12.3 disait 90 %) |
| Plafond d'octets | 100 Gio (`rx_bytes + tx_bytes` du pair), constante `aether`, **non signée** ; seuil à 80 Gio |
| Limite ferme | la gateway retire le slot à 100 % de l'un ou l'autre, dans la boucle qui applique déjà les 24 h |
| Canal | la transaction v5 inchangée, sur QUIC, adressée à l'adresse de la gateway dans le tunnel |
| Bascule | négociation et bascule dans la **même** transaction ; aucun PSK négocié à l'avance |
| Initiateur | Orion seul ; la gateway ne fait qu'appliquer la limite ferme |
| Repli | nouvelles tentatives dans le tunnel jusqu'à 100 % ; aucun repli vers le port public pendant le renouvellement |
| Essai bloquant §20.0 | levé par décision du 2026-10-09 ; V1 se mesure sur le code de production grâce au renouvellement forcé |

### Pourquoi le volume et pas un compteur anti-rejeu

Le compteur anti-rejeu de WireGuard appartient aux clés de session, comme le
numéro de séquence ESP appartient à la SA enfant en IPsec : il repart à zéro à
chaque rekey (120 s), WireGuard gère seul sa limite, et ni le noyau ni
WireGuard-NT ne l'exposent. Le PSK joue le rôle du secret de niveau IKE SA,
dont IPsec borne la vie en temps et en volume (*lifetime* et *lifebytes*, seuil
*soft* puis *hard*). Le volume est le seul compteur d'usure que les deux bouts
savent lire.

### Pourquoi une constante et pas un champ signé

Signer le plafond modifierait les octets authentifiés de la réponse v5 : tout
Orion déployé refuserait la réponse d'une gateway à jour. Une constante
partagée par `aether` ne change rien au fil. Changer un jour cette valeur
exigera de la signer, comme la durée de vie.

### Pourquoi pas de PSK négocié à l'avance

Deux invariants l'interdisent : un PSK négocié est posé sur le plan de données
**avant** d'être annoncé, et le commit exige la preuve d'un handshake avec ce
PSK. WireGuard n'offre qu'un slot par pair : un PSK négocié mais non posé
serait seulement un secret gardé en mémoire sans usage. La négociation coûte
quelques millisecondes ; rien n'est gagné à l'anticiper.

## 3. Déroulé

```text
Orion                                   tunnel                         Helios
  │ déclencheur (temps ou octets)                                         │
  │── QUIC vers <hôte heliosd_url>:<port de négociation> ────────────────>│
  │   challenge, requête ML-KEM signée (transaction v5 inchangée)         │
  │                                                     réserve génération│
  │                                                     + Preparing       │
  │                                                     pose le candidat  │
  │<──────────────────────────────── réponse signée ──────────────────────│
  │ dérive le PSK                                                         │
  │ rekey_peer : retrait puis réinscription du pair     (micro-coupure)   │
  │════════════ handshake WireGuard avec le nouveau PSK ═════════════════│
  │ observe un handshake postérieur à la pose           observe de même   │
  │── confirmation ──────────────────────────────────────────────────────>│
  │                                                     commit, âge et    │
  │<──────────────────────────────────────────── ack ─────────────────────│ point de départ remis à zéro
  │ ferme QUIC, efface l'ancien PSK                                       │
```

Les clés de session en cours restent valides entre la pose côté gateway et le
`rekey_peer` d'Orion : le trafic continue jusqu'à la réinitialisation. La
connexion QUIC traverse la micro-coupure grâce à son délai d'inactivité de
50 s. QUIC porte toujours une seule transaction et se ferme après le commit.

## 4. Composants

### 4.1 `aether`

- `NEGOTIATED_PSK_BYTE_LIMIT: u64 = 100 * 1024³`, à côté de
  `NEGOTIATED_PSK_LIFETIME_SECS` dans `aether::key_negotiation`.
- Seuil de renouvellement exprimé une fois (80 %), utilisé par Orion pour le
  temps et le volume.

### 4.2 `helios-firewall`

`ruleset/transport.rs::key_negotiation_listener` ouvre aussi le port de
négociation en entrée sur l'interface du tunnel (et la sortie correspondante),
en plus de chaque WAN. Aucune autre interface. Le ruleset reste construit en
entier puis appliqué de façon atomique.

### 4.3 `heliosd`

**Classification de la connexion.** Si l'adresse source est une VIP d'un pair
admis (IPv4 `/32` ou IPv6 `/128`), la connexion est une connexion de tunnel. Elle n'est alors acceptée que
si :

1. ce pair est exactement celui que mTLS a résolu depuis l'état de confiance
   de la gateway (la clé WireGuard de la requête ne sert jamais de clé de
   recherche) ;
2. son slot est `Committed` en `ml_kem` ;
3. le mode demandé est `ml_kem`.

Tout autre cas est refusé par l'erreur publique générique, sans rien révéler
de l'admission. Le chemin dans le tunnel ne peut donc ni amorcer un premier
PSK ni abaisser le mode ; le plancher anti-downgrade reste vérifié comme
aujourd'hui. Une source usurpée depuis le WAN n'aboutit pas : la réponse part
dans le tunnel vers le vrai pair.

**Transaction.** Inchangée. Le remplacement d'un slot committé existe déjà :
`SlotState::Preparing` porte `previous` et `previous_psk`, le rollback les
remet en place, la génération réservée sous le même verrou sérialise le
renouvellement face au `release`, à la récupération par vieillissement et aux
retraits.

**Usure.** `InstalledPsk` enregistre au commit `rx_bytes + tx_bytes` du pair
(point de départ). La boucle qui applique `MAX_PSK_LIFETIME` retire aussi le
slot quand `courant − départ ≥ NEGOTIATED_PSK_BYTE_LIMIT`. Si le compteur
courant est inférieur au point de départ (pair recréé), le point de départ
prend la valeur courante. Ces limites ne visent que `Committed`, jamais un
candidat. Le journal nomme la cause : durée ou volume.

**Budget.** Le budget par identité s'applique comme sur le port public. À
1 Gbit/s soutenu, 80 Gio représentent environ un renouvellement toutes les
11 minutes.

### 4.4 `orion-core`

**Backend.** `VpnBackend::rekey_peer(&ClientProfile)` retire puis réinscrit le
pair avec le nouveau PSK, l'endpoint et le keep-alive. Implémentations :
simulation (`backend/dryrun.rs`) et WireGuard (`backend/wireguard.rs`, via
`remove_peer` puis `configure_peer` de defguard, Linux et WireGuard-NT). Les
garde-fous de routes Linux existants s'appliquent à la réinscription.

**Adresse dans le tunnel.** L'hôte vient de `heliosd_url`, validé par
`tunnel_routed_address` (adresse littérale, comprise dans les `AllowedIPs`,
aucune résolution DNS) ; le port vient de l'endpoint de négociation du profil ;
le `server_name` et tous les épinglages restent ceux du profil. La socket est liée à la VIP du client
(`net_pin::tunnel_socket`) : la socket de la première négociation est, elle,
épinglée **hors** du tunnel et ne peut pas servir ici. Sans
`heliosd_url` valide, aucun renouvellement n'est tenté et l'événement le dit ;
l'échéance mène alors au chemin de reconnexion existant.

**Déclencheur.** Au commit, Orion enregistre l'instant monotone, l'heure
murale et `rx_bytes + tx_bytes`. L'échéance de 80 % retient la plus proche des
deux horloges (§12.3 : une veille ou un recul d'horloge ne prolonge jamais un
slot). Le volume suit la même règle de point de départ que la gateway. La
surveillance tourne à côté de celle du vieillissement du handshake
(`backend/mod.rs`).

**Échecs.** Après un rollback ou un délai dépassé, nouvelle tentative dans le
tunnel après 1, 2, 4… minutes, plafonnée à 15 minutes, jusqu'à 100 %. Au-delà,
la gateway retire le slot et le chemin existant (vieillissement du handshake
puis négociation publique) reprend.

**Rollback local.** Si `rekey_peer` échoue à la réinscription, Orion réinscrit
le pair avec l'**ancien** PSK. Cette restauration est portée par une garde qui
survit à l'annulation de la tâche : un retour asynchrone ordinaire ne suffit
pas. Si la restauration échoue elle aussi, l'erreur est affichée et le chemin
de reconnexion existant s'applique. Après commit, l'ancien PSK est effacé ; le
nouveau n'est jamais persisté.

### 4.5 `apps/orion`

- Commande Tauri de renouvellement forcé, refusée hors tunnel monté en
  `ml_kem`.
- Action « Renouveler la clé maintenant » dans `ConnectView.tsx`, construite
  avec les composants, l'espacement et la formulation existants.
- Événements : « renouvellement déclenché (durée / volume / manuel) », « clé
  renouvelée », « échec, nouvel essai dans N min ».

Aucune variable ni option ne raccourcit la durée de vie ou le plafond dans un
binaire livré.

## 5. Ce qui ne change pas

- Messages, transcriptions signées et ALPN de la v5.
- Ordre de pose : gateway avant réponse, Orion après dérivation.
- Preuve par handshake avant commit des deux côtés.
- Vivacité lue sur le plan de données ; QUIC n'est pas un canal de vivacité.
- `release` sur l'API interne, récupération à 300 s, renégociation sur
  événement (reconnexion, changement de réseau, rotation d'identité).

## 6. Tests

| Niveau | Comportement vérifié |
| --- | --- |
| `heliosd` | renouvellement accepté seulement sur `Committed` `ml_kem` ; VIP différente du pair mTLS → refus générique ; slot vide, statique ou autre mode → refus générique ; retrait à 100 Gio ; point de départ réinitialisé si le compteur redescend ; rollback vers l'ancien PSK ; limites jamais appliquées à `Preparing` |
| `helios-firewall` | golden : port de négociation ouvert sur chaque WAN et sur l'interface du tunnel, nulle part ailleurs |
| `orion-core` | seuil temps, seuil volume, échéance la plus proche des deux horloges ; délais croissants plafonnés ; `rekey_peer` en simulation ; restauration de l'ancien PSK en cas d'échec et en cas d'annulation ; refus sans `heliosd_url` valide |
| `apps/orion` | action visible seulement tunnel monté en `ml_kem` ; événements affichés |
| cible | V1 : 20 renouvellements forcés avec ping 10 ms et une connexion iperf3 unique, noyau Linux et WireGuard-NT, chemin sain puis dégradé (`netem`), verdict PASS/FAIL par critère |

Le démon isolé de la campagne dry-run n'a pas de tunnel : aucune source n'y
est une VIP, donc le chemin « tunnel » se prouve par les tests `heliosd` au
niveau du gestionnaire et par V1 sur cible, pas par la campagne.

`scripts/regression.sh` est la vérification complète. Aucune ligne cible ne se
coche depuis WSL2.

Si V1 échoue sur cible, le repli du §12.3 s'applique : déconnexion puis
reconnexion complètes planifiées par Orion au même seuil de 80 %, sans
supprimer la preuve par handshake.

## 7. Dépendance d'ordonnancement

La migration `SecretString` d'`orion-core` (H4) est en cours et touche
`backend/mod.rs`, `config.rs` et `key_negotiation.rs`. L'implémentation
commence après sa fusion.

## 8. Documentation à mettre à jour avec le code

- `NEGOCIATION-DE-CLE-V5.md` : §12.3 (80 %, volume, canal dans le tunnel),
  nouvelle section du canal de renouvellement à côté du §7.5, §20.0 (essai
  bloquant levé par décision, mesure sur le code de production), en-tête
  « Ce qui n'est pas implémenté » et §21.
- `ADR-005` : une mention du canal de renouvellement dans le tunnel.
- `README.md` « État et limites », `ROADMAP.md` (F1, V1), recette V1 dans
  `testing/TESTING.md`.
