# ADR 005 — Négociation de clé pré-WireGuard

**Statut** : accepté (2026-07-25)

Remplace et détaille l'amendement du 24 juillet 2026 de
[ADR-001](ADR-001-WIREGUARD.md), qui reste la référence pour le transport
WireGuard lui-même.

## Contexte

WireGuard protège une session par Curve25519. Un adversaire qui enregistre
aujourd'hui le trafic et disposera plus tard d'un calculateur quantique casse
cet échange et déchiffre l'enregistrement : c'est le « récolter maintenant,
déchiffrer plus tard ». Le slot `PresharedKey` de WireGuard neutralise cette
menace — il entre dans la dérivation et n'est pas cassé par Shor — mais il faut
que les deux pairs portent la même valeur **avant** le handshake.

Le provisioning post-quantique existant (ADR-001 §2) pose ce PSK par l'API
interne, qui vit derrière `admin_iface`. Il exige donc un tunnel déjà monté. La
conséquence est structurelle et n'a pas de correctif dans ce cadre : **le
premier handshake d'un client n'est jamais protégé**, et c'est précisément
celui qu'un adversaire patient enregistre. Le second l'est ; le premier a déjà
révélé la session qui a servi à poser le PSK.

Le choix initial de n'exposer aucun plan de contrôle avant WireGuard empêchait
exactement la chose qu'il fallait faire.

## Décision

Un second port UDP public, distinct du transport WireGuard, porte une
négociation authentifiée dont le seul produit est le PSK du premier handshake.

| | port | rôle |
|---|---|---|
| `key_negotiation_port` | 51821 par défaut | négociation, aucun trafic utilisateur |
| `wg_listen_port` | 51820 par défaut | transport WireGuard, inchangé |

Les deux se redirigent séparément sur la box. Sans le second port, un profil
qui réclame une négociation échoue — il n'existe **aucun repli** vers un
premier handshake nu.

### 1. Trois modes, choisis par le client, jamais substitués

| Mode | Slot préparé par la gateway |
|---|---|
| `classic` | vidé |
| `static_psk` | PSK déjà configuré, retrouvé par comparaison d'empreinte |
| `ml_kem` | PSK frais dérivé d'une encapsulation ML-KEM-768 |

Orion choisit ; Helios exécute exactement le mode demandé ou refuse. Une
réponse qui sélectionnerait un autre mode est rejetée par le client, le mode
étant couvert par les signatures et par la dérivation.

En `static_psk`, seule l'**empreinte** du PSK circule : la valeur ne quitte
jamais les deux configurations.

### 2. L'ancre d'authentification est ML-DSA-65, pas TLS

QUIC impose TLS 1.3 ; le port l'utilise en mutuel. Mais **TLS n'est pas
l'ancre de sécurité** : ses certificats sont classiques (ECDSA P-256), donc
cassables par le même adversaire quantique dont on se protège. Un attaquant
capable de forger un certificat pourrait substituer `kpub` et connaître le
PSK — la protection ML-KEM serait vidée de son sens.

Une PKI applicative ML-DSA-65 (FIPS 204) est donc superposée :

- **CA opérateur** — deux autorités créées ensemble sur le poste opérateur,
  une TLS et une ML-DSA-65. Leurs moitiés privées ne vont jamais sur une
  gateway.
- **Certificat gateway** — naît **sur** la gateway, auto-signé, ses clés
  privées TLS et ML-DSA scellées au TPM. Il lie le nom du serveur à la clé
  publique WireGuard de la gateway.
- **Certificat client** — émis par la CA opérateur, lie la clé de signature du
  client à sa clé publique WireGuard. Son empreinte est déclarée à l'admission.

Sont signés en ML-DSA-65 : la requête (mode, identité WireGuard, nonce,
`kpub`), la réponse (mode, ciphertext, contexte complet), la confirmation et
l'acquittement de commit. Casser ECDSA ne permet donc ni de substituer `kpub`,
ni d'altérer le ciphertext, ni de forger un commit. TLS reste une première
barrière qui réduit l'exposition du parseur applicatif.

Le protocole v1, non signé, est refusé : la rupture est volontaire.

### 3. Dérivation liée à toute la transaction

En mode ML-KEM, Orion génère une paire éphémère, envoie `kpub`, conserve
`kpriv` ; Helios encapsule et renvoie le ciphertext. Les deux obtiennent le
même secret, puis dérivent :

```
PSK = HKDF-SHA-256(
        secret ML-KEM,
        version ‖ mode ‖ identifiant de transaction
              ‖ nonce client ‖ nonce gateway
              ‖ clé WireGuard client ‖ clé WireGuard gateway )
```

Lier ces éléments rend inutilisable un ciphertext rejoué, destiné à un autre
pair, ou associé à un autre mode. Le PSK fait 32 octets et n'est **jamais**
écrit sur disque, d'aucun côté.

### 4. Ordre de pose : poser, puis annoncer

```
1. mTLS établit le transport QUIC
2. Orion signe mode, identité WireGuard et kpub
3. Helios vérifie certificat PQ, signature, empreinte admise et plancher
4. Helios pose le slot sur son plan de données
5. Helios signe et renvoie ciphertext et contexte
6. Orion vérifie, pose le même slot, attend un handshake WireGuard frais
7. Orion confirme par signature ; Helios commit et signe l'acquittement
```

L'étape 4 précède l'étape 5 : un PSK annoncé mais non posé ferait échouer tous
les handshakes, sans canal de rattrapage puisque le tunnel est justement ce qui
manque. Si le plan de données refuse la pose, aucune réponse de succès ne part.

Si la session QUIC se ferme, si le handshake n'arrive pas dans le délai, ou si
la confirmation est invalide, Helios **restaure le slot précédent**. Les
transactions sont sérialisées par pair.

### 5. Plancher anti-downgrade, qui ne monte que

L'ordre des modes est monotone : `classic < static_psk < ml_kem`. Chaque pair
Helios et chaque profil Orion portent un `minimum_key_negotiation_mode`.

- Une demande sous le plancher est refusée **avant** toute modification du plan
  de données.
- L'admission avec un certificat PQ choisit `ml_kem` comme plancher par défaut.
- Chaque commit réussi **élève** le plancher au mode utilisé, et le persiste.
- Le hot-reload refuse de recopier un plancher inférieur depuis la vue
  expurgée de l'API.

Un pair peut donc passer de classique à statique puis à ML-KEM, jamais dans
l'autre sens — y compris après redémarrage. Aucun message réseau, aucune
renégociation ne peut abaisser ce plancher : seule une édition locale explicite
de `network.toml` le peut.

Le même cliquet existe côté client : `ClientConfig::upsert` refuse d'abaisser
un plancher connu, **y compris en supprimant le bloc de négociation** — une
suppression est un downgrade, puisqu'elle renverrait vers le chemin hérité dont
le premier handshake est nu.

### 6. Identité cliente : scellée au poste, jamais dans le profil

L'identité cliente — deux certificats et leurs deux clés privées — naît sur le
poste opérateur et ne voyage **qu'une fois**. Sur Windows, elle est scellée par
DPAPI, liée au compte de l'utilisateur et à une entropie propre à cet usage.

Le Credential Manager a été écarté : il plafonne un secret à 2560 octets quand
la seule clé privée ML-DSA-65 en fait 4032. La découper entre plusieurs entrées
aurait reconstruit un conteneur, en moins bon.

Le profil VPN ne porte que le **nom** de l'entrée. Le document d'échange, lui,
transporte l'identité une seule fois dans un champ `key_negotiation_identity`
que l'import scelle immédiatement et qui n'atteint jamais `ClientProfile`, donc
jamais `profiles.toml`.

### 7. L'enrôlement ne suppose aucune connexion préalable

L'API de contrôle vit derrière le tunnel. L'exiger pour l'enrôlement rendrait
la protection du premier handshake dépendante d'un premier handshake — une
circularité qui viderait la feature de son intérêt.

Le protocole n'a jamais eu cette dépendance : Orion compose le port public
avant de monter quoi que ce soit. L'outillage suit :
`helios-ctl enroll` accepte les matériaux en fichiers (`--gateway-certificate`,
`--gateway-pq-certificate`, `--address`), que l'opérateur récupère par la
session SSH qu'il détient déjà, et l'admission emprunte `heliosd peer add` en
console — la commande prévue pour l'amorçage. Le certificat PQ portant le sujet
**et** la clé WireGuard épinglée, rien n'est retapé.

## Modèle de menace

### Ce que la feature arrête

| Attaque | Ce qui l'arrête |
|---|---|
| Récolte passive, déchiffrement quantique différé | PSK ML-KEM-768 dans le slot dès le premier handshake |
| Substitution de `kpub` ou du ciphertext | Signature ML-DSA-65 couvrant requête et réponse |
| Rupture future d'ECDSA / de l'échange TLS | L'ancre est ML-DSA-65 ; TLS n'est qu'un transport |
| Rejeu d'une transaction | Identifiant de transaction, cache anti-rejeu borné, nonces liés au PSK |
| Confusion de pair | Les deux identités WireGuard entrent dans la dérivation |
| Downgrade forcé par le réseau | Plancher persistant des deux côtés, refus avant toute pose |
| Client non admis | Empreinte du certificat PQ vérifiée contre la table des pairs |
| Pose partielle du PSK | Pose avant annonce ; restauration si la confirmation n'arrive pas |
| Vol du blob d'identité sur un autre compte Windows | DPAPI lié au compte et à l'entropie applicative |

### Ce qu'elle n'arrête pas

- **Le déni de service.** Un attaquant qui joint le port peut ouvrir des
  transactions. Les limites (connexions globales, verrou par pair, messages
  bornés à 64 Kio, cache anti-rejeu borné) contiennent la consommation, elles
  n'empêchent pas la saturation du lien.
- **La compromission d'un poste client.** Une identité scellée reste
  utilisable par un code s'exécutant sous le compte de l'utilisateur. DPAPI
  protège contre le vol du fichier, pas contre l'exécution locale.
- **La compromission de la CA opérateur.** Ses clés privées émettent des
  identités clientes valides. Elles vivent hors gateway, en `0600`, et leur
  compromission impose de réémettre.
- **La révocation.** Il n'existe pas de CRL ni d'OCSP. Retirer un accès se fait
  par révocation d'admission (`peer remove`), qui coupe au handshake suivant.
- **L'analyse de trafic.** Le port de négociation est visible et identifiable ;
  il révèle qu'un client Helios se connecte, sans rien dire de la session.
- **Le DNS du client**, toujours hors tunnel (voir `helios-firewall::ruleset`).

### Surface exposée

Le port applique, dans cet ordre : mTLS avant tout protocole, un ALPN dédié,
des messages JSON stricts (`deny_unknown_fields`) bornés à 64 Kio, une limite
globale de connexions, un verrou par pair, un cache anti-rejeu borné. Les
erreurs publiques restent volontairement peu détaillées — elles ne distinguent
pas un pair inconnu d'une signature invalide.

## Conséquences

### Pour l'opérateur

Deux redirections UDP au lieu d'une. Une CA à créer une fois et à conserver
hors gateway. Un enrôlement par client, qui produit un fichier **secret** à
transférer par canal maîtrisé et à détruire des deux côtés après import.

### Pour l'utilisateur

L'écran *Profils* d'Orion expose le mode, le plancher, l'empreinte du
certificat épinglé et l'état de l'identité. Les modes sous le plancher sont
montrés **désactivés** plutôt que masqués : voir ce qu'on a laissé derrière est
le sens même d'un cliquet.

### Pour le code

Une dépendance de test de `heliosd` vers `orion-core`. Elle est assumée : la
gateway ne dépend pas du client, mais leur interopérabilité doit être prouvée
quelque part, et le seul endroit honnête est un test qui fait dialoguer le vrai
handler et le vrai client à travers un vrai socket. Ce test compare les deux
PSK dérivés — une divergence d'un seul champ dans la dérivation laisserait les
deux côtés « réussir » puis échouer à chaque handshake, sans rien qui désigne
la cause.

## Limites connues

- **DPAPI ne se compile ni ne s'exerce en WSL2.** Hors Windows, le scellement
  échoue explicitement (`IdentityStoreError::UnsupportedPlatform`) plutôt que
  d'écrire ces clés en clair. Débloquer Linux suppose `libsecret`, macOS le
  Keychain — chacun avec sa sémantique de déverrouillage, ce qui interdit de
  les simuler.
- **Les effets matériels ne sont pas prouvés en WSL2.** La transaction est
  couverte par les tests ; la pose réelle du slot sur WireGuard-NT et sur le
  backend noyau exige deux machines et les deux redirections
  ([TESTING](../testing/TESTING.md)).
- **Aucune rotation automatique des certificats.** Ils valent 825 jours ; leur
  expiration se traite en réémettant. Rien n'avertit à l'approche de l'échéance.
- **Le profil hérité reste servi.** Un profil sans bloc `key_negotiation`
  emprunte l'ancien provisioning, dont le premier handshake n'est pas protégé.
  Supprimer ce chemin exige que tous les profils déployés aient été réenrôlés.

## Alternatives écartées

**Réutiliser le port WireGuard.** Il aurait fallu démultiplexer un protocole
applicatif sur le même socket UDP que WireGuard, donc modifier le plan de
données ou s'interposer devant lui. Coût élevé, surface d'attaque déplacée sur
un composant critique, pour économiser une redirection.

**S'en remettre à TLS seul.** C'était l'implémentation initiale. Elle protège
contre la récolte passive mais pas contre un adversaire quantique **actif**,
qui forge un certificat et substitue `kpub`. Le PSK serait alors connu de
l'attaquant tout en étant issu de ML-KEM — la pire des situations, celle qui
donne l'apparence de la protection.

**Négocier à chaque handshake WireGuard.** WireGuard rekeye seul toutes les
deux minutes ; s'y accrocher aurait imposé une négociation applicative au même
rythme, pour un gain nul — le PSK couvre déjà toutes les sessions dérivées.

**Une PKI post-quantique complète en remplacement de X.509.** Aucune pile QUIC
ne l'accepte aujourd'hui. La superposition retenue donne la même propriété
d'authentification PQ sans réécrire une pile TLS.
