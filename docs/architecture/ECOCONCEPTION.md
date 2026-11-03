# Étude — consommation électrique et écoconception

Statut : **diagnostic et propositions**, aucune modification de configuration
sur la passerelle. Investigation du 1er octobre 2026 : lecture du dépôt
(`79d89df`) et diagnostic SSH de la cible définie dans `scripts/lib-remote.sh`.
Les constats logiciels portent sur le code local ; sa correspondance exacte
avec le binaire déployé n'a pas été vérifiée.

## 1. Conclusion et ordre d'action

Le portable MSI utilisé comme passerelle offre plusieurs pistes matérielles.
Helios consomme peu de CPU dans le court échantillon observé, mais entretient
des tâches périodiques susceptibles de réveiller le processeur au repos.
Il faut mesurer ces deux dimensions séparément.

| Priorité | Action proposée | État des preuves / critère de réussite |
| --- | --- | --- |
| 1 | Mesurer la machine à la prise | Consommation totale inconnue ; établir une référence avant changement |
| 1 | Éteindre le rétroéclairage SteelSeries | Clavier identifié ; extinction et persistance après redémarrage à vérifier |
| 1 | Résoudre l'absence de veille du GPU NVIDIA | GPU actif, environ 4 W annoncés ponctuellement ; vérifier RTD3 et gain à la prise |
| 2 | Comparer le profil CPU `power-saver` à `balanced` | Profil disponible ; conserver débit, latence et délais de négociation |
| 2 | Évaluer un fonctionnement sans session graphique | GDM/GNOME actifs, écran déjà éteint ; garder un accès console de secours |
| 2 | Réduire les réveils de télémétrie sans lecteur | Lecture du WAN chaque seconde dans le code local ; mesurer sans console ouverte |
| 3 | Remplacer les scrutations de fichiers par des notifications | Trois boucles à 2 s ; préserver admission, adoption des secrets et échéances Astra |
| 3 | Réduire les sondes Orion et rafraîchissements invisibles | Bénéfice sur les clients et sur la passerelle, croissant avec leur nombre |
| 3 | Examiner services et périphériques inutilisés | Arrêt uniquement après vérification de leur rôle et mesure comparative |

Les économies proposées ne sont pas encore mesurées. La mesure ponctuelle GPU
ne constitue ni la consommation du PC, ni un gain garanti de 4 W à la prise.

## 2. État de la passerelle observé

Diagnostic réalisé vers 12 h 57–13 h 04, heure de Paris, par SSH en lecture
seule. Pas d'installation, arrêt de service, écriture sysfs ou redémarrage.

| Élément | Observation |
| --- | --- |
| Machine | MSI GP75 Leopard 10SFSK, Ubuntu 26.04.1, noyau `7.0.0-34-generic` |
| CPU | Intel Core i7-10875H, 8 cœurs / 16 processeurs logiques |
| Graphisme | Intel UHD intégré + NVIDIA TU104M / RTX 2070 Super |
| Écran | `actual_brightness=0`, `bl_power=4` ; rétroéclairage éteint au relevé |
| Clavier RGB | USB SteelSeries KLC `1038:1122`, `power/control=on`, `runtime_status=active` |
| LED standard | Num Lock et LED Wi-Fi à 1 ; aucune entrée `kbd_backlight` dans `/sys/class/leds` |
| Alimentation | Secteur présent, batterie à 95 %, `Not charging`, courant annoncé nul |
| CPU, politique | `intel_pstate` actif, gouverneur `powersave`, EPP `balance_performance`, profil `balanced` |
| Turbo / limites | Turbo autorisé ; plage de performance 15–100 % |
| Repos CPU | Pilote `intel_idle`, gouverneur `menu`, états exposés non désactivés sur CPU0 |
| GPU NVIDIA | Pilote `595.91.07` open ; fonction GPU PCI `active`, temps suspendu nul |
| RTD3 | `Runtime D3 status: Not supported`, malgré `DynamicPowerManagement: 2` et PCI `control=auto` |
| GPU, relevé ponctuel | P8, utilisation 0 %, mémoire 4 MiB, `power.draw=4.05 W` |
| Réseau | Ethernet et Wi-Fi connectés ; route par défaut Wi-Fi métrique 600, Ethernet 20100 |
| Ethernet EEE | Activé mais inactif ; capacités du partenaire non annoncées |
| Stockage | SSD NVMe WDC PC SN730 1 To ; contrôle runtime PCI `on`, délai APST configuré à 100 000 µs |
| USB inutilisés | Webcam, Bluetooth et lecteur de cartes déjà en `auto`, état `suspended` |
| Bureau | `graphical.target`, GDM et GNOME actifs |
| Services notables | Helios, Docker/Astra, NordVPN, Tailscale, strongSwan, impression, Bluetooth, Avahi, ModemManager |
| Journaux Helios | 8 Mo au relevé ; pas d'indice de volume excessif dans ce constat |

`pidstat -u -w -C 'heliosd|astra|nordvpnd|tailscaled|gnome-shell|Xorg' 5 3`
donne, sur 15 secondes, environ 0,13 % CPU pour Helios, 1,20 % pour NordVPN,
0,67 % pour Tailscale et 0,07 % pour GNOME. Ces pourcentages sont rapportés à
un processeur logique, ne sont pas des watts et ne décrivent pas une charge VPN
soutenue. Astra n'apparaît pas dans cet échantillon : cela ne prouve pas une
consommation nulle. La connexion SSH ajoute elle-même du travail.

Une vérification ultérieure compte zéro connexion TCP établie vers le port
d'administration 8080. Cela décrit uniquement cet instant.

## 3. Clavier, écran et GPU

### Clavier et LED

L'éclairage signalé par l'utilisateur correspond à un contrôleur SteelSeries
USB, distinct des LED Num Lock/Caps Lock. Une commande générique écrivant dans
`/sys/class/leds/*/brightness` ne cible donc pas son RGB. La classe LED Linux
expose les dispositifs pris en charge par un pilote, pas tous les éclairages
physiques ([documentation noyau](https://docs.kernel.org/leds/leds-class.html)).

Premier essai proposé sur place : diminuer le rétroéclairage avec la touche
Fn portant le symbole de luminosité du clavier, jusqu'à extinction. Vérifier
le résultat après redémarrage. Les combinaisons exactes varient selon le
clavier ; ne pas appliquer une combinaison d'un autre modèle
([instructions MSI](https://us.msi.com/support/technical_details/NB_KB_Backlight)).

Pour une commande Linux automatisable, le projet
[msi-perkeyrgb](https://github.com/Askannz/msi-perkeyrgb) utilise par défaut
l'identifiant `1038:1122`. Son option `--disable` envoie une couleur nulle à
toutes les régions ; ce chemin ne dépend pas de la disposition des touches
([commande](https://raw.githubusercontent.com/Askannz/msi-perkeyrgb/master/msi_perkeyrgb/main.py),
[contrôle des régions](https://raw.githubusercontent.com/Askannz/msi-perkeyrgb/master/msi_perkeyrgb/msi_keyboard.py)).
L'outil n'est pas installé et sa compatibilité GP75 n'a pas été testée ici.
Après examen et installation appropriée, la commande candidate serait :

```sh
sudo msi-perkeyrgb --id 1038:1122 --disable
```

Préférer un réglage ponctuel, puis éventuellement un service `oneshot` au
démarrage si l'éclairage revient. Aucun démon RGB permanent n'est nécessaire.
Conserver les permissions restreintes des interfaces HID ; ne pas reprendre
une ouverture globale des `/dev/hidraw*`. Ne pas confondre extinction du RGB
et suspension USB : cette dernière ne garantit pas l'extinction des LED.
Le gain clavier et celui des petites LED restent à mesurer.

### Écran et bureau

L'écran interne est déjà éteint au relevé : aucun gain supplémentaire lié à
son extinction ne peut être annoncé dans cet état. GDM/GNOME restent actifs.
Un essai sans gestionnaire de connexion graphique peut réduire du travail
ou libérer des ressources graphiques, mais son gain n'est pas établi.
Prévoir le retour au bureau et l'accès console avant cet essai.
Fermer le capot n'est pas une solution à appliquer sans vérifier la politique
de veille et la ventilation : la passerelle doit continuer de router.

### GPU : une limitation identifiée du pilote installé

La RTX est de génération Turing. La documentation **595.91.07**, correspondant
au pilote installé, limite RTD3 avec les modules open à Ampere et générations
suivantes ([NVIDIA, limitations connues](https://download.nvidia.com/XFree86/Linux-x86_64/595.91.07/README/kernel_open.html)).
Cela explique l'indication locale `Not supported` ; ajouter à nouveau
`DynamicPowerManagement=2` ne suffit pas, ce réglage est déjà présent.

Pistes à évaluer : fonctionnement avec le seul GPU Intel, désactivation du
GPU dédié dans le firmware si cette option existe, ou combinaison pilote/module
compatible avec RTD3 sur Turing et avec le noyau Ubuntu installé. Aucune de ces
options n'a été validée sur cette machine. Ne pas retirer le GPU du bus ou
changer le pilote à distance sans retour arrière et accès console préparés.
Un changement de firmware ou de démarrage doit suivre les procédures TPM
existantes, car il peut modifier les PCR (ADR-006/007).

La requête `nvidia-smi` était ponctuelle, après observation d'un GPU déjà actif.
La surveillance continue du GPU peut elle-même le solliciter. Pour confirmer
une veille, privilégier `runtime_status` et l'augmentation de
`runtime_suspended_time`, puis mesurer à la prise.

## 4. CPU, réseau, stockage et services

Comparer le profil déjà disponible `power-saver` au profil actuel `balanced`.
Avec `intel_pstate`, le nom `powersave` ne signifie pas fréquence minimale fixe ;
l'EPP et les limites de performance comptent aussi
([documentation Intel P-state](https://docs.kernel.org/admin-guide/pm/intel_pstate.html)).
Tester ensuite les limites turbo seulement si nécessaire : une fréquence plus
basse peut allonger le travail, les négociations et les transferts. Le résultat
doit être jugé en énergie pour une même charge et en latence, pas en fréquence.

La résidence réelle du paquet CPU dans ses états de repos n'a pas été mesurée.
Les états disponibles ne prouvent pas leur utilisation à l'échelle du paquet
([CPUIdle](https://docs.kernel.org/admin-guide/pm/cpuidle.html)).
`turbostat` est installé, mais nécessite des droits indisponibles ici.

**Le Wi-Fi est la route Internet prioritaire actuelle.** Son extinction peut
couper SSH, Tailscale ou le WAN utilisé par Helios. Vérifier la topologie et
le basculement Ethernet avant de proposer sa désactivation ; conserver les
sémantiques multi-uplink et les règles firewall/NAT existantes.
Une contre-vérification trouve Ethernet en connectivité NetworkManager
« limité », Wi-Fi en « plein » ; `ip -4 route get 1.1.1.1` choisit `wlo1`.
La métrique Ethernet 20100 correspond à 100 + la pénalité de connectivité
20000 décrite par [NetworkManager](https://www.networkmanager.dev/docs/api/latest/NetworkManager.conf.html).
L'investigation complémentaire confirme le blocage Ethernet par le pare-feu
Helios, lié à une course au démarrage : voir §4.1 ci-dessous.
La route du réseau local conserve Ethernet à 100 contre Wi-Fi à 600 ; le
constat de priorité Wi-Fi concerne la sortie Internet par défaut, pas tous
les flux ni toutes les routes VPN.
EEE est déjà activé : vérifier le switch et la négociation de lien plutôt
qu'activer une seconde fois ce réglage
([interface ethtool du noyau](https://docs.kernel.org/networking/ethtool-netlink.html)).

Le NVMe est une piste secondaire. Son contrôle runtime PCI et son APST sont
deux mécanismes distincts ; le délai configuré ne prouve pas l'état APST réel.
Comparer toute optimisation avec les latences d'E/S et les erreurs noyau.
Webcam, Bluetooth USB et lecteur de cartes sont déjà suspendus : potentiel
supplémentaire probablement limité dans l'état relevé.
L'ASPM est sur la politique par défaut ; ne pas forcer une politique PCIe
globalement sans tester chaque périphérique.

L'inventaire montre des services de bureau/impression et `strongswan.service`.
Leur présence justifie une vérification d'utilité, pas une suppression automatique.
NordVPN et Tailscale travaillent davantage que Helios dans l'échantillon ;
leurs fonctions de sortie ou d'administration peuvent être indispensables.
Docker héberge Astra : l'arrêter supprimerait une fonction du produit.
Conserver synchronisation horaire, mises à jour de sécurité et protections
thermiques. N'appliquer aucun réglage global `powertop --auto-tune` sur ce
routeur : évaluer séparément les changements USB/PCI/réseau.

### 4.1. Pourquoi le RJ45 perd sa priorité : investigation complémentaire

Diagnostic du 1er octobre après 14 h 32, sans modification réseau, complété
par la table nftables transmise par l'utilisateur.
Deux problèmes indépendants ont été observés.

**Le RJ45 est absent de la liste WAN retenue au démarrage d'Helios.**
Les journaux du démarrage du 30 septembre donnent cette séquence :

| Heure locale | Événement relevé |
| --- | --- |
| 19:41:16 | Le pilote Ethernet rapporte un lien descendant |
| 19:41:20 | Helios résout les WAN : `interfaces=wlo1 preferred=wlo1` |
| 19:41:21 | Helios applique sa table nftables : politique Drop, 47 règles |
| 19:41:28 | Ethernet devient actif, à `100Mbps/Full` |
| 19:41:29 | NetworkManager termine l'activation et obtient le bail Ethernet |

Dans [la résolution WAN](../../crates/heliosd/src/commands/wan.rs),
`resolve_uplink` remplace `auto` une fois au démarrage. Le sélecteur
[uplink](../../crates/heliosd/src/uplink.rs), `InterfaceFacts::usable`,
ne retient que les interfaces physiques avec porteuse. L'Ethernet existe,
mais est exclu parce que sa porteuse n'est pas encore établie ; ce cas ne se
limite donc pas aux adaptateurs branchés après le démarrage.

Les [sorties propres à la passerelle](../../crates/helios-firewall/src/ruleset/gateway_wan.rs)
sont ensuite autorisées sur les WAN retenus, interface par interface.
La politique reste fermée pour les interfaces non déclarées. Aucun suivi des
changements de porteuse n'actualise cette liste. Le rechargement de la
configuration préserve la liste déjà résolue lorsqu'il relit `auto`.

Les tests en lecture seule sont cohérents avec un blocage local :

| Test forcé sur l'interface, sans proxy | Ethernet `enp3s0` | Wi-Fi `wlo1` |
| --- | --- | --- |
| Sonde HTTP `connectivity-check.ubuntu.com` | Connexion expirée après 3 s | HTTP 204, en-tête `online` |
| HTTPS `ubuntu.com` | Connexion expirée après 3 s | HTTP 200 |
| Sonde HTTP avec IP résolue imposée, sans dépendre du DNS | Connexion expirée | HTTP 204 |
| Compteur Ethernet pendant cette dernière sonde | TX reste à 2947 paquets / 124501 octets | Le compteur Wi-Fi augmente pendant son test |

Le routage forcé `ip route get 1.1.1.1 oif enp3s0` trouve bien une route via
la Livebox. `rp_filter=2` sur les deux interfaces et globalement ne correspond
pas au cas de filtrage inverse strict documenté par NetworkManager. NordVPN
annonce `Disconnected` ; Meshnet et ses routes restent présents, mais les
requêtes testées portent sur des adresses Internet hors CGNAT.

Les journaux NetworkManager montrent aussi des tentatives de retour à
Ethernet à 05:31:21, 10:11:22 et 12:11:23, suivies une seconde plus tard d'un
retour au Wi-Fi. La table nftables transmise confirme donc le mécanisme :
**Ethernet absent des WAN autorisés → sonde bloquée → connectivité limitée
→ pénalité de 20000 → Wi-Fi préféré**.

L'utilisateur a fourni la sortie de `sudo nft list table inet helios`.
La chaîne `output`, de politique `drop`, autorise DNS, HTTP, HTTPS et NTP
uniquement sur `wlo1` ; aucune règle ne nomme `enp3s0`. Les listeners WireGuard
et de négociation, les ouvertures DHCP, les sorties marquées NordVPN et la
sortie Meshnet relayée sont aussi limités au Wi-Fi. Les connexions nouvelles
par Ethernet tombent donc sous la politique fermée. Les ouvertures génériques
`established,related` ne suffisent pas à créer ces connexions.
Cette confirmation porte sur la table Helios, pas sur une capture privilégiée
ou un inventaire de toutes les tables d'autres logiciels.
Les pings vers la Livebox échouent sur les deux interfaces et ne permettent
pas de conclure sur le câble.

**Le lien Ethernet négocie 100 Mbit/s, malgré une carte compatible gigabit.**
`ethtool enp3s0` indique `Speed: 100Mb/s`, `Duplex: Full`, autonegotiation
active. Le MSI annonce `1000baseT/Full`, mais le partenaire de lien annonce
seulement 10/100 Mbit/s. Les compteurs d'erreurs CRC/RX/TX relevés sont nuls ;
cela ne valide pas les quatre paires nécessaires au gigabit.
Le chemin indiqué de mémoire par l'utilisateur est prise murale → switch
→ Livebox. Le modèle et les capacités du switch, le câblage et la configuration
de son port restent inconnus. Ne pas attribuer la limite au câble seul.

Le Wi-Fi présente un signal de -80 dBm et des débits de liaison instantanés
RX 130 / TX 45 Mbit/s. Ce ne sont pas des débits applicatifs mesurés.
Passer au câble peut améliorer stabilité et débit, mais un lien plafonné à
100 Mbit/s ne peut pas fournir un accès gigabit.

**Corrections proposées, non appliquées :**

1. Confirmer la table Helios active, puis déclarer explicitement les deux
   uplinks autorisés avec `wan_iface = ["enp3s0", "wlo1"]` dans la configuration
   existante, sans la reconstruire depuis une vue API dépourvue de secrets.
   Vérifier l'application atomique et l'adoption des secrets via le chemin de
   rechargement établi. Cette liste autorise les deux chemins ; les métriques
   Linux restent responsables de la préférence. Un simple redémarrage après
   activation des deux interfaces serait un test temporaire, pas une solution
   durable à la course au démarrage.
2. Vérifier que la sonde Ubuntu réussit par Ethernet, que la pénalité disparaît
   et que la route Internet choisit `enp3s0`. Ne pas simplement imposer une
   métrique plus basse à une sortie encore bloquée, ni désactiver la sonde.
3. Vérifier le modèle du switch et ses ports, puis faire sur place un essai
   avec un câble connu bon directement sur un port gigabit de la Livebox.
   Le critère est `Speed: 1000Mb/s` ; isoler ensuite le segment limitant du
   chemin habituel. Ne pas forcer `speed 1000 autoneg off` à distance.
4. Comparer le débit utile et la latence à charge identique, puis examiner
   l'extinction du Wi-Fi avec accès distant et secours vérifiés.

Une correction du mode `auto` serait un travail logiciel distinct : traiter
les interfaces présentes mais sans porteuse au démarrage, avec une politique
d'admission d'uplink explicite, sans affaiblir le kill-switch initial, sans
déplacer simplement Helios après `network-online.target`, et en appliquant
le ruleset complet atomiquement. Les invariants et tests multi-uplink restent
requis ; aucune modification de ce comportement n'est incluse dans ce diagnostic.

## 5. Pistes dans Helios et Orion

Les nombres ci-dessous comptent des échéances de tâches, pas des réveils
physiques distincts, des paquets effectivement transmis ou de l'énergie.

| Composant, source | Comportement actuel | Proposition et contraintes |
| --- | --- | --- |
| [Télémétrie WAN](../../crates/heliosd/src/orchestrator/telemetry.rs), `spawn_telemetry_loop` | Lit `/proc/net/dev` toutes les 1 s, même sans lecteur ; environ 86 400 lectures/jour | Échantillonnage selon lecteurs/visibilité, cadence ralentie au repos. Calculer les débits avec le temps réellement écoulé et réinitialiser la référence après pause |
| [Rechargement](../../crates/heliosd/src/orchestrator/reload.rs), `spawn_network_config_watcher` | Un `stat` toutes les 2 s ; relit seulement si taille/date changent | Notifications du répertoire parent pour couvrir le remplacement atomique ; resynchronisation après débordement et conservation de `adopt_runtime_secrets_from` |
| [Admissions](../../crates/heliosd/src/certificates/admission.rs), `spawn_admission_drain` | Scrute la boîte d'admission toutes les 2 s | Notifications, balayage initial et reprise sans perte/double admission ; conserver vérifications et erreurs explicites |
| [Astra](../../crates/astra/src/daemon.rs), `spawn_transition_sweep` | Toutes les 2 s, oublie les transitions d'ancre arrivées au terme de leur fenêtre. La boîte de dépôt des campagnes que cette boucle scrutait aussi a disparu avec le lot 5a de F14 : les ouvertures arrivent par la porte du service | Programmer le balayage sur la prochaine échéance plutôt qu'à intervalle fixe ; ne pas supprimer les expirations en supprimant la scrutation |
| [Observation WireGuard](../../crates/heliosd/src/orchestrator/observation.rs), `spawn_handshake_poller` | Lecture pairs toutes les 10 s | Conserver initialement : participe aux transitions d'état et à l'application du firewall |
| [Nettoyage PSK](../../crates/heliosd/src/key_negotiation/server.rs), `spawn_psk_reclaimer` | Vérification toutes les 10 s | Conserver initialement : nettoyage du plan de données et propriété par génération |
| [Certificats](../../crates/heliosd/src/certificates/service.rs), `spawn_maintenance` | Échéances toutes les 60 s | Faible priorité ; préserver baux, overlaps et destruction des générations sortantes |
| [Santé web](../../web/src/components/HealthPanel.tsx), `HealthPanel` | Requête `/api/health` toutes les 5 s tant que monté | Suspendre hors visibilité, rafraîchir au retour ; pas de sondes concurrentes ni états trompeurs |
| [WebSocket web](../../web/src/hooks/useHelios.ts), `useHelios` | Chaque télémétrie met à jour le tableau React ; reconnexion avec délai croissant | Réduire l'affichage invisible tout en livrant les événements d'état ; fiabiliser l'arrêt des reconnexions au démontage |
| [Atteignabilité Orion](../../crates/orion-core/src/telemetry.rs), `run` | `/api/status` toutes les 3 s après `Up`, client HTTP réutilisé | Cadence adaptative ou évolution du flux existant ; ce signal ne remplace jamais la preuve WireGuard |
| [Orion shell](../../apps/orion/src-tauri/src/main.rs), `HANDSHAKE_POLL_INTERVAL` | Observation locale toutes les 3 s pendant la connexion | Ne pas arrêter la surveillance du tunnel quand la fenêtre est masquée |
| [Astra UI Orion](../../apps/orion/src/App.tsx) | Trois appels IPC toutes les 3 s, même sans cérémonie active | Notifications du propriétaire de l'état ou cadence adaptée ; ne pas masquer une opération lors d'une lecture partielle/échouée |
| [Durées affichées](../../web/src/views/Overview.tsx), [Orion](../../apps/orion/src/views/ConnectView.tsx) | Rafraîchissement chaque seconde pendant connexion | Suspendre les mises à jour visuelles invisibles ; recalculer depuis les dates au retour |

Les trois scrutations de fichiers à 2 s représentent environ 129 600 échéances
par jour si toutes sont actives. Remplacer ces scrutations n'implique pas un
gain proportionnel de watts : cache, regroupement et autres réveils comptent.
Le watcher actuel évite déjà de relire `network.toml` à chaque passage ; Astra
ne persiste les transitions que lorsqu'elles changent.

Le handler [WebSocket serveur](../../crates/helios-api/src/ws.rs) attend le
broadcast, puis envoie. Avant de piloter la télémétrie par le nombre d'abonnés,
assurer la détection des fermetures même quand aucun événement n'est émis.
Garder les notifications de sécurité indépendantes de l'abonnement aux métriques.

Les scrutations rapides à 250 ms pendant confirmation d'une négociation sont
temporaires et liées au handshake frais. Ce ne sont pas des tâches permanentes
à supprimer. Conserver le plan de données WireGuard noyau et les signatures
hybrides ; ne pas réduire la protection cryptographique pour économiser.

`PersistentKeepalive=25` a un coût, mais ADR-001 §3 l'impose pour l'inférence de
vie du tunnel. Le mettre à zéro ferait considérer un tunnel silencieux comme
périmé et peut déclencher du nettoyage PSK. WireGuard standard peut être
silencieux sans keepalive ; Helios a un contrat supplémentaire
([WireGuard](https://www.wireguard.com/quickstart/), [ADR-001](../adr/ADR-001-WIREGUARD.md)).
Une évolution demanderait une décision explicite, des tests de sécurité et de
NAT, et une mise à jour du protocole si nécessaire.

Les timers systemd sont secondaires : purge horaire, fenêtre TPM toutes les
5 minutes dans le dépôt avec `AccuracySec=1min`. systemd sait regrouper les
échéances ([documentation](https://github.com/systemd/systemd/blob/main/man/systemd.timer.xml)).
La liste de timers cible consultée ne montre pas le timer de fenêtre TPM ;
aucune consommation de celui-ci n'a été attribuée à cette passerelle.
Les builds release utilisent déjà `lto=thin` et `strip=true` ; ces options ne
prouvent pas une économie électrique. Les builds/tests ciblés et le cache
partagé réduisent le travail de développement ; conserver la régression
canonique avant livraison. Éviter compilations et tests de débit continus sur
la passerelle en exploitation.

## 6. Mesure et validation avant déploiement

Utiliser une mesure à la prise incluant l'alimentation. RAPL couvre des domaines
CPU et ne remplace pas le total machine
([powercap](https://docs.kernel.org/power/powercap/powercap.html)).
Ici, `energy_uj` est lisible par root uniquement, `sudo -n` demande une
authentification et la batterie sur secteur n'annonce pas une puissance totale.
Ni watts CPU ni watts machine n'ont donc été mesurés.

Comparer A/B/A, une modification à la fois, avec charge et conditions identiques :

1. Référence au repos 10–15 minutes après stabilisation, sans UI ouverte.
2. Répéter avec un client connecté inactif, puis avec la console ouverte.
3. Trafic représentatif à débit fixé, mêmes pairs et distribution de paquets ;
   relever Wh, débit utile, latence médiane/p95/p99, pertes et retransmissions.
4. Répéter les cas pour clavier éteint, GPU effectivement suspendu, profil CPU,
   bureau arrêté, puis optimisations logicielles ; ne pas additionner les gains
   de tests indépendants sans mesurer la combinaison finale.
5. Après validation courte, comparer 24 heures représentatives et un redémarrage.

Noter température, charge batterie, trafic NordVPN/Tailscale et tâches apt/snap
pour expliquer les variations. Rapporter watts moyens au repos, Wh sur durée
fixe et joules/Go utile sous charge. Une baisse de watts qui ralentit un transfert
ne garantit pas une baisse d'énergie pour ce transfert.

Pour un gain constant sur 365 jours : **kWh/an = watts économisés × 8,76**.
Exemples arithmétiques, pas prévisions : 1 W → 8,76 kWh/an ; 4 W → 35,04 ;
10 W → 87,6. Multiplier par le tarif réel du contrat pour obtenir le coût.

Pour les modifications logicielles, valider lecteurs absents/présents,
pause/reprise, débit nul, intervalles variables, fermeture WS, rechargement par
rename et débordement de notifications, annulation et échéances de confiance.
Exécuter les tests ciblés, puis `bash scripts/regression.sh` pour les changements
transversaux. Sur cible, revérifier : handshake/commit, expiration, nettoyage
PSK, kill-switch, trafic uniquement en `Up`, reprise après panne et multi-uplink.
Voir [la stratégie de test](../testing/TESTING.md).

Ne pas mettre automatiquement en veille toute la passerelle : cela interrompt
le service VPN. Ne pas retirer le tunnel Orion sur panne pour réduire son coût.
Un remplacement par du matériel moins consommateur serait une étude ultérieure,
fondée sur des mesures et tenant aussi compte de la fabrication et du réemploi
du MSI. L'investigation présente concerne d'abord l'électricité en exploitation.

## 7. Limites et prochaine campagne

Il reste à mesurer la consommation à la prise, le gain RGB et RTD3, les états
de repos du paquet CPU, le comportement APST et les performances sous charge.
Ces points nécessitent instrumentation, accès administrateur ou présence
sur place. Aucun changement matériel n'a été testé et aucune économie totale
chiffrée n'est revendiquée. Les mesures SSH et la revue du code établissent
des priorités, pas une validation énergétique sur 24 heures.
