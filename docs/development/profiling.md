# Profilage en fonctionnement réel

Ce guide mesure la passerelle `heliosd` et le client Orion sur leurs machines
cibles. Il relève CPU, mémoire, charge système et latence HTTP pendant des
phases de charge comparables. Les mesures faites dans WSL2 ou avec `--dev`
servent au développement ; elles ne représentent ni le noyau WireGuard réel,
ni le matériel de production.

## Préparer une campagne

Choisir une durée (par exemple 5 minutes par phase), garder les mêmes postes,
versions, réseau et nombre de pairs, puis répéter chaque phase trois fois :

1. Helios démarré, aucun client connecté ;
2. Orion connecté, trafic presque nul ;
3. transfert soutenu via le tunnel avec le speedtest déjà intégré ;
4. mêmes opérations avec le nombre habituel de clients.

Noter la version (`heliosd --version` et version Orion), le modèle de CPU, la
RAM, le système, le nombre de pairs et le débit offert. Faire les mesures
depuis un autre poste quand c'est possible : les commandes de surveillance et
les sondes contribuent elles-mêmes à la charge.

## Passerelle Linux

Sur la gateway, relever l'identifiant du processus et lancer `pidstat` (paquet
`sysstat`) à une seconde d'intervalle. Garder la sortie par phase :

```sh
pidof heliosd
pidstat -h -u -r -d -w -p "$(pidof heliosd)" 1 300 | tee heliosd-pidstat.txt
```

`%CPU` est rapporté à un cœur logique ; `RSS` donne la mémoire résidente en
Kio. Pour le contexte machine, l'API publique de lecture fournit déjà
`/api/health` : uptime, charge moyenne, nombre de processeurs, mémoire totale
et disponible, température si le noyau la publie.

```sh
curl -fsS http://127.0.0.1:8080/api/health | tee helios-health.json
```

Mesurer la latence des lectures API depuis le poste client, à travers le
tunnel. Cette boucle écrit le temps total et le code HTTP pour chaque requête :

```sh
for i in $(seq 1 300); do
  curl -sS -o /dev/null -w '%{time_total},%{http_code}\n' \
    http://100.64.0.1:8080/api/status
  sleep 1
done > helios-api-latency.csv
```

Remplacer `100.64.0.1` par la VIP réelle. Le temps inclut réseau, tunnel,
serveur et encodage de la réponse ; il ne mesure pas le délai de rendu UI.
Calculer médiane, p95 et p99 sur les lignes HTTP 2xx, et compter séparément
les erreurs et expirations. Faire les mêmes requêtes sur `/api/health` si l'on
veut suivre les valeurs machine pendant la campagne.

## Client Orion

### Linux

Lancer Orion normalement, trouver son PID et surveiller aussi ses processus
WebKit/Tauri fils :

```sh
pgrep -a -f 'orion|Orion'
pstree -ap "$(pgrep -n -x orion)"
pidstat -h -u -r -d -w -p ALL 1 300 | tee orion-pidstat.txt
```

Dans le relevé `pidstat`, isoler le PID Orion et les PID de ses descendants
affichés par `pstree`. Si plusieurs processus Orion tournent, sélectionner
ceux de la session testée. Pour la mémoire du groupe, comparer la somme des RSS
des processus à chaque instant ; noter que les pages partagées peuvent alors
être comptées plusieurs fois.

### Windows

Dans le Gestionnaire des tâches, afficher les colonnes **PID**, **Processeur**,
**Mémoire (jeu de travail)** et **Taille de validation** pour Orion et ses
processus WebView2. Pour un relevé horodaté depuis PowerShell :

```powershell
Get-Counter '\Process(*)\% Processor Time','\Process(*)\Working Set - Private' `
  -SampleInterval 1 -MaxSamples 300 |
  Export-Counter -Path .\orion-performance.blg -FileFormat BLG
```

Dans PerfMon, filtrer les instances `orion` et `msedgewebview2` correspondant
à la session. `% Processor Time` peut dépasser 100 % si plusieurs cœurs sont
utilisés ; diviser par le nombre de processeurs logiques pour le pourcentage
machine.

## Lire les résultats

Conserver séparément les valeurs au repos et sous charge. Pour chaque phase,
rapporter le CPU moyen et le maximum, le RSS moyen et le maximum, le minimum de
mémoire disponible, ainsi que médiane/p95/p99 et taux d'erreur des requêtes.
Joindre les fichiers bruts et noter les événements (connexion, début/fin du
transfert). Une moyenne seule masque les pointes et les ralentissements.

La latence de `/api/status` est une mesure de bout en bout de cette route. Elle
ne donne pas une distribution par endpoint ni une latence interne du serveur.
Le speedtest mesure le débit du tunnel, pas la consommation électrique. Pour
les watts de la machine entière, utiliser un wattmètre à la prise ; les
estimations CPU, la charge moyenne et la température ne se convertissent pas
fiablement en watts.

Le processus `heliosd` tourne avec les privilèges de la gateway : ne lancer les
outils avec `sudo` que si les droits de lecture du PID l'exigent. Ne pas
ajouter les fichiers de campagne au dépôt : ils décrivent une machine et une
session précises.
