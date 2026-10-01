# Protection physique et authentification de la gateway

`scripts/gateway-hardening.py` prépare une gateway Linux contre la lecture de
données au repos et l'utilisation de sa console par une personne non autorisée.
Les mots de passe sont saisis au terminal : aucun argument, variable exportée,
journal ou fichier de configuration ne reçoit leur valeur en clair.

Le script ne chiffre pas automatiquement une racine en service. La conversion
nécessite une console locale démarrée sur une clé USB live, une sauvegarde sur
un autre disque chiffré, une partition `/boot` séparée et une récupération
Helios préparée. Sans ces prérequis, il refuse explicitement l'opération.
Les partitions Windows ne sont ni reformatées ni supprimées.

## État initial et décisions d'exploitation

Sur la gateway examinée le 30 septembre 2026, Linux occupe une partition ext4,
Windows occupe d'autres partitions du même NVMe, et `/boot` est dans la racine
Linux. Aucune sauvegarde extérieure n'est disponible. Une ancienne partition
swap existe également, mais le swap utilisé est `/swap.img`.

Ne pas réutiliser une partition sur la seule base de son numéro : la petite
partition swap est une candidate pour `/boot`, uniquement après vérification
locale de son inutilisation et sauvegarde. Le script exige une partition ext4
déjà préparée et vide ; il ne crée, ne supprime et ne formate aucune partition.
Cette préparation reste une opération locale avec un outil de partitionnement.

Le mode livré utilise une passphrase LUKS2, sans clé de déverrouillage sur le
disque ni déverrouillage TPM automatique. Une intervention est donc nécessaire
au démarrage. Le mot de passe GRUB peut imposer une seconde authentification.
Un déverrouillage autonome doit faire l'objet d'une conception distincte du
démarrage vérifié et de ses mesures ; il n'est pas ajouté comme raccourci.

## Authentification du compte et de sudo

Depuis une session interactive, localement ou par SSH :

```sh
sudo python3 scripts/gateway-hardening.py auth --user christophe
```

Par SSH, préserver le contexte pour contrôler aussi les règles `Match` de la
connexion actuelle : `sudo --preserve-env=SSH_CONNECTION python3
scripts/gateway-hardening.py auth --user christophe`. Si ce contexte a été
effacé par sudo, le script refuse avant de changer le mot de passe. Les règles
`Match` visant d'autres adresses ou noms d'hôte restent à vérifier séparément.

Sur la machine où le script est installé sous `/usr/local/sbin` :

```sh
sudo /usr/local/sbin/helios-host-hardening auth --user christophe
```

Le script vérifie que le compte existe et est déjà administrateur et que le
profil PAM Ubuntu `pwquality` est actif. Il exige au moins 20 caractères via ce
module, sans bonus de longueur lié aux classes de caractères, y compris lors
d'un changement effectué par root, puis lance `passwd`.
Il vérifie le profil PAM de `passwd`, refuse les arguments PAM non pris en
charge et contrôle les surcharges des fichiers `pwquality` lus après sa
politique. Une configuration qui abaisse la longueur ou désactive son
application entraîne un refus avant le changement de mot de passe.
Choisir une passphrase longue, unique et composée de plusieurs mots
tirés au hasard, distincte des passphrases du disque et du démarrage.
Le script retire les exceptions de tests Helios, conserve leur copie hors de
`/etc/sudoers.d`, force `PASSWD` et conserve l'authentification sudo pendant
15 minutes dans le même terminal. Une première authentification reste
nécessaire ; `sudo -k` permet d'invalider volontairement le cache. Il valide la
syntaxe avec `visudo`, puis demande une authentification sudo avec le nouveau
mot de passe avant de conserver la politique. Après invalidation du cache,
il vérifie d'abord que sudo refuse une validation sans mot de passe. Si une
autre règle permet encore cette validation, ou si l'authentification échoue,
la politique sudo précédente est restaurée ; le nouveau mot de passe demeure.
Les autres règles sudo sont à revoir si une configuration supplémentaire existe.

Le compte root reste verrouillé. SSH n'accepte que des clés, refuse root et
désactive les redirections TCP, socket, agent et X11. Les clés autorisées
existantes sont conservées. Garder la session courante ouverte jusqu'à ce
qu'une seconde connexion par clé réussisse. Protéger également les clés privées
du poste opérateur par une passphrase ; ne pas déposer ces clés sur la gateway.
La désactivation des redirections affecte notamment les tunnels SSH et certains
outils de développement distant.

## Sauvegarde et récupération obligatoires

Avant une migration, suivre [OPERATOR-TOOLING.md](OPERATOR-TOOLING.md) et les
[ADR-006](../adr/ADR-006-SECRETS-AU-REPOS.md) et
[ADR-007](../adr/ADR-007-FENETRE-DE-MISE-A-JOUR.md).
Préparer la restauration des identités WireGuard, négociation, canal Astra et
des coffres associés. Une copie de blobs scellés ne suffit pas à prouver leur
récupération après changement des PCR. Le seul séquestre WireGuard ne prouve
pas la récupération des autres identités. Ne pas effacer le TPM.

`--recovery-confirmed` est l'attestation de l'opérateur après vérification de
cette récupération ; le script ne réalise pas un test cryptographique de tous
les coffres. Prévoir la restauration ou le ré-enrôlement requis avant d'utiliser
ce drapeau. Les clés privées de récupération restent sur le poste opérateur.

La sauvegarde de migration est une archive complète Linux avec propriétaires,
ACL, attributs et fichiers creux, une archive EFI, la table des partitions,
les sommes SHA-256 et une copie de l'en-tête LUKS. Elle doit résider sur un
volume LUKS extérieur déjà déverrouillé, monté sous un chemin détenu par root
et sans écriture de groupe ou d'autres utilisateurs. Le script contrôle sa
topologie, le type LUKS de sa couche de chiffrement et son espace libre, et
compare le contenu de l'archive Linux à la racine hors ligne avant conversion.
Ce contrôle ne remplace pas un exercice de restauration.

## Conversion Linux lors d'une intervention locale

1. Sur la gateway encore fonctionnelle, installer `cryptsetup-initramfs` avec
   les mécanismes Ubuntu habituels. Cette dépendance doit être présente avant
   la sauvegarde : une conversion ne doit pas dépendre d'un téléchargement
   après chiffrement. Préparer la récupération et l'accès SSH hors tunnel.
2. Arrêter proprement la gateway selon la procédure TPM adaptée au changement
   de démarrage. Démarrer une clé Ubuntu live en UEFI et ouvrir un terminal.
3. Connecter et déverrouiller le disque de sauvegarde extérieur, avec assez de
   place pour les données Linux utilisées plus 2 Gio. Vérifier les partitions
   et préparer une partition ext4 vide suffisamment grande pour `/boot`.
   Ne pas modifier les partitions Windows ni l'ESP.
4. Copier le script sur la clé live. Utiliser `lsblk -f` et `blkid` pour relever
   les appareils et l'UUID de la racine. Les noms peuvent changer après démarrage.
5. Exécuter, en remplaçant chaque valeur par le résultat relevé :

```sh
sudo python3 gateway-hardening.py encrypt-root \
  --root-device /dev/PARTITION_LINUX \
  --root-uuid UUID_EXT4_VERIFIE \
  --boot-device /dev/PARTITION_BOOT_VIDE \
  --efi-device /dev/PARTITION_EFI \
  --backup-directory /mnt/backup-chiffre \
  --recovery-confirmed
```

La racine live doit être `overlay` avec `boot=casper` ; les partitions sélectionnées doivent être
démontées et distinctes. Le script exige une racine ext4 saine, une partition
boot ext4 vide et une ESP FAT. Il refuse les autres montages de données et
swap non couverts, un `/boot` déjà séparé, les liens symboliques sur les points
de montage et toute entrée active de `crypttab`. Les UUID de la racine et de
l'ESP doivent correspondre aux entrées de `fstab`. Ces contrôles ont lieu
avant la sauvegarde et la modification des systèmes de fichiers.
Après confirmation de l'UUID, il sauvegarde Linux et EFI,
copie `/boot`, réduit ext4 de 32 Mio, puis appelle le mécanisme natif de
conversion LUKS2 de cryptsetup, avec Argon2id et vérification de passphrase.
Choisir une passphrase longue et unique dans l'invite native.

Il sauvegarde l'en-tête sur le disque extérieur, ouvre la racine chiffrée,
adapte `crypttab` et `fstab`, monte `/boot` et l'ESP, redirige le petit fichier
`EFI/ubuntu/grub.cfg` vers le nouvel UUID de `/boot`, puis régénère initramfs et
la configuration GRUB dans la racine convertie. Les binaires signés shim/GRUB
sont conservés. L'ESP et les entrées UEFI ne
sont pas reformatées ou supprimées. `/swap.img` demeure à l'intérieur de LUKS.
La partition `/boot` et l'ESP restent lisibles : ne pas y stocker de secrets.

En cas d'interruption, ne pas relancer aveuglément tout le script ni redémarrer
la gateway. La reprise native d'une conversion initialisée utilise
`cryptsetup reencrypt --resume-only /dev/PARTITION_LINUX` depuis le live ; il
faut ensuite contrôler l'état et terminer la préparation du démarrage. En cas
d'échec ultérieur, utiliser la sauvegarde ou terminer manuellement initramfs et
GRUB dans la racine chiffrée montée. Ne jamais lancer `luksFormat` pour reprendre
une conversion. Le script s'arrête sur toute erreur et n'offre pas de reprise
automatique des étapes ; elle exige le diagnostic de l'état réellement atteint.

Une conversion en place ne prouve pas l'effacement des anciens blocs NAND
du SSD, des copies antérieures et des partitions supprimées. Pour éliminer ces
résidus, il faut une migration vers un support neuf ou une procédure d'effacement
du support avec restauration, ce qui nécessite aussi de traiter Windows.
Le chiffrement XTS protège la confidentialité au repos, sans authentifier tous
les secteurs. Secure Boot avec `/boot` séparé ne certifie pas à lui seul un
initramfs modifié hors ligne ; contre une manipulation furtive avant retour de
l'opérateur, une chaîne avec image noyau unifiée signée et mesures adaptées
reste un travail de conception distinct. Le script ne revendique pas cette garantie.

## Authentification GRUB et firmware

Sur la gateway restaurée, localement :

```sh
sudo /usr/local/sbin/helios-host-hardening boot-password
sudo /usr/local/sbin/helios-host-hardening firmware --recovery-confirmed
```

La première commande crée le superutilisateur GRUB `helios-admin`, avec saisie
masquée d'une passphrase d'au moins 20 caractères et hachage natif PBKDF2.
Elle désactive les entrées de récupération générées par Ubuntu. Tester le
démarrage et vérifier que l'édition/la console GRUB demandent le mot de passe.
Les entrées GRUB explicitement `--unrestricted` ne deviennent pas protégées.

La seconde commande demande confirmation puis ouvre le firmware au
redémarrage, si la machine le supporte. Elle ne programme aucun réglage MSI :
activer Secure Boot, conserver le démarrage Ubuntu via `shim`, définir un mot
de passe administrateur UEFI distinct et désactiver USB/PXE inutilisés se font
dans le menu constructeur. Leur contrôle reste local.
Modifier Secure Boot change PCR 7, hors de la fenêtre de mise à jour noyau
Helios ; la récupération doit être prête avant cette opération.

## Windows et validation

Sous Windows, contrôler `manage-bde -status` dans un terminal administrateur,
puis activer BitLocker sur les volumes de données concernés si disponible.
Conserver les clés de récupération hors de la gateway. Ces vérifications
ne sont pas accessibles depuis la session Linux utilisée pour préparer ce script.

Après maintenance, vérifier : `lsblk -f` montre la racine sous un périphérique
`crypt`, une mauvaise passphrase n'ouvre pas le disque, `mokutil --sb-state`
annonce Secure Boot actif, la console GRUB est protégée, sudo demande le nouveau
mot de passe, une nouvelle connexion SSH par clé fonctionne, et Helios/Astra
retrouvent leurs identités et pairs. Une tentative SSH par mot de passe/root
doit échouer. Tester également le démarrage Windows et son chiffrement.

Tests automatisés :

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/tests -p 'test_gateway_hardening.py'
```

Ils éprouvent les refus et les opérations de fichiers sans modifier de machine.
Une migration réelle, le redémarrage chiffré, la récupération TPM, la saisie
GRUB et les réglages firmware exigent une cible de test avec sauvegarde.

Références : [cryptsetup reencrypt](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup-reencrypt.8.adoc),
[Ubuntu FDE](https://documentation.ubuntu.com/security/security-features/storage/encryption-full-disk/),
[Ubuntu OpenSSH](https://ubuntu.com/server/docs/how-to/security/openssh-server/).
