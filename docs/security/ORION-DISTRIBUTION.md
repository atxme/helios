# Livraison des installateurs Orion

Les installateurs Orion ont deux chaînes distinctes. Authenticode permet au
chargeur Windows d'identifier l'éditeur interne ; les signatures hybrides
Ed25519 + ML-DSA-65 de l'ADR-002 autorisent le contenu Helios. Une clé de l'une
ne doit jamais servir à l'autre et `helios-publisher` ne manipule aucun
certificat X.509.

## Dépendance WireGuardNT

`defguard_wireguard_rs` 0.11.0 ouvre, sur Windows x86-64,
`resources-windows/binaries/wireguard-amd64.dll` relativement au répertoire
courant. Sur ARM64 il ouvre `wireguard-arm64.dll`. Ces noms viennent de sa
source ; ils ne sont pas une convention inventée par le bundle Orion.

Le build Windows prépare automatiquement les ressources avant de compiler
Orion. Pour préparer les DLL sans compiler le client, utiliser :

```sh
cargo xtask orion-deps
```

La commande télécharge l'archive officielle WireGuardNT 1.1, refuse plus de
16 Mio, vérifie son SHA-256 épinglé, puis extrait les deux DLL et la licence
dans `resources-windows/`. Ce répertoire et l'archive en cache restent hors Git.
La configuration Tauri Windows exécute aussi cette commande avant le build et
place le répertoire sous `bundle.resources`.

## Association `.orion` et icône de document

Les profils clients portent l'extension `.orion` — `.orionprofile` jusqu'en
août 2026. Les documents déjà écrits restent **lus** : `ORION_SUFFIXES` de
`orion-core` accepte les deux suffixes, et le filtre du double-clic aussi.
Seul l'enregistrement système change : l'installateur ne déclare plus que
`.orion`, donc un double-clic sur un ancien fichier ne démarre plus Orion. Le
glisser sur le bouton *Importer* fonctionne toujours, et le renommer suffit.

Le gabarit WiX de Tauri écrit un ProgID **annoncé sans icône**, ce qui fait
retomber Windows sur celle de l'exécutable : un profil s'affichait alors avec
l'icône de l'application qui l'ouvre. `bundle.fileAssociations` n'a pas de champ
d'icône, d'où le fragment `windows/orion-profile-icon.wxs`, référencé par
`wix.fragmentPaths` et `wix.componentRefs`. Il pose deux valeurs sous
`HKLM\Software\Classes\Orion.orion` : le nom affiché dans la colonne *Type* de
l'Explorateur, et un `DefaultIcon` visant `orion-profile.ico`, livrée en
ressource à côté de `orion.exe`.

L'identifiant `Orion.orion` est celui que le gabarit fabrique à partir de
`productName` et de l'extension déclarée. Le couplage est **testé**
(`windows_bundle_gives_orion_profiles_their_own_icon`) : renommer le produit ou
l'extension sans suivre cette clé produirait un installateur qui se construit,
s'installe, et affiche la mauvaise icône.

**Limite connue.** Cela ne vaut que pour le MSI. Le paquet NSIS
(`cargo xtask orion-msi --with-nsis`) écrit sa propre association avec l'icône
de l'exécutable ; le MSI est le format livré.

## Autorité interne Authenticode

Créer l'autorité dans un emplacement protégé hors du dépôt :

```sh
bash scripts/orion-internal-ca.sh /media/coffre/autorite-orion
```

La recette OpenSSL produit :

- `authority-offline/orion-root-ca.key`, qui reste hors ligne ;
- `authority-offline/orion-root-ca.cer`, seule racine à distribuer ;
- `signing-station/orion-code-signing.pfx`, importé uniquement sur le poste de
  signature Windows.

L'import de la racine sur chaque poste client est une opération
d'administration hors bande :

```powershell
Import-Certificate -FilePath .\orion-root-ca.cer -CertStoreLocation Cert:\LocalMachine\Root
```

L'import du PFX se fait dans `Cert:\CurrentUser\My` sur le poste de signature.
Son empreinte SHA-1 publique alimente `ORION_SIGNING_CERT_SHA1`.

## Build et horodatage obligatoires

Le fichier `tauri.windows.conf.json` force tous les artefacts Windows produits
par Tauri à passer par `windows/sign-orion.ps1`. Ce script refuse de signer si
l'empreinte du certificat ou l'URL RFC 3161 manque, appelle `signtool` avec
`/fd SHA256 /tr … /td SHA256`, puis vérifie avec `/pa /tw`.

```powershell
$env:ORION_SIGNING_CERT_SHA1 = "EMPREINTE_SHA1_SANS_ESPACES"
$env:ORION_TIMESTAMP_URL = "https://tsa.interne.example/rfc3161"
npm run tauri build --prefix apps/orion -- --features wireguard
```

Le serveur d'horodatage doit être disponible pendant le build. Une signature
sans jeton temporel n'est pas une release : après expiration du certificat,
Windows ne pourrait plus établir que le binaire avait été signé pendant sa
période de validité.

## Fabrication en CI, signature hors ligne

Personne n'installe de chaîne de compilation pour utiliser Orion : la CI
fabrique l'installateur, et l'utilisateur reçoit un MSI. Le job `orion-windows`
de `release.yml` tourne sur `windows-latest` — le bundling MSI/NSIS et
l'édition de liens MSVC n'ont pas d'équivalent croisé depuis Linux — et publie
les installateurs **non signés** avec leurs empreintes.

La CI ne détient aucun certificat, et ne doit pas en détenir. Elle emprunte donc
un chemin explicite :

```text
ORION_UNSIGNED_FOR_OFFLINE_SIGNING=1
```

`sign-orion.ps1` refuse toujours de signer sans certificat ni horodatage ; cette
variable, comparée strictement à `1`, lui fait sauter la signature en le disant
bruyamment. Le job renomme ensuite les artefacts en `-unsigned` et **vérifie par
`Get-AuthenticodeSignature` qu'ils sont réellement nus** : un artefact à moitié
signé serait le pire des deux états.

La suite se joue sur le poste de signature : télécharger l'artefact, le signer
avec `windows/sign-orion.ps1` en fournissant les deux variables ci-dessus, puis
distribuer. C'est la même séparation que pour le bundle gateway, où la CI
assemble et où `helios-publisher` signe hors ligne.

Une machine Windows de développement reste utile pour itérer, mais elle n'est
plus le seul chemin vers un installateur.

## Amorçage circulaire

Le premier installateur ne peut pas installer la racine qui doit déjà le rendre
digne de confiance. La racine `orion-root-ca.cer` est donc provisionnée avant
le premier lancement, par stratégie de groupe, gestion de parc ou commande
d'administration explicitement exécutée. L'installateur Orion ne modifie jamais
le magasin `Root`.

Ce même ordre vaut pour une machine neuve restaurée : racine hors bande, puis
vérification Authenticode, puis installation. Un certificat public EV pourrait
supprimer ce bootstrap interne et améliorer la réputation SmartScreen ; cette
décision de coût reste hors de ce lot.

## Privilèges des paquets

Sous Windows, le manifeste de l'exécutable demande `requireAdministrator`.
Sous Linux, le `postinst` du paquet `.deb` pose seulement
`cap_net_admin=ep` sur `/usr/bin/orion`; `libcap2-bin` est une dépendance du
paquet. La recette cible doit vérifier le tunnel réel, les routes et le
lancement WebKitGTK après installation.
