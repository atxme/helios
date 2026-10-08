# Livraison des installateurs Orion

Les installateurs Orion ont deux chaînes distinctes. Authenticode permet au
chargeur Windows d'identifier l'éditeur interne ; les signatures hybrides
Ed25519 + ML-DSA-65 de l'ADR-002 autorisent le contenu Helios. Une clé de l'une
ne doit jamais servir à l'autre et `helios-publisher` ne manipule aucun
certificat X.509.

## Dépendance WireGuardNT

`defguard_wireguard_rs` 0.12 ouvre, sur Windows x86-64,
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

Depuis une console PowerShell ouverte sous le compte Windows dédié au runner :

```powershell
.\scripts\setup-orion-signing.ps1 `
  -PfxPath C:\transfert\orion-code-signing.pfx `
  -RootCertificatePath C:\transfert\orion-root-ca.cer `
  -ExpectedThumbprint EMPREINTE_SHA1_SANS_SEPARATEURS
```

Le script demande le mot de passe sans l'écrire dans la ligne de commande,
contrôle l'empreinte, l'EKU Code Signing et l'expiration, puis importe la clé
sans la rendre exportable. Il approuve la racine pour le seul compte de
signature et configure l'horodateur RFC 3161 utilisé dans l'exemple officiel
de SignTool. La copie de transfert du PFX est supprimée manuellement après le
premier build vérifié ; la racine privée reste dans `authority-offline`.

## Build et horodatage obligatoires

Le fichier `tauri.windows.conf.json` force tous les artefacts Windows produits
par Tauri à passer par `windows/sign-orion.ps1`. Ce script refuse de signer si
l'empreinte du certificat ou l'URL RFC 3161 manque, appelle `signtool` avec
`/fd SHA256 /tr … /td SHA256`, puis vérifie avec `/pa /tw`.

```powershell
$env:ORION_SIGNING_CERT_SHA1 = "EMPREINTE_SHA1_SANS_SEPARATEURS"
$env:ORION_TIMESTAMP_URL = "http://timestamp.digicert.com"
npm run tauri build --prefix apps/orion -- --features wireguard
```

Le serveur d'horodatage doit être disponible pendant le build. Une signature
sans jeton temporel n'est pas une release : après expiration du certificat,
Windows ne pourrait plus établir que le binaire avait été signé pendant sa
période de validité.

## Fabrication et signature sur le runner interne

Personne n'installe de chaîne de compilation pour utiliser Orion : le runner
Windows interne fabrique et signe le MSI, puis l'utilisateur reçoit ce MSI. Le
bundling WiX et l'édition de liens MSVC n'ont pas d'équivalent croisé depuis
Linux ou WSL2.

Le runner porte les labels `self-hosted`, `windows`, `x64` et
`orion-signing`. Il utilise un compte Windows dédié, dans lequel le PFX est
importé sans être exportable. Rust stable, Node 24, le SDK Windows et
`signtool.exe` sont préinstallés. Les variables de dépôt
`ORION_SIGNING_CERT_SHA1` et `ORION_TIMESTAMP_URL` ne sont pas secrètes ; le
PFX et son mot de passe ne sont jamais placés dans GitHub.

L'environnement GitHub `orion-signing` doit exiger une approbation. Le job
refuse les lancements manuels hors de `main`; les tags de release doivent être
protégés. Il ne tourne jamais pour une pull request. Après le build, il exige
que chaque MSI ait une signature `Valid`, le certificat attendu et un jeton
d'horodatage, puis calcule les empreintes avant publication.

Le chemin `cargo xtask orion-msi --unsigned` reste disponible uniquement pour
les essais locaux. Aucun artefact empruntant ce chemin n'est publié par la
release.

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
