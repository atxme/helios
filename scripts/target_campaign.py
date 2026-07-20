#!/usr/bin/env python3
"""Campagne d'essais matériels Helios, pilotée depuis la machine de dev.

Le dry-run de ``scripts/campaign.sh`` ne prouve rien du plan de données : seule
une cible Linux réelle (noyau nf_tables, module WireGuard, /dev/tpmrm0) tranche.
Ce module joue cette recette de bout en bout, sans dépendance externe.

Deux couches, volontairement séparées :

* les **tests unitaires restent en Rust** — ce module ne les réimplémente pas,
  il exécute ``cargo test --workspace --all-features`` sur la cible et rapporte ;
* la **campagne matérielle** est orchestrée ici, parce qu'elle enchaîne des
  états (daemon monté, handshake attendu, pare-feu engagé) qu'un script shell
  ne sait pas décrire sans devenir illisible.

Survie de la session SSH
------------------------
Le backend Netlink réel installe une table ``inet helios`` en politique *drop*
sur la chaîne ``input``. Une nouvelle connexion SSH serait donc refusée, et la
table survit à l'arrêt du daemon (invariant fail-closed, jamais de teardown).
Deux protections, cumulées :

1. toutes les commandes passent par **une seule** connexion SSH multiplexée
   (``ControlMaster``) : elle est ``established`` avant l'engagement du
   kill-switch, donc acceptée par ``ct state established,related`` ;
2. la configuration générée renseigne ``allow_ssh_from`` avec le préfixe de
   gestion, ce qui rouvre le port 22 même kill-switch engagé.

Malgré cela, les scénarios qui touchent au pare-feu réel exigent ``--pare-feu``
explicite : sans accès console, une erreur de manipulation coûte la machine.

Limite connue
-------------
Les catégories ``rauc`` et ``tpm-billets`` ne sont pas jouées ici. Le
rescellement TPM et le rollback A/B modifient les slots de boot et le NV du
TPM ; les rejouer sans accès console rendrait la cible non amorçable. Ils
restent dans la recette manuelle de docs/testing/MANUAL-TESTING.md. Ce qui
débloquerait leur automatisation : une cible avec console série pilotable et un
TPM logiciel dédié aux essais.

Usage
-----
    python3 scripts/target_campaign.py --host christophe@192.168.1.44
    python3 scripts/target_campaign.py --only unite
    python3 scripts/target_campaign.py --pare-feu --json rapport.json
"""

from __future__ import annotations

import argparse
import atexit
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

# ── Présentation ────────────────────────────────────────────────────────────

_COULEUR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, texte: str) -> str:
    return f"\033[{code}m{texte}\033[0m" if _COULEUR else texte


def info(msg: str) -> None:
    print(f"{_c('1;34', '==>')} {msg}", flush=True)


def detail(msg: str) -> None:
    print(f"    {msg}", flush=True)


class Etat(Enum):
    """Issue d'un scénario. ``HORS_PORTEE`` n'est pas un échec : c'est un
    scénario que l'environnement courant ne permet pas de trancher."""

    OK = "ok"
    ECHEC = "échec"
    HORS_PORTEE = "hors portée"


@dataclass
class Resultat:
    nom: str
    categorie: str
    etat: Etat
    message: str = ""
    duree_s: float = 0.0
    details: list[str] = field(default_factory=list)


# ── Exécution distante ──────────────────────────────────────────────────────


@dataclass
class Sortie:
    code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.code == 0


class Cible:
    """Cible d'essais accessible par SSH, sur une connexion multiplexée unique.

    Le multiplexage n'est pas une optimisation : c'est ce qui garantit que la
    session survit à l'engagement du kill-switch (voir le doc-comment du
    module). Fermer le maître avant la fin de la campagne coupe l'accès.
    """

    def __init__(self, hote: str, repo: str = "~/helios", verbeux: bool = False):
        self.hote = hote
        self.repo = repo
        self.verbeux = verbeux
        self._socket = os.path.join(
            tempfile.mkdtemp(prefix="helios-cible-"), "control.sock"
        )
        self._maitre: subprocess.Popen | None = None

    # -- cycle de vie --------------------------------------------------------

    def resoudre_repo(self) -> str:
        """Résout le dépôt en chemin absolu, une fois pour toutes.

        La règle sudoers autorise ``setcap`` sur un chemin littéral : un dépôt
        désigné par ``~/helios`` ici et par ``/home/…/helios`` là-bas ne
        correspondrait pas, et l'appel serait refusé.
        """
        s = self.executer("pwd -P", dans_repo=True)
        if not s.ok:
            raise RuntimeError(f"dépôt {self.repo} introuvable sur {self.hote}")
        self.repo = s.stdout.strip()
        return self.repo

    def ouvrir(self) -> None:
        """Établit la connexion maître. Toute commande ultérieure la réutilise."""
        self._maitre = subprocess.Popen(
            [
                "ssh",
                "-M",
                "-N",
                "-o",
                f"ControlPath={self._socket}",
                "-o",
                "ControlPersist=no",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "ServerAliveInterval=15",
                self.hote,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        atexit.register(self.fermer)
        for _ in range(100):
            if os.path.exists(self._socket):
                return
            if self._maitre.poll() is not None:
                err = (self._maitre.stderr.read() or b"").decode(errors="replace")
                raise RuntimeError(f"connexion SSH impossible vers {self.hote}\n{err}")
            time.sleep(0.1)
        raise RuntimeError(f"délai dépassé à l'ouverture de la session vers {self.hote}")

    def fermer(self) -> None:
        if self._maitre and self._maitre.poll() is None:
            self._maitre.terminate()
            try:
                self._maitre.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._maitre.kill()
        self._maitre = None

    def __enter__(self) -> "Cible":
        self.ouvrir()
        return self

    def __exit__(self, *_) -> None:
        self.fermer()

    # -- commandes -----------------------------------------------------------

    def _script(self, commande: str, dans_repo: bool) -> str:
        """Compose le script distant.

        Le répertoire n'est pas passé à ``shlex.quote`` : un ``~`` quoté n'est
        plus développé par le shell distant, et le ``cd`` échouerait
        silencieusement en court-circuitant le reste de la commande.
        """
        repo = self.repo.replace("~", "$HOME", 1) if self.repo.startswith("~") else self.repo
        prefixe = 'export PATH="$HOME/.cargo/bin:$PATH"'
        if dans_repo:
            return f'{prefixe}; cd "{repo}" && {commande}'
        return f"{prefixe}; {commande}"

    def _argv(self, script: str) -> list[str]:
        """``ssh`` concatène ses arguments de commande avec des espaces avant de
        les confier au shell distant : le script doit donc voyager comme un
        argument unique et déjà quoté, sans quoi il est redécoupé en route."""
        return [
            "ssh",
            "-o",
            f"ControlPath={self._socket}",
            "-o",
            "BatchMode=yes",
            self.hote,
            f"bash -lc {shlex.quote(script)}",
        ]

    def executer(
        self, commande: str, *, dans_repo: bool = True, timeout: int = 1800
    ) -> Sortie:
        """Joue une commande shell sur la cible et capture sa sortie."""
        script = self._script(commande, dans_repo)
        if self.verbeux:
            detail(_c("2", f"$ {commande}"))
        try:
            proc = subprocess.run(
                self._argv(script),
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return Sortie(124, "", f"délai dépassé après {timeout}s")
        sortie = Sortie(proc.returncode, proc.stdout, proc.stderr)
        if self.verbeux and not sortie.ok:
            detail(_c("2", (sortie.stderr or sortie.stdout).strip()[:2000]))
        return sortie

    def deposer(self, contenu: str, chemin_distant: str) -> None:
        """Écrit un fichier sur la cible sans passer par un fichier local."""
        proc = subprocess.run(
            self._argv(f"cat > {shlex.quote(chemin_distant)}"),
            input=contenu,
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"écriture de {chemin_distant} impossible : {proc.stderr}")


# ── Registre de scénarios ───────────────────────────────────────────────────

CATEGORIES = ("preflight", "synchro", "unite", "build", "campagne", "pare-feu")

_REGISTRE: list[tuple[str, str, Callable]] = []


def scenario(nom: str, categorie: str):
    """Déclare un scénario. Il reçoit le contexte et renvoie ``(Etat, message)``."""

    def decorateur(fn):
        _REGISTRE.append((nom, categorie, fn))
        return fn

    return decorateur


@dataclass
class Contexte:
    cible: Cible
    branche: str
    prefixe_gestion: str
    pare_feu_autorise: bool
    forcer_synchro: bool = False
    # Rempli au fil de la campagne : les scénarios tardifs dépendent des clés
    # et du répertoire de travail créés par les précédents.
    tmp: str = ""
    client_priv: str = ""
    client_pub: str = ""
    gateway_priv: str = ""
    gateway_pub: str = ""
    keyring: str = ""
    faits: dict = field(default_factory=dict)


# ── Scénarios : preflight ───────────────────────────────────────────────────


@scenario("cible non-WSL2", "preflight")
def _preflight_pas_wsl(ctx: Contexte):
    s = ctx.cible.executer("grep -qi microsoft /proc/version && echo WSL || echo natif")
    if "natif" not in s.stdout:
        return Etat.ECHEC, "la cible est un WSL2 : aucun effet noyau réel n'y est prouvable"
    return Etat.OK, ""


@scenario("modules noyau wireguard et nf_tables", "preflight")
def _preflight_modules(ctx: Contexte):
    """Un module peut être intégré au noyau plutôt que chargeable : on constate
    donc sa disponibilité effective, pas le seul succès de ``modprobe``."""
    absents = []
    for module in ("wireguard", "nf_tables"):
        ctx.cible.executer(f"sudo -n modprobe {module} 2>/dev/null")
        charge = ctx.cible.executer(
            f"lsmod | grep -qE '^{module}' || test -d /sys/module/{module}"
        )
        if not charge.ok:
            absents.append(module)
    if absents:
        return Etat.ECHEC, f"modules indisponibles : {', '.join(absents)}"
    return Etat.OK, ""


@scenario("outils wg, nft, ip présents", "preflight")
def _preflight_outils(ctx: Contexte):
    manquants = []
    for outil in ("wg", "nft", "ip"):
        if not ctx.cible.executer(f"command -v {outil} >/dev/null").ok:
            manquants.append(outil)
    if manquants:
        return Etat.ECHEC, f"absents : {', '.join(manquants)} — jouer scripts/setup-dev.sh --target"
    return Etat.OK, ""


@scenario("TPM /dev/tpmrm0 accessible sans sudo", "preflight")
def _preflight_tpm(ctx: Contexte):
    if not ctx.cible.executer("test -c /dev/tpmrm0").ok:
        return Etat.HORS_PORTEE, "aucun /dev/tpmrm0 : la feature tpm ne sera pas exercée"
    if not ctx.cible.executer("test -r /dev/tpmrm0").ok:
        return Etat.ECHEC, "présent mais illisible — ajouter l'utilisateur au groupe tss"
    ctx.faits["tpm"] = True
    return Etat.OK, ""


@scenario("toolchain Rust et Node", "preflight")
def _preflight_toolchain(ctx: Contexte):
    rust = ctx.cible.executer("rustc --version")
    if not rust.ok:
        return Etat.ECHEC, "rustc absent — jouer scripts/setup-dev.sh --target"
    node = ctx.cible.executer("node --version")
    if not node.ok:
        return Etat.ECHEC, "node absent — jouer scripts/setup-dev.sh --target"
    majeur = int(node.stdout.strip().lstrip("v").split(".")[0])
    if majeur < 22:
        return Etat.ECHEC, f"Node {node.stdout.strip()} < 22 requis par les builds frontend"
    return Etat.OK, f"{rust.stdout.strip()}, node {node.stdout.strip()}"


@scenario("sudo non interactif sur les commandes d'essai", "preflight")
def _preflight_sudo(ctx: Contexte):
    """Sonde les commandes réellement nécessaires, une par une.

    Tester ``sudo -n true`` serait un contresens : la règle est délibérément
    scopée, donc ``true`` n'y figure pas et échouerait même une fois le
    provisionnement correct. Les sondes ci-dessous sont toutes en lecture ou
    idempotentes.
    """
    sondes = {
        "modprobe": "sudo -n modprobe wireguard",
        "nft": "sudo -n nft list tables",
        "ip": "sudo -n ip link show",
        "wg": "sudo -n wg show",
    }
    refusees = [nom for nom, cmd in sondes.items() if not ctx.cible.executer(cmd).ok]
    if refusees:
        return Etat.ECHEC, (
            f"sudo exige un mot de passe pour : {', '.join(refusees)} — "
            "provisionner avec --bootstrap"
        )
    # setcap ne se sonde pas sans l'appliquer : on lit la liste des droits.
    droits = ctx.cible.executer("sudo -n -l 2>/dev/null")
    if droits.ok and "setcap" not in droits.stdout:
        return Etat.ECHEC, "setcap absent de la règle NOPASSWD — relancer --bootstrap"
    return Etat.OK, ""


# ── Scénarios : synchronisation ─────────────────────────────────────────────


@scenario("dépôt cible synchronisé sur la branche d'essai", "synchro")
def _synchro_git(ctx: Contexte):
    s = ctx.cible.executer("git status --porcelain")
    if s.stdout.strip():
        # La synchronisation fait un reset --hard : refuser plutôt que de
        # détruire un correctif en cours sur la cible. Lister les fichiers
        # concernés, sans quoi l'utilisateur doit aller les chercher lui-même.
        fichiers = ", ".join(l.strip().split(maxsplit=1)[-1] for l in s.stdout.strip().splitlines())
        if not ctx.forcer_synchro:
            return Etat.ECHEC, (
                f"arbre de travail sale sur la cible ({fichiers}) : refus d'écraser. "
                "Committer, annuler, ou relancer avec --forcer-synchro."
            )
        detail(_c("33", f"--forcer-synchro : modifications écrasées ({fichiers})"))
    s = ctx.cible.executer(
        f"git fetch --quiet origin && git checkout --quiet {shlex.quote(ctx.branche)} && "
        f"git reset --hard --quiet origin/{shlex.quote(ctx.branche)} && git rev-parse HEAD"
    )
    if not s.ok:
        return Etat.ECHEC, f"synchronisation impossible : {(s.stderr or s.stdout).strip()}"
    ctx.faits["commit"] = s.stdout.strip()
    return Etat.OK, f"HEAD {s.stdout.strip()[:12]}"


# ── Scénarios : tests unitaires Rust ────────────────────────────────────────


@scenario("frontends construits (prérequis de --all-features)", "unite")
def _unite_frontends(ctx: Contexte):
    """Construit `web/dist` et `apps/orion/dist` s'ils manquent.

    Ce n'est pas une commodité, c'est un prérequis de compilation :
    `--all-features` active `embed-ui`, dont le `#[derive(RustEmbed)]` pointe
    sur `web/dist/`. Dossier absent, la macro ne génère pas `Assets::get` et
    `helios-api` ne compile pas — l'erreur ne dit rien du frontend manquant.
    Le crate `orion` a la même dépendance via `frontendDist` de Tauri.

    C'est la raison pour laquelle `scripts/regression.sh` construit les
    frontends avant clippy et les tests ; l'ordre est ici le même.
    """
    construits = []
    for app, dist in (("web", "web/dist"), ("apps/orion", "apps/orion/dist")):
        if ctx.cible.executer(f"test -d {dist}").ok:
            continue
        s = ctx.cible.executer(
            f"npm ci --prefix {app} && npm run build --prefix {app}", timeout=1800
        )
        if not s.ok:
            return Etat.ECHEC, f"{app} : {(s.stderr or s.stdout).strip()[-800:]}"
        construits.append(app)
    if not construits:
        return Etat.OK, "déjà présents"
    return Etat.OK, f"construits : {', '.join(construits)}"


@scenario("cargo fmt", "unite")
def _unite_fmt(ctx: Contexte):
    s = ctx.cible.executer("cargo fmt --check")
    return (Etat.OK, "") if s.ok else (Etat.ECHEC, s.stdout.strip()[:800])


@scenario("clippy, toutes features, sans avertissement", "unite")
def _unite_clippy(ctx: Contexte):
    s = ctx.cible.executer(
        "cargo clippy --workspace --all-targets --all-features -- -D warnings",
        timeout=3600,
    )
    return (Etat.OK, "") if s.ok else (Etat.ECHEC, s.stderr.strip()[-1500:])


@scenario("tests unitaires Rust, toutes features", "unite")
def _unite_tests(ctx: Contexte):
    """Les features noyau/TPM sont ici compilées **et** liées sur la cible :
    c'est ce que WSL2 ne peut pas faire. L'exécution réelle des effets reste
    l'affaire des catégories campagne et pare-feu."""
    s = ctx.cible.executer(
        "cargo test --workspace --all-features 2>&1", timeout=3600
    )
    # `Running unittests src/lib.rs (target/debug/deps/aether-1a2b)` précède le
    # `test result:` du même binaire : on apparie les deux pour nommer chaque
    # ligne de résultat, sinon le détail est une colonne de chiffres anonymes.
    details: list[str] = []
    binaire = "?"
    for ligne in s.stdout.splitlines():
        depouillee = ligne.strip()
        if depouillee.startswith(("Running ", "Doc-tests ")):
            binaire = depouillee.split("(")[-1].rstrip(")").split("/")[-1]
            # Le suffixe de hash change à chaque compilation : il n'apporte
            # rien à la lecture et fait diverger deux rapports identiques.
            binaire = re.sub(r"-[0-9a-f]{8,}$", "", binaire)
            if depouillee.startswith("Doc-tests"):
                binaire = f"doc:{depouillee.split()[-1]}"
        elif depouillee.startswith("test result:"):
            bilan = depouillee.removeprefix("test result:").strip()
            # « 0 measured; 0 filtered out » n'est jamais informatif ici.
            bilan = re.sub(r";\s*\d+ (measured|filtered out)", "", bilan)
            details.append(f"{binaire:<28} {bilan}")
        elif depouillee.startswith("---- ") and " stdout" in depouillee:
            details.append(f"ÉCHEC {depouillee}")
    if not s.ok:
        return Etat.ECHEC, s.stdout.strip()[-1500:], details
    resultats = [l for l in s.stdout.splitlines() if "test result:" in l]
    total = sum(int(l.split("test result:")[1].split()[1]) for l in resultats if "ok." in l)
    return Etat.OK, f"{total} tests sur {len(resultats)} binaires", details


# ── Scénarios : build matériel ──────────────────────────────────────────────


def _assurer_keyring(ctx: Contexte) -> str:
    """Garantit un trousseau éditeur d'essai, et renvoie son chemin.

    `aether/build.rs` refuse le trousseau de développement en profil release
    (invariant : une release ne se construit qu'avec une ancre éditeur
    explicite). **Toute** commande `cargo` en release doit donc porter
    `HELIOS_PUBLISHER_KEYRING_PATH`, pas seulement celle de `heliosd`.
    """
    if ctx.keyring:
        return ctx.keyring
    chemin = f"{ctx.tmp}/keys/publisher-keyring.json"
    if not ctx.cible.executer(f"test -f {shlex.quote(chemin)}").ok:
        s = ctx.cible.executer(
            f"cargo run --quiet -p helios-publisher -- keygen "
            f"--key-epoch 4294967295 --output-dir {shlex.quote(ctx.tmp)}/keys"
        )
        if not s.ok:
            raise RuntimeError(
                f"génération du trousseau impossible : {(s.stderr or s.stdout).strip()[-500:]}"
            )
    ctx.keyring = chemin
    return chemin


def _cargo_release(ctx: Contexte, arguments: str, timeout: int = 3600) -> Sortie:
    """Joue une commande cargo en release avec l'ancre éditeur.

    Centralisé parce que l'oublier ne produit pas une erreur parlante : le
    build script d'`aether` panique sur le trousseau de développement, et le
    message ne dit pas quelle commande a omis la variable.
    """
    keyring = _assurer_keyring(ctx)
    return ctx.cible.executer(
        f"HELIOS_PUBLISHER_KEYRING_PATH={shlex.quote(keyring)} {arguments}",
        timeout=timeout,
    )


@scenario("trousseau éditeur d'essai", "build")
def _build_keyring(ctx: Contexte):
    try:
        return Etat.OK, _assurer_keyring(ctx)
    except RuntimeError as exc:
        return Etat.ECHEC, str(exc)


@scenario("build release avec netlink, wireguard, tpm", "build")
def _build_release(ctx: Contexte):
    s = ctx.cible.executer("npm ci --prefix web && npm run build --prefix web", timeout=1800)
    if not s.ok:
        return Etat.ECHEC, f"frontend : {(s.stderr or s.stdout).strip()[-800:]}"
    s = _cargo_release(
        ctx, "cargo build --release -p heliosd --features netlink,wireguard,tpm,embed-ui"
    )
    if not s.ok:
        return Etat.ECHEC, s.stderr.strip()[-1500:]
    return Etat.OK, "target/release/heliosd"


@scenario("build helios-ctl", "build")
def _build_ctl(ctx: Contexte):
    s = _cargo_release(ctx, "cargo build --release -p helios-ctl", timeout=1800)
    return (Etat.OK, "") if s.ok else (Etat.ECHEC, s.stderr.strip()[-1000:])


@scenario("un Orion réel refuse de démarrer sans backend", "build")
def _build_orion(ctx: Contexte):
    """Invariant : compilé avec ``wireguard``, Orion ne retombe jamais sur le
    dry-run. On vérifie ici que la feature lie bien sur la cible ; le refus au
    démarrage est couvert par les tests unitaires d'orion-core."""
    s = _cargo_release(
        ctx, "cargo build --release -p orion-core --features wireguard", timeout=1800
    )
    return (Etat.OK, "") if s.ok else (Etat.ECHEC, s.stderr.strip()[-1000:])


# ── Scénarios : campagne de provisioning post-quantique ─────────────────────


def _generer_cles(ctx: Contexte) -> None:
    """Deux paires WireGuard jetables, jamais persistées hors du répertoire
    temporaire de la campagne."""
    if not ctx.cible.executer("test -x target/release/helios-ctl").ok:
        raise RuntimeError("target/release/helios-ctl absent : jouer la catégorie build")
    for role in ("client", "gateway"):
        s = ctx.cible.executer("./target/release/helios-ctl campaign --generate-keys 2>/dev/null")
        if not s.ok:
            raise RuntimeError(
                f"génération de clés {role} impossible (code {s.code}) : "
                f"{(s.stderr or s.stdout).strip()[-300:] or 'aucune sortie'}"
            )
        for ligne in s.stdout.splitlines():
            if ligne.startswith("WG_PRIVATE_KEY="):
                setattr(ctx, f"{role}_priv", ligne.split("=", 1)[1].strip())
            elif ligne.startswith("WG_PUBLIC_KEY="):
                setattr(ctx, f"{role}_pub", ligne.split("=", 1)[1].strip())
    for champ in ("client_priv", "client_pub", "gateway_priv", "gateway_pub"):
        if not getattr(ctx, champ):
            raise RuntimeError(f"clé {champ} non extraite")


def _assurer_cles(ctx: Contexte) -> None:
    """Génère les clés de campagne une seule fois, à la demande.

    Le premier scénario de la catégorie composait sa configuration avant que
    `_generer_cles` ait tourné : `wg_private_key` sortait vide et heliosd
    s'arrêtait sur « gateway non configurée », masquant ce qu'on voulait
    mesurer.
    """
    if not ctx.gateway_priv:
        _generer_cles(ctx)


def _config_reseau(ctx: Contexte, iface_wan: str) -> str:
    """Configuration isolée : jamais /var/lib/helios.

    ``allow_ssh_from`` est renseigné avec le préfixe de gestion — sans lui, le
    kill-switch réel coupe toute nouvelle connexion SSH vers la cible.

    Le pair de campagne est déclaré ``admin`` (ADR-003) : les routes de mutation
    exigent cette autorisation, résolue à partir de la VIP source. Sans elle, la
    campagne se verrait refuser en 403 les scénarios qui éprouvent justement ces
    routes. Un champ inconnu d'un binaire antérieur à l'ADR-003 est simplement
    ignoré à la désérialisation, la déclaration est donc rétrocompatible.
    """
    return f"""wan_iface = "{iface_wan}"
wg_iface = "helios-test0"
wg_private_key = "{ctx.gateway_priv}"
wg_address = "100.64.0.1/10"
wg_listen_port = 51821
admin_iface = "helios-test0"
allow_ssh_from = ["{ctx.prefixe_gestion}"]

[[peers]]
name = "campagne"
public_key = "{ctx.client_pub}"
address = "100.64.1.2/32"
admin = true
"""


@scenario("TPM enforce : refus de démarrer sans blob scellé", "campagne")
def _campagne_tpm_fail_closed(ctx: Contexte):
    """Vérifie le fail-closed TPM sur le matériel réel, sans rien y écrire.

    Compilé avec la feature `tpm`, `TpmSettings::default()` donne
    `enabled = true`, `enforce = true` et `allow_provisioning = false`. Sans
    blob dans `/var/lib/helios/sealed.key`, `BootController::unlock` renvoie
    `MissingBlobOnField` et le démarrage doit s'arrêter là — avant tout réseau.

    C'est le seul scénario TPM automatisable sans risque : il constate un refus,
    donc il ne scelle rien et ne touche pas au NV. Le rescellement et les
    billets restent dans la recette manuelle.
    """
    if not ctx.cible.executer("test -c /dev/tpmrm0").ok:
        return Etat.HORS_PORTEE, "aucun TPM sur cette cible"
    if ctx.cible.executer("test -f /var/lib/helios/sealed.key").ok:
        return Etat.HORS_PORTEE, "un blob scellé existe déjà : le refus n'est pas exerçable"

    # Reconstruire explicitement avec `tpm` : le scénario suivant produit un
    # binaire sans la feature, et le réutiliser ici ne prouverait rien.
    build = _cargo_release(
        ctx, "cargo build --release -p heliosd --features netlink,wireguard,tpm,embed-ui"
    )
    if not build.ok:
        return Etat.ECHEC, build.stderr.strip()[-800:]

    _assurer_cles(ctx)
    ctx.cible.deposer(_config_reseau(ctx, "lo"), f"{ctx.tmp}/network-tpm.toml")
    s = ctx.cible.executer(
        f"HELIOS_NETWORK_CONFIG={ctx.tmp}/network-tpm.toml "
        "timeout 30 ./target/release/heliosd run --dev 2>&1 || true"
    )
    journal = s.stdout + s.stderr
    if "déscellement TPM échoué" not in journal and "MissingBlob" not in journal:
        return Etat.ECHEC, (
            "heliosd n'a pas refusé de démarrer sur absence de blob scellé : "
            f"{journal.strip()[-600:]}"
        )
    return Etat.OK, "refus avant tout réseau"


@scenario("binaire de campagne sans tpm", "campagne")
def _campagne_binaire(ctx: Contexte):
    """Reconstruit heliosd avec les backends réseau réels mais sans `tpm`.

    Le scénario précédent vient d'établir qu'un binaire `tpm` refuse de démarrer
    tant qu'aucune identité n'est scellée. Provisionner ce scellement sur la
    machine ferait sortir la campagne de son périmètre — elle écrirait dans le
    TPM. On désactive donc la feature plutôt que de contourner l'invariant :
    `enabled` retombe à `false`, `BootDecision::Disabled`, et le plan de données
    reste pleinement réel (netlink et WireGuard noyau).
    """
    s = _cargo_release(
        ctx, "cargo build --release -p heliosd --features netlink,wireguard,embed-ui"
    )
    if not s.ok:
        return Etat.ECHEC, s.stderr.strip()[-1200:]
    return Etat.OK, "netlink + wireguard réels, tpm désactivé"


@scenario("catégorie client : validations hors daemon", "campagne")
def _campagne_client(ctx: Contexte):
    _assurer_cles(ctx)
    s = ctx.cible.executer(
        f"./target/release/helios-ctl campaign --only client "
        f"--client-key {shlex.quote(ctx.client_priv)} "
        f"--gateway-key {shlex.quote(ctx.gateway_pub)}"
    )
    if not s.ok:
        return Etat.ECHEC, (s.stdout + s.stderr).strip()[-1200:], _details_campagne(s.stdout)
    return Etat.OK, _resume_campagne(s.stdout), _details_campagne(s.stdout)


@scenario("catégorie protocole : tour ML-KEM complet", "campagne")
def _campagne_protocole(ctx: Contexte):
    """Monte un heliosd dry-run isolé et joue le tour complet client → HTTP →
    orchestrateur. Le dry-run suffit ici : c'est le protocole qui est en cause,
    pas le plan de données."""
    ctx.cible.deposer(_config_reseau(ctx, "lo"), f"{ctx.tmp}/network-dev.toml")
    journal_daemon = f"{ctx.tmp}/daemon-dev.log"
    pid = _lancer_daemon(
        ctx, {"config": "network-dev.toml", "mode": "run --dev"}, journal_daemon
    )
    try:
        if not _attendre_api(ctx, "http://127.0.0.1:8080", pid):
            journal = ctx.cible.executer(f"cat {journal_daemon}").stdout
            return Etat.ECHEC, f"le daemon n'a pas répondu :\n{journal.strip()[-1000:]}"
        if not _api_est_la_notre(ctx, "http://127.0.0.1:8080"):
            return Etat.ECHEC, "l'API répondante n'est pas celle du daemon lancé"
        s = ctx.cible.executer(
            f"./target/release/helios-ctl campaign --only protocole "
            f"--client-key {shlex.quote(ctx.client_priv)} "
            f"--gateway-key {shlex.quote(ctx.gateway_pub)}"
        )
        if not s.ok:
            return Etat.ECHEC, (s.stdout + s.stderr).strip()[-1200:], _details_campagne(s.stdout)
        # Invariant : aucun secret ne doit transiter par le journal.
        fuite = ctx.cible.executer(
            f"grep -qF {shlex.quote(ctx.client_priv)} {ctx.tmp}/daemon-dev.log"
        )
        if fuite.ok:
            return Etat.ECHEC, "une clé privée a été journalisée par le daemon"
        return Etat.OK, _resume_campagne(s.stdout), _details_campagne(s.stdout)
    finally:
        ctx.cible.executer(f"kill {pid} 2>/dev/null; true")
        _tuer_daemons(ctx)


@scenario("daemon réel : plan de données noyau monté", "campagne")
def _campagne_daemon_reel(ctx: Contexte):
    """Monte heliosd avec les backends noyau et constate leurs effets réels.

    C'est ce que le dry-run ne peut pas faire : `DryRunBackend` journalise un
    ruleset sans qu'aucun paquet ne soit filtré, et déclare une interface qui
    n'existe pas. On vérifie ici que le noyau a bien reçu les trois choses —
    table nft en `drop`, interface WireGuard adressée, pair déclaré.

    L'API n'est délibérément pas sollicitée : le ruleset refuse le port
    d'administration depuis toute interface autre que le tunnel, loopback
    compris (`ruleset.rs`, « en tête de chaîne, avant même le loopback »). La
    gateway ne joint donc pas sa propre API, et c'est l'invariant recherché.
    """
    if not ctx.pare_feu_autorise:
        return Etat.HORS_PORTEE, (
            "exige --pare-feu : monter le backend réel installe un ruleset "
            "fail-closed persistant sur la cible"
        )

    iface_wan = ctx.faits.get("iface_wan", "lo")
    ctx.cible.deposer(_config_reseau(ctx, iface_wan), f"{ctx.tmp}/network-reel.toml")
    # Chemins littéraux : ils doivent correspondre au mot pour mot à la règle
    # sudoers, qui n'accepte aucun joker (sudo-rs). `helios-ctl` en a besoin
    # autant que le daemon : c'est lui qui lit le plan de données via
    # `wg show`, refusé sans CAP_NET_ADMIN.
    for nom in ("heliosd", "helios-ctl"):
        binaire = f"{ctx.cible.repo}/target/release/{nom}"
        pose = ctx.cible.executer(
            f"sudo -n setcap cap_net_admin,cap_net_raw+eip {shlex.quote(binaire)}",
            dans_repo=False,
        )
        if not pose.ok:
            return Etat.ECHEC, (
                f"setcap refusé sur {binaire} : {(pose.stderr or pose.stdout).strip()[:300]} "
                "— relancer --bootstrap pour rafraîchir la règle sudoers"
            )

    journal_daemon = f"{ctx.tmp}/daemon-reel.log"
    pid = _lancer_daemon(ctx, {"config": "network-reel.toml", "mode": "run"}, journal_daemon)
    details: list[str] = []
    try:
        if not _attendre_interface(ctx, "helios-test0", pid):
            journal = ctx.cible.executer(f"cat {journal_daemon}").stdout
            return Etat.ECHEC, f"le daemon réel n'a pas monté l'interface :\n{journal.strip()[-1200:]}"

        adresse = ctx.cible.executer("ip -brief addr show helios-test0").stdout.strip()
        if "100.64.0.1" not in adresse:
            return Etat.ECHEC, f"interface sans adresse attendue : {adresse}"
        details.append(f"✓ interface WireGuard adressée        {adresse}")

        pairs = ctx.cible.executer("sudo -n wg show helios-test0 dump", dans_repo=False)
        if not pairs.ok:
            return Etat.ECHEC, f"wg show a échoué : {(pairs.stderr or pairs.stdout).strip()[:300]}"
        # La première ligne décrit l'interface, les suivantes les pairs.
        lignes_pairs = [l for l in pairs.stdout.strip().splitlines()[1:] if l.strip()]
        if not any(ctx.client_pub in l for l in lignes_pairs):
            return Etat.ECHEC, "le pair de campagne n'est pas déclaré dans le noyau"
        details.append(f"✓ pair déclaré dans le noyau          {len(lignes_pairs)} pair(s)")

        table = ctx.cible.executer("sudo -n nft list table inet helios", dans_repo=False)
        if not table.ok or "policy drop" not in table.stdout:
            return Etat.ECHEC, "la table nft n'est pas posée en politique drop"
        details.append(
            f"✓ table nft fail-closed posée         {table.stdout.count('policy drop')} chaînes en drop"
        )

        # Le PSK n'est pas encore négocié : le slot doit être vide à ce stade.
        # Le vérifier évite de confondre « pas de provisioning » et « PSK posé ».
        psk_vides = sum(1 for l in lignes_pairs if l.split("\t")[1:2] in ([""], ["(none)"]))
        details.append(f"— slot PSK vide avant provisioning    {psk_vides}/{len(lignes_pairs)}")
        return Etat.OK, "interface, pair et ruleset confirmés dans le noyau", details
    finally:
        ctx.cible.executer(f"kill {pid} 2>/dev/null; true")
        _tuer_daemons(ctx)


@scenario("PSK réellement posé dans le slot WireGuard", "campagne")
def _campagne_psk_plan_de_donnees(ctx: Contexte):
    """Limite connue : ce scénario exige un **second poste**.

    Le PSK n'arrive dans le slot qu'au terme d'un provisioning mené *par un
    client, à travers le tunnel* — c'est la recette en deux machines de
    docs/testing/TESTING.md. Or le ruleset refuse le port d'administration
    depuis toute interface autre que celle du tunnel, loopback compris : la
    gateway ne peut pas se provisionner elle-même, et c'est voulu.

    Le déclarer « hors portée » plutôt que de le faire échouer est délibéré :
    l'échec laisserait croire à une régression du PSK, alors que rien n'a été
    éprouvé. Ce qui débloquerait : un second hôte joignable, monté en client
    WireGuard, d'où jouer `helios-ctl --url http://100.64.0.1:8080 campaign`
    avant d'inspecter le slot depuis la gateway.
    """
    return Etat.HORS_PORTEE, (
        "exige un second poste client : la gateway ne joint pas sa propre API "
        "(port d'administration refusé hors interface de tunnel)"
    )


# ── Scénarios : pare-feu réel ───────────────────────────────────────────────


@scenario("ruleset fail-closed maintenu après l'arrêt du daemon", "pare-feu")
def _pare_feu_table(ctx: Contexte):
    """Vérifie l'invariant de persistance.

    Le daemon de la catégorie précédente est déjà arrêté quand ce scénario
    s'exécute : constater que la table est toujours là, et toujours en `drop`,
    c'est constater que `teardown()` ne la supprime jamais. Un kill-switch qui
    tomberait avec le processus ne serait pas un kill-switch.
    """
    if not ctx.pare_feu_autorise:
        return Etat.HORS_PORTEE, "exige --pare-feu"
    s = ctx.cible.executer("sudo -n nft list table inet helios", dans_repo=False)
    if not s.ok:
        return Etat.ECHEC, "aucune table inet helios : le backend Netlink n'a rien posé"
    chaines = s.stdout.count("policy drop")
    if chaines == 0:
        return Etat.ECHEC, "la table existe mais aucune chaîne n'est en politique drop"
    ctx.faits["table_posee"] = True
    return Etat.OK, f"{chaines} chaînes en drop, daemon arrêté"


@scenario("SSH de gestion préservé par allow_ssh_from", "pare-feu")
def _pare_feu_ssh(ctx: Contexte):
    """Vérification directe de l'invariant qui protège cette campagne
    elle-même : une **nouvelle** connexion SSH doit passer, hors session
    multiplexée."""
    if not ctx.pare_feu_autorise:
        return Etat.HORS_PORTEE, "exige --pare-feu"
    if not ctx.faits.get("table_posee"):
        # Sans ruleset engagé, rien ne bloque SSH : un succès ici ne
        # prouverait pas que `allow_ssh_from` protège quoi que ce soit.
        return Etat.HORS_PORTEE, "aucun ruleset engagé : la protection n'est pas exerçable"
    proc = subprocess.run(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ControlPath=none",
            ctx.cible.hote,
            "true",
        ],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return Etat.ECHEC, (
            "une nouvelle connexion SSH est refusée alors que allow_ssh_from "
            f"couvre {ctx.prefixe_gestion} — la session courante reste ouverte, "
            "purger avec : sudo nft delete table inet helios"
        )
    return Etat.OK, "nouvelle connexion acceptée"


@scenario("port d'administration refusé hors tunnel", "pare-feu")
def _pare_feu_admin(ctx: Contexte):
    """L'API ne doit être atteignable que par l'interface du tunnel.

    On lit la table effectivement posée dans le noyau plutôt que d'interroger
    l'API : la joindre est précisément ce que l'invariant interdit, et un
    `curl` qui échoue ne distingue pas « refusé » de « daemon arrêté ».

    L'ordre compte autant que la présence : l'acceptation scopée au tunnel doit
    précéder le refus général, sinon elle est morte.
    """
    if not ctx.pare_feu_autorise:
        return Etat.HORS_PORTEE, "exige --pare-feu"
    table = ctx.cible.executer("sudo -n nft list table inet helios", dans_repo=False)
    if not table.ok:
        return Etat.HORS_PORTEE, "aucune table posée à inspecter"

    entree = table.stdout.split("chain input")[1].split("}")[0]
    lignes = [l.strip() for l in entree.splitlines() if "8080" in l]
    accept = next((i for i, l in enumerate(lignes) if "helios-test0" in l and "accept" in l), None)
    drop = next((i for i, l in enumerate(lignes) if "drop" in l), None)
    if accept is None:
        return Etat.ECHEC, "aucune acceptation du port d'administration via le tunnel"
    if drop is None:
        return Etat.ECHEC, "le port d'administration n'est refusé nulle part ailleurs"
    if accept > drop:
        return Etat.ECHEC, "le refus général précède l'acceptation : l'API est injoignable partout"
    return Etat.OK, "accepté via helios-test0, refusé partout ailleurs"


@scenario("purge du ruleset d'essai", "pare-feu")
def _pare_feu_purge(ctx: Contexte):
    """Retire la table ``inet helios`` laissée par la campagne.

    L'invariant fail-closed veut que la table survive au daemon, et le scénario
    précédent vient de le vérifier. Mais la chaîne ``output`` est elle aussi en
    ``drop`` : tant que la table est en place, la cible n'a plus de trafic
    sortant — ni DNS, ni paquets, ni cargo. La laisser serait transformer une
    campagne d'essai en panne.

    La purge est donc délibérée et journalisée, jamais implicite. Elle s'exécute
    même si les scénarios précédents ont échoué, et même sans ``--pare-feu`` :
    une table oubliée par une exécution interrompue doit pouvoir être nettoyée.
    """
    if not ctx.cible.executer("sudo -n nft list table inet helios", dans_repo=False).ok:
        return Etat.HORS_PORTEE, "aucune table à purger"
    if not ctx.cible.executer("sudo -n nft delete table inet helios", dans_repo=False).ok:
        return Etat.ECHEC, (
            "purge impossible — la cible reste sans trafic sortant. Depuis la "
            "console : sudo nft delete table inet helios"
        )
    if ctx.cible.executer("sudo -n nft list table inet helios", dans_repo=False).ok:
        return Etat.ECHEC, "la table est toujours présente après suppression"
    # Constater le rétablissement plutôt que le supposer.
    sortant = ctx.cible.executer("curl -sf -m 8 -o /dev/null https://deb.nodesource.com")
    if not sortant.ok:
        return Etat.OK, "table retirée ; trafic sortant non reconfirmé (réseau externe)"
    return Etat.OK, "table retirée, trafic sortant rétabli"


# ── Utilitaires de scénario ─────────────────────────────────────────────────


def _tuer_daemons(ctx: Contexte) -> None:
    """Élimine tout heliosd résiduel.

    ``pkill -x`` compare le **nom** du processus : un ``pkill -f`` sur le chemin
    tuerait aussi la session SSH qui le lance, puisque le motif figure dans sa
    propre ligne de commande.
    """
    ctx.cible.executer("pkill -x heliosd; sleep 0.5; true", dans_repo=False)


def _lancer_daemon(ctx: Contexte, arguments: str, journal: str) -> str:
    """Lance heliosd en arrière-plan et renvoie son PID réel.

    Deux pièges, tous deux rencontrés :

    * ``cd X && cmd &`` fait porter le ``&`` sur le compound entier, donc
      ``$!`` renvoie le PID du sous-shell et non celui de heliosd — un ``kill``
      sur ce PID laisse le daemon orphelin, qui squatte le port de l'API pour
      les exécutions suivantes ;
    * ce même sous-shell garde le tube ssh ouvert, et ``subprocess`` bloque
      jusqu'à son timeout au lieu de rendre la main.

    D'où le ``;`` au lieu du ``&&``, et la redirection des trois descripteurs :
    le ``&`` ne porte plus que sur une commande simple, qui ne retient rien.
    """
    _tuer_daemons(ctx)
    if ctx.cible.executer("ss -lnt | grep -q ':8080 '", dans_repo=False).ok:
        raise RuntimeError("le port 8080 est déjà occupé : un daemon étranger écoute")
    # L'interface d'essai survit à un daemon tué brutalement et ferait échouer
    # la création suivante.
    ctx.cible.executer("sudo -n ip link delete helios-test0 2>/dev/null; true", dans_repo=False)
    repo = ctx.cible.repo
    lancement = (
        f'cd "{repo}"; HELIOS_NETWORK_CONFIG={ctx.tmp}/{arguments["config"]} '
        f'nohup ./target/release/heliosd {arguments["mode"]} '
        f"> {journal} 2>&1 </dev/null & echo $!"
    )
    pid = ctx.cible.executer(lancement, dans_repo=False).stdout.strip()
    if not pid.isdigit():
        raise RuntimeError(f"PID du daemon illisible : {pid!r}")
    return pid


def _attendre_api(ctx: Contexte, url: str, pid: str, essais: int = 60) -> bool:
    """Attend que l'API réponde plutôt que de dormir un délai arbitraire."""
    for _ in range(essais):
        if ctx.cible.executer(f"curl -sf -m 5 {url}/api/status >/dev/null").ok:
            return True
        if not ctx.cible.executer(f"kill -0 {pid} 2>/dev/null").ok:
            return False
        time.sleep(0.5)
    return False


def _attendre_interface(ctx: Contexte, iface: str, pid: str, essais: int = 60) -> bool:
    """Attend que l'interface WireGuard existe.

    En mode réel c'est le bon signal de démarrage : l'API, elle, est
    volontairement injoignable depuis la gateway.
    """
    for _ in range(essais):
        if ctx.cible.executer(f"ip link show {iface} >/dev/null 2>&1").ok:
            return True
        if not ctx.cible.executer(f"kill -0 {pid} 2>/dev/null").ok:
            return False
        time.sleep(0.5)
    return False


def _api_est_la_notre(ctx: Contexte, url: str) -> bool:
    """Vérifie que l'API interrogée est bien celle du daemon qu'on a lancé.

    Sans ce contrôle, un daemon résiduel qui détient déjà le port répond à la
    place du nôtre : l'attente réussit, les scénarios s'exécutent contre un
    inconnu, et le vert obtenu ne prouve rien. C'est arrivé.
    """
    s = ctx.cible.executer(f"curl -sf -m 5 {url}/api/network")
    if not s.ok:
        return False
    try:
        pairs = json.loads(s.stdout).get("peers", [])
    except json.JSONDecodeError:
        return False
    return any(p.get("public_key") == ctx.client_pub for p in pairs)


def _sans_ansi(texte: str) -> str:
    """Retire les séquences d'échappement ANSI d'une ligne."""
    return re.sub(r"\x1b\[[0-9;]*m", "", texte)


def _resume_campagne(sortie: str) -> str:
    """Extrait la ligne de synthèse de helios-ctl, sans les codes ANSI."""
    for ligne in reversed(sortie.strip().splitlines()):
        nettoyee = _sans_ansi(ligne).strip()
        if "scénario" in nettoyee:
            return nettoyee
    return ""


def _details_campagne(sortie: str) -> list[str]:
    """Remonte chaque sous-scénario joué par helios-ctl.

    Sans cela, six vérifications distinctes disparaissent derrière un unique
    « campagne réussie » : on sait que rien n'a cassé, pas ce qui a été
    éprouvé. Les en-têtes de catégorie sont conservés pour le regroupement.
    """
    lignes: list[str] = []
    for brute in sortie.splitlines():
        nettoyee = _sans_ansi(brute).rstrip()
        depouillee = nettoyee.strip()
        if not depouillee:
            continue
        if depouillee[0] in "✓✗—":
            lignes.append(depouillee)
        elif depouillee.endswith("─" * 3):
            # Ligne de soulignement : on garde l'intitulé qui la précède.
            continue
        elif nettoyee.startswith(("plan de données", "protocole", "client")):
            lignes.append(f"[{depouillee}]")
    return lignes


# ── Orchestration ───────────────────────────────────────────────────────────


def jouer(ctx: Contexte, categories: list[str]) -> list[Resultat]:
    resultats: list[Resultat] = []
    categorie_courante = ""
    for nom, categorie, fn in _REGISTRE:
        if categorie not in categories:
            continue
        if categorie != categorie_courante:
            info(categorie)
            categorie_courante = categorie
        debut = time.monotonic()
        details: list[str] = []
        try:
            # Un scénario renvoie (état, message) ou, s'il agrège des
            # sous-tests, (état, message, détails).
            issue = fn(ctx)
            if len(issue) == 3:
                etat, message, details = issue
            else:
                etat, message = issue
        except Exception as exc:  # un scénario qui explose est un échec, pas un crash
            etat, message = Etat.ECHEC, f"{type(exc).__name__}: {exc}"
        duree = time.monotonic() - debut
        resultats.append(Resultat(nom, categorie, etat, message, duree, details))
        marque = {
            Etat.OK: _c("32", "✓"),
            Etat.ECHEC: _c("31", "✗"),
            Etat.HORS_PORTEE: _c("33", "—"),
        }[etat]
        suffixe = f"  {_c('2', message)}" if message and etat is not Etat.ECHEC else ""
        print(f"  {marque} {nom:<52} {duree:6.1f}s{suffixe}", flush=True)
        for ligne in details:
            if ligne.startswith("["):
                print(f"      {_c('1', ligne.strip('[]'))}", flush=True)
            elif ligne.startswith("✗") or ligne.startswith("ÉCHEC"):
                print(f"        {_c('31', ligne)}", flush=True)
            elif ligne.startswith("—"):
                print(f"        {_c('33', ligne)}", flush=True)
            elif ligne.startswith("✓"):
                print(f"        {_c('32', ligne)}", flush=True)
            else:
                print(f"        {_c('2', ligne)}", flush=True)
        if etat is Etat.ECHEC and message:
            for ligne in message.strip().splitlines():
                print(f"      {_c('31', ligne)}", flush=True)
    return resultats


def rapporter(resultats: list[Resultat]) -> int:
    ok = sum(1 for r in resultats if r.etat is Etat.OK)
    echecs = [r for r in resultats if r.etat is Etat.ECHEC]
    hors = sum(1 for r in resultats if r.etat is Etat.HORS_PORTEE)
    print()
    if echecs:
        info(_c("31", f"{len(echecs)} échec(s) sur {len(resultats)} scénario(s)"))
        for r in echecs:
            detail(f"{_c('31', '✗')} [{r.categorie}] {r.nom}")
    else:
        info(_c("32", f"campagne réussie — {ok} scénario(s)"))
    if hors:
        detail(f"{hors} scénario(s) hors portée dans cet environnement")
    return 1 if echecs else 0


AIDE_SUDOERS = """\
Le provisionnement est automatisé — rien de tout ceci n'est à recopier :

    python3 scripts/target_campaign.py --bootstrap

Cette commande résout le dépôt et l'utilisateur sur la cible, compose la règle
ci-dessous, la fait valider par visudo *avant* installation, puis l'installe et
ajoute l'utilisateur au groupe tss. Un seul mot de passe sudo est demandé.

Seules les dépendances système restent à poser une fois, sur la cible :

    ssh -t christophe@192.168.1.44 'cd ~/helios && bash scripts/setup-dev.sh --target'

Règle générée pour cette cible, donnée à titre de contrôle :

{regle}
Notes de portabilité, constatées sur Ubuntu 26.04 (sudo-rs, pas le sudo
classique) : aucun joker n'est accepté dans les arguments, d'où les deux
variantes littérales de setcap ; et la virgule des capacités est échappée,
faute de quoi elle serait lue comme le séparateur de la liste de commandes.
"""


SUDOERS_CHEMIN = "/etc/sudoers.d/helios-target-tests"


def _regle_sudoers(utilisateur: str, repo: str) -> str:
    """Compose la règle NOPASSWD, strictement scopée aux essais.

    Trois contraintes dictent cette forme, toutes constatées sur Ubuntu 26.04
    qui embarque sudo-rs et non le sudo classique :

    * aucun joker n'est accepté dans les arguments, donc chaque invocation de
      ``setcap`` est écrite littéralement — d'où les deux variantes de syntaxe
      de capacités, ``+eip`` et ``=ep`` ;
    * la virgule qui sépare les capacités doit être échappée, sinon elle est
      lue comme le séparateur de la liste de commandes ;
    * le chemin du binaire est absolu et littéral : il doit correspondre au mot
      près à celui que la campagne passera à ``setcap``.

    Ni shell générique, ni ``apt-get``, ni root inconditionnel n'y figurent.
    """
    binaires = [f"{repo}/target/release/heliosd", f"{repo}/target/release/helios-ctl"]
    commandes = [
        "/usr/sbin/modprobe wireguard",
        "/usr/sbin/modprobe nf_tables",
        "/usr/sbin/nft",
        "/usr/sbin/ip",
        "/usr/bin/wg",
    ]
    # `helios-ctl` interroge le plan de données via `wg show` : sans
    # CAP_NET_ADMIN il obtient « Operation not permitted » et le scénario
    # plan-de-donnees échoue sans rien prouver.
    for binaire in binaires:
        commandes.append(rf"/usr/sbin/setcap cap_net_admin\,cap_net_raw+eip {binaire}")
        commandes.append(rf"/usr/sbin/setcap cap_net_admin\,cap_net_raw=ep {binaire}")
    return f"{utilisateur} ALL=(root) NOPASSWD: {', '.join(commandes)}\n"


def bootstrap(hote: str, repo: str, verbeux: bool) -> int:
    """Provisionne la cible : règle sudoers et accès TPM, en un seul mot de passe.

    Le fichier est **validé avant** d'être installé : ``visudo -c`` ne demande
    aucun privilège sur un fichier temporaire, et un sudoers invalide déposé
    dans ``/etc/sudoers.d`` casserait sudo pour toute la machine.
    """
    with Cible(hote, repo, verbeux) as cible:
        chemin_repo = cible.resoudre_repo()
        utilisateur = cible.executer("id -un", dans_repo=False).stdout.strip()
        detail(f"utilisateur {utilisateur}, dépôt {chemin_repo}")

        regle = _regle_sudoers(utilisateur, chemin_repo)
        temporaire = "/tmp/helios-target-tests.sudoers"
        cible.deposer(regle, temporaire)

        info("validation de la règle avant installation")
        verif = cible.executer(f"visudo -c -f {temporaire}", dans_repo=False)
        if not verif.ok:
            detail(_c("31", (verif.stderr or verif.stdout).strip()))
            cible.executer(f"rm -f {temporaire}", dans_repo=False)
            return 1
        detail(_c("32", verif.stdout.strip() or "syntaxe correcte"))

        deja = cible.executer(
            f"sudo -n -l 2>/dev/null | grep -q setcap", dans_repo=False
        ).ok
        if deja:
            info("règle déjà active ; réinstallation pour rafraîchir les chemins")

        # Seule étape privilégiée, et donc seul mot de passe demandé. Elle
        # exige un TTY : d'où le ssh -t dédié, hors session multiplexée.
        script = (
            f"sudo install -m 0440 -o root -g root {temporaire} {SUDOERS_CHEMIN} && "
            f"sudo usermod -aG tss {shlex.quote(utilisateur)} && "
            f"rm -f {temporaire} && echo PROVISIONNEMENT-OK"
        )
        info("installation (mot de passe sudo demandé une fois)")
        proc = subprocess.run(
            ["ssh", "-t", "-o", "BatchMode=no", hote, f"bash -lc {shlex.quote(script)}"]
        )
        if proc.returncode != 0:
            detail(_c("31", "installation interrompue ou refusée"))
            return 1

    # Session neuve : la règle et l'appartenance au groupe tss ne prennent
    # effet que hors de la connexion qui les a posées.
    info("vérification sur une session neuve")
    with Cible(hote, repo, verbeux) as cible:
        cible.resoudre_repo()
        ctx = Contexte(cible=cible, branche="", prefixe_gestion="", pare_feu_autorise=False)
        etat, message = _preflight_sudo(ctx)
        if etat is not Etat.OK:
            detail(_c("31", message))
            return 1
        detail(_c("32", "sudo non interactif opérationnel"))
        if not cible.executer("test -r /dev/tpmrm0").ok:
            detail(
                _c("33", "/dev/tpmrm0 encore illisible : le groupe tss prend effet")
            )
            detail(_c("33", "à la prochaine ouverture de session sur la cible."))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        description="Campagne d'essais matériels Helios sur cible distante.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--host", default="helios-target", help="cible SSH (défaut : helios-target)")
    p.add_argument("--repo", default="~/helios", help="dépôt sur la cible")
    p.add_argument("--branche", default="client-app", help="branche à synchroniser")
    p.add_argument(
        "--only",
        action="append",
        choices=CATEGORIES,
        help="restreindre à une catégorie (répétable)",
    )
    p.add_argument(
        "--pare-feu",
        action="store_true",
        help="autorise les scénarios qui posent un ruleset fail-closed réel "
        "et montent le backend WireGuard noyau",
    )
    p.add_argument(
        "--forcer-synchro",
        action="store_true",
        help="écrase les modifications non commitées de l'arbre de travail de la cible",
    )
    p.add_argument(
        "--prefixe-gestion",
        default="192.168.1.0/24",
        help="CIDR à inscrire dans allow_ssh_from pour préserver l'accès SSH",
    )
    p.add_argument("--json", metavar="FICHIER", help="écrit le rapport structuré")
    p.add_argument("-v", "--verbose", action="store_true", help="trace les commandes distantes")
    p.add_argument(
        "--bootstrap",
        action="store_true",
        help="provisionne la cible : règle sudoers scopée et accès TPM "
        "(un seul mot de passe, exige un terminal)",
    )
    p.add_argument("--aide-sudoers", action="store_true", help="affiche la règle sudoers générée")
    args = p.parse_args()

    if args.aide_sudoers:
        with Cible(args.host, args.repo, args.verbose) as cible:
            regle = _regle_sudoers(
                cible.executer("id -un", dans_repo=False).stdout.strip(),
                cible.resoudre_repo(),
            )
        print(AIDE_SUDOERS.format(regle=regle))
        return 0

    if args.bootstrap:
        info(f"provisionnement de {args.host}")
        return bootstrap(args.host, args.repo, args.verbose)

    categories = args.only or list(CATEGORIES)
    if args.pare_feu:
        print(
            _c(
                "33",
                "Attention : --pare-feu installe une table nft fail-closed qui "
                "survit à l'arrêt du daemon.\n"
                "En cas de perte d'accès : sudo nft delete table inet helios "
                "depuis la console.\n",
            )
        )

    info(f"cible {args.host}, branche {args.branche}")
    with Cible(args.host, args.repo, args.verbose) as cible:
        detail(f"dépôt {cible.resoudre_repo()}")
        tmp = cible.executer("mktemp -d -t helios-campagne-XXXXXX", dans_repo=False).stdout.strip()
        ctx = Contexte(
            cible=cible,
            branche=args.branche,
            prefixe_gestion=args.prefixe_gestion,
            pare_feu_autorise=args.pare_feu,
            forcer_synchro=args.forcer_synchro,
            tmp=tmp,
        )
        # Interface portant la route par défaut : c'est le wan_iface réaliste.
        route = cible.executer("ip route show default | awk '{print $5}' | head -1")
        ctx.faits["iface_wan"] = route.stdout.strip() or "lo"

        try:
            resultats = jouer(ctx, categories)
        finally:
            # Les clés jetables et la config ne survivent pas à la campagne.
            cible.executer(f"rm -rf {shlex.quote(tmp)}", dans_repo=False)

        if args.json:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "hote": args.host,
                        "branche": args.branche,
                        "commit": ctx.faits.get("commit"),
                        "scenarios": [
                            {
                                "nom": r.nom,
                                "categorie": r.categorie,
                                "etat": r.etat.value,
                                "message": r.message,
                                "duree_s": round(r.duree_s, 2),
                                "details": r.details,
                            }
                            for r in resultats
                        ],
                    },
                    f,
                    ensure_ascii=False,
                    indent=2,
                )
            detail(f"rapport écrit dans {args.json}")

        return rapporter(resultats)


if __name__ == "__main__":
    sys.exit(main())
