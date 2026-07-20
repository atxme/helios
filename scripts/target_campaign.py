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
    if not ctx.cible.executer("sudo -n true").ok:
        return Etat.ECHEC, (
            "sudo exige un mot de passe : installer la règle NOPASSWD scopée "
            "(voir --aide-sudoers)"
        )
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
        return Etat.ECHEC, (
            f"arbre de travail sale sur la cible ({fichiers}) : refus d'écraser. "
            "Committer ou annuler ces modifications avant de relancer."
        )
    s = ctx.cible.executer(
        f"git fetch --quiet origin && git checkout --quiet {shlex.quote(ctx.branche)} && "
        f"git reset --hard --quiet origin/{shlex.quote(ctx.branche)} && git rev-parse HEAD"
    )
    if not s.ok:
        return Etat.ECHEC, f"synchronisation impossible : {(s.stderr or s.stdout).strip()}"
    ctx.faits["commit"] = s.stdout.strip()
    return Etat.OK, f"HEAD {s.stdout.strip()[:12]}"


# ── Scénarios : tests unitaires Rust ────────────────────────────────────────


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
    s = ctx.cible.executer("cargo test --workspace --all-features", timeout=3600)
    if not s.ok:
        return Etat.ECHEC, s.stdout.strip()[-1500:] or s.stderr.strip()[-1500:]
    lignes = [l for l in s.stdout.splitlines() if "test result:" in l]
    total = sum(int(l.split("test result:")[1].split()[1]) for l in lignes if "ok." in l)
    return Etat.OK, f"{total} tests sur {len(lignes)} binaires"


# ── Scénarios : build matériel ──────────────────────────────────────────────


@scenario("trousseau éditeur d'essai", "build")
def _build_keyring(ctx: Contexte):
    ctx.keyring = f"{ctx.tmp}/keys/publisher-keyring.json"
    s = ctx.cible.executer(
        f"cargo run --quiet -p helios-publisher -- keygen "
        f"--key-epoch 4294967295 --output-dir {shlex.quote(ctx.tmp)}/keys"
    )
    if not s.ok:
        return Etat.ECHEC, (s.stderr or s.stdout).strip()[-800:]
    return Etat.OK, ""


@scenario("build release avec netlink, wireguard, tpm", "build")
def _build_release(ctx: Contexte):
    s = ctx.cible.executer("npm ci --prefix web && npm run build --prefix web", timeout=1800)
    if not s.ok:
        return Etat.ECHEC, f"frontend : {(s.stderr or s.stdout).strip()[-800:]}"
    s = ctx.cible.executer(
        f"HELIOS_PUBLISHER_KEYRING_PATH={shlex.quote(ctx.keyring)} "
        "cargo build --release -p heliosd --features netlink,wireguard,tpm,embed-ui",
        timeout=3600,
    )
    if not s.ok:
        return Etat.ECHEC, s.stderr.strip()[-1500:]
    return Etat.OK, "target/release/heliosd"


@scenario("build helios-ctl", "build")
def _build_ctl(ctx: Contexte):
    s = ctx.cible.executer("cargo build --release -p helios-ctl", timeout=1800)
    return (Etat.OK, "") if s.ok else (Etat.ECHEC, s.stderr.strip()[-1000:])


@scenario("un Orion réel refuse de démarrer sans backend", "build")
def _build_orion(ctx: Contexte):
    """Invariant : compilé avec ``wireguard``, Orion ne retombe jamais sur le
    dry-run. On vérifie ici que la feature lie bien sur la cible ; le refus au
    démarrage est couvert par les tests unitaires d'orion-core."""
    s = ctx.cible.executer("cargo build --release -p orion-core --features wireguard", timeout=1800)
    return (Etat.OK, "") if s.ok else (Etat.ECHEC, s.stderr.strip()[-1000:])


# ── Scénarios : campagne de provisioning post-quantique ─────────────────────


def _generer_cles(ctx: Contexte) -> None:
    """Deux paires WireGuard jetables, jamais persistées hors du répertoire
    temporaire de la campagne."""
    for role in ("client", "gateway"):
        s = ctx.cible.executer(
            f"./target/release/helios-ctl campaign --generate-keys 2>/dev/null"
        )
        if not s.ok:
            raise RuntimeError(f"génération de clés {role} impossible : {s.stderr}")
        for ligne in s.stdout.splitlines():
            if ligne.startswith("WG_PRIVATE_KEY="):
                setattr(ctx, f"{role}_priv", ligne.split("=", 1)[1].strip())
            elif ligne.startswith("WG_PUBLIC_KEY="):
                setattr(ctx, f"{role}_pub", ligne.split("=", 1)[1].strip())
    for champ in ("client_priv", "client_pub", "gateway_priv", "gateway_pub"):
        if not getattr(ctx, champ):
            raise RuntimeError(f"clé {champ} non extraite")


def _config_reseau(ctx: Contexte, iface_wan: str) -> str:
    """Configuration isolée : jamais /var/lib/helios. ``allow_ssh_from`` est
    renseigné avec le préfixe de gestion — sans lui, le kill-switch réel coupe
    toute nouvelle connexion SSH vers la cible."""
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
"""


@scenario("catégorie client : validations hors daemon", "campagne")
def _campagne_client(ctx: Contexte):
    _generer_cles(ctx)
    s = ctx.cible.executer(
        f"./target/release/helios-ctl campaign --only client "
        f"--client-key {shlex.quote(ctx.client_priv)} "
        f"--gateway-key {shlex.quote(ctx.gateway_pub)}"
    )
    if not s.ok:
        return Etat.ECHEC, (s.stdout + s.stderr).strip()[-1200:]
    return Etat.OK, _resume_campagne(s.stdout)


@scenario("catégorie protocole : tour ML-KEM complet", "campagne")
def _campagne_protocole(ctx: Contexte):
    """Monte un heliosd dry-run isolé et joue le tour complet client → HTTP →
    orchestrateur. Le dry-run suffit ici : c'est le protocole qui est en cause,
    pas le plan de données."""
    ctx.cible.deposer(_config_reseau(ctx, "lo"), f"{ctx.tmp}/network-dev.toml")
    lancement = (
        f"HELIOS_NETWORK_CONFIG={ctx.tmp}/network-dev.toml "
        f"nohup ./target/release/heliosd run --dev "
        f"> {ctx.tmp}/daemon-dev.log 2>&1 & echo $!"
    )
    s = ctx.cible.executer(lancement)
    pid = s.stdout.strip()
    try:
        if not _attendre_api(ctx, "http://127.0.0.1:8080", pid, f"{ctx.tmp}/daemon-dev.log"):
            journal = ctx.cible.executer(f"cat {ctx.tmp}/daemon-dev.log").stdout
            return Etat.ECHEC, f"le daemon n'a pas répondu :\n{journal.strip()[-1000:]}"
        s = ctx.cible.executer(
            f"./target/release/helios-ctl campaign --only protocole "
            f"--client-key {shlex.quote(ctx.client_priv)} "
            f"--gateway-key {shlex.quote(ctx.gateway_pub)}"
        )
        if not s.ok:
            return Etat.ECHEC, (s.stdout + s.stderr).strip()[-1200:]
        # Invariant : aucun secret ne doit transiter par le journal.
        fuite = ctx.cible.executer(
            f"grep -qF {shlex.quote(ctx.client_priv)} {ctx.tmp}/daemon-dev.log"
        )
        if fuite.ok:
            return Etat.ECHEC, "une clé privée a été journalisée par le daemon"
        return Etat.OK, _resume_campagne(s.stdout)
    finally:
        ctx.cible.executer(f"kill {pid} 2>/dev/null; true")


@scenario("catégorie plan-de-donnees : PSK réellement posé", "campagne")
def _campagne_plan_de_donnees(ctx: Contexte):
    """Le seul scénario que le dry-run ne peut pas jouer : il lit l'état noyau
    via ``wg show`` et vérifie que le slot PSK est renseigné des deux côtés,
    après qu'un handshake a survécu à sa pose."""
    if not ctx.pare_feu_autorise:
        return Etat.HORS_PORTEE, (
            "exige --pare-feu : monter le backend réel installe un ruleset "
            "fail-closed persistant sur la cible"
        )

    iface_wan = ctx.faits.get("iface_wan", "lo")
    ctx.cible.deposer(_config_reseau(ctx, iface_wan), f"{ctx.tmp}/network-reel.toml")
    # Chemin littéral : il doit correspondre au mot pour mot à la règle
    # sudoers, qui n'accepte aucun joker (sudo-rs).
    binaire = f"{ctx.cible.repo}/target/release/heliosd"
    pose = ctx.cible.executer(
        f"sudo -n setcap cap_net_admin,cap_net_raw+eip {shlex.quote(binaire)}",
        dans_repo=False,
    )
    if not pose.ok:
        return Etat.ECHEC, (
            f"setcap refusé sur {binaire} : {(pose.stderr or pose.stdout).strip()[:300]} "
            "— vérifier que la règle sudoers vise ce chemin exact (--aide-sudoers)"
        )
    lancement = (
        f"HELIOS_NETWORK_CONFIG={ctx.tmp}/network-reel.toml "
        f"nohup ./target/release/heliosd run "
        f"> {ctx.tmp}/daemon-reel.log 2>&1 & echo $!"
    )
    pid = ctx.cible.executer(lancement).stdout.strip()
    try:
        if not _attendre_api(ctx, "http://127.0.0.1:8080", pid, f"{ctx.tmp}/daemon-reel.log"):
            journal = ctx.cible.executer(f"cat {ctx.tmp}/daemon-reel.log").stdout
            return Etat.ECHEC, f"le daemon réel n'a pas démarré :\n{journal.strip()[-1200:]}"
        s = ctx.cible.executer(
            f"./target/release/helios-ctl campaign --only plan-de-donnees "
            f"--wg-iface helios-test0 "
            f"--client-key {shlex.quote(ctx.client_priv)} "
            f"--gateway-key {shlex.quote(ctx.gateway_pub)}",
            timeout=300,
        )
        if not s.ok:
            return Etat.ECHEC, (s.stdout + s.stderr).strip()[-1200:]
        return Etat.OK, _resume_campagne(s.stdout)
    finally:
        ctx.cible.executer(f"kill {pid} 2>/dev/null; true")


# ── Scénarios : pare-feu réel ───────────────────────────────────────────────


@scenario("table inet helios présente et fail-closed", "pare-feu")
def _pare_feu_table(ctx: Contexte):
    if not ctx.pare_feu_autorise:
        return Etat.HORS_PORTEE, "exige --pare-feu"
    s = ctx.cible.executer("sudo -n nft list table inet helios", dans_repo=False)
    if not s.ok:
        return Etat.ECHEC, "aucune table inet helios : le backend Netlink n'a rien posé"
    if "policy drop" not in s.stdout:
        return Etat.ECHEC, "la table existe mais aucune chaîne n'est en politique drop"
    return Etat.OK, f"{s.stdout.count('policy drop')} chaînes en drop"


@scenario("SSH de gestion préservé par allow_ssh_from", "pare-feu")
def _pare_feu_ssh(ctx: Contexte):
    """Vérification directe de l'invariant qui protège cette campagne
    elle-même : une **nouvelle** connexion SSH doit passer, hors session
    multiplexée."""
    if not ctx.pare_feu_autorise:
        return Etat.HORS_PORTEE, "exige --pare-feu"
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


@scenario("aucun secret exposé par GET /api/network", "pare-feu")
def _pare_feu_api(ctx: Contexte):
    if not ctx.pare_feu_autorise:
        return Etat.HORS_PORTEE, "exige --pare-feu"
    s = ctx.cible.executer("curl -sf http://127.0.0.1:8080/api/network || true")
    corps = s.stdout
    if not corps.strip():
        return Etat.HORS_PORTEE, "aucun daemon en écoute à ce stade"
    for secret in (ctx.gateway_priv, ctx.client_priv):
        if secret and secret in corps:
            return Etat.ECHEC, "une clé privée est sérialisée par l'API"
    if "preshared" in corps.lower() or "private" in corps.lower():
        return Etat.ECHEC, f"champ suspect dans la réponse : {corps[:300]}"
    return Etat.OK, ""


# ── Utilitaires de scénario ─────────────────────────────────────────────────


def _attendre_api(ctx: Contexte, url: str, pid: str, journal: str, essais: int = 60) -> bool:
    """Attend que l'API réponde plutôt que de dormir un délai arbitraire."""
    for _ in range(essais):
        if ctx.cible.executer(f"curl -sf {url}/api/status >/dev/null").ok:
            return True
        if not ctx.cible.executer(f"kill -0 {pid} 2>/dev/null").ok:
            return False
        time.sleep(0.5)
    return False


def _resume_campagne(sortie: str) -> str:
    """Extrait la ligne de synthèse de helios-ctl, sans les codes ANSI."""
    for ligne in reversed(sortie.strip().splitlines()):
        nettoyee = "".join(
            c for c in ligne if c.isprintable()
        ).replace("\x1b", "")
        if "scénario" in nettoyee:
            return nettoyee.strip()
    return ""


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
        try:
            etat, message = fn(ctx)
        except Exception as exc:  # un scénario qui explose est un échec, pas un crash
            etat, message = Etat.ECHEC, f"{type(exc).__name__}: {exc}"
        duree = time.monotonic() - debut
        resultats.append(Resultat(nom, categorie, etat, message, duree))
        marque = {
            Etat.OK: _c("32", "✓"),
            Etat.ECHEC: _c("31", "✗"),
            Etat.HORS_PORTEE: _c("33", "—"),
        }[etat]
        suffixe = f"  {_c('2', message)}" if message and etat is not Etat.ECHEC else ""
        print(f"  {marque} {nom:<52} {duree:6.1f}s{suffixe}", flush=True)
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
Provisionnement ponctuel de la cible. Ces étapes exigent un mot de passe sudo :
les jouer depuis un vrai terminal, avec un TTY (l'option -t de ssh).

    ssh -t christophe@192.168.1.44

Puis, sur la cible :

    cd ~/helios
    git fetch origin && git checkout client-app

    # 1. dépendances noyau/TPM/WireGuard, toolchain et Node >= 22
    bash scripts/setup-dev.sh --target

    # 2. accès TPM sans sudo (prend effet à la session suivante)
    sudo usermod -aG tss "$USER"

    # 3. règle sudoers strictement scopée : ni shell générique, ni apt-get,
    #    ni root inconditionnel — uniquement les commandes des essais.
    #
    #    Deux contraintes d'Ubuntu 26.04, qui embarque sudo-rs et non le sudo
    #    classique : aucun joker n'est accepté dans les arguments (l'appel
    #    setcap est donc écrit littéralement), et la virgule de la liste de
    #    capacités doit être échappée, sinon elle est lue comme le séparateur
    #    de commandes. Le heredoc est quoté pour que le shell n'y touche pas :
    #    adapter les chemins à la main si l'utilisateur n'est pas christophe.
    #    La règle tient sur une seule ligne : ni indentation ni continuation à
    #    recoller, donc rien qui puisse casser à la copie.
    sudo tee /etc/sudoers.d/helios-target-tests >/dev/null <<'EOF'
christophe ALL=(root) NOPASSWD: /usr/sbin/modprobe wireguard, /usr/sbin/modprobe nf_tables, /usr/sbin/nft, /usr/sbin/ip, /usr/bin/wg, /usr/sbin/setcap cap_net_admin\\,cap_net_raw+eip /home/christophe/helios/target/release/heliosd
EOF
    sudo chmod 0440 /etc/sudoers.d/helios-target-tests
    visudo -c -f /etc/sudoers.d/helios-target-tests

Refermer la session, puis vérifier depuis la machine de dev :

    python3 scripts/target_campaign.py --only preflight
"""


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
        "--prefixe-gestion",
        default="192.168.1.0/24",
        help="CIDR à inscrire dans allow_ssh_from pour préserver l'accès SSH",
    )
    p.add_argument("--json", metavar="FICHIER", help="écrit le rapport structuré")
    p.add_argument("-v", "--verbose", action="store_true", help="trace les commandes distantes")
    p.add_argument("--aide-sudoers", action="store_true", help="affiche la configuration sudoers")
    args = p.parse_args()

    if args.aide_sudoers:
        print(AIDE_SUDOERS)
        return 0

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
