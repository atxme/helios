#!/usr/bin/env python3
"""Campagne d'installation par bundle signé (ADR-004, lot 2).

Ce que cette campagne prouve, et que les tests unitaires ne prouvent pas : le
chemin passe par le trousseau éditeur **réellement compilé** dans
`helios-installer`, pas par un trousseau injecté. Une régression du build (ancre
absente, époque incohérente, encodage canonique modifié) se voit ici.

Le répertoire d'installation est un faux système jetable : rien n'est écrit
hors du répertoire temporaire de la campagne.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys

BINAIRES = ("heliosd", "helios-installer", "helios-ctl")
UNITES = (
    "heliosd.service",
    "helios-update.service",
    "helios-update.path",
    "helios-log-prune.service",
    "helios-log-prune.timer",
)
SEQUENCE = 9002


class Echec(RuntimeError):
    """Un scénario de campagne n'a pas produit le résultat attendu."""


def executer(commande: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        commande,
        capture_output=True,
        text=True,
        env={**os.environ, **(env or {})},
        check=False,
    )


def exiger_succes(resultat: subprocess.CompletedProcess, quoi: str) -> str:
    if resultat.returncode != 0:
        raise Echec(f"{quoi} a échoué :\n{resultat.stdout}\n{resultat.stderr}")
    return resultat.stdout


def exiger_refus(resultat: subprocess.CompletedProcess, quoi: str, motif: str) -> None:
    if resultat.returncode == 0:
        raise Echec(f"{quoi} aurait dû être refusé, or la commande a réussi")
    sortie = resultat.stdout + resultat.stderr
    if motif not in sortie:
        raise Echec(f"{quoi} : refus attendu sur « {motif} », obtenu :\n{sortie}")


def assembler(
    racine_depot: pathlib.Path,
    destination: pathlib.Path,
    artefacts: pathlib.Path,
) -> None:
    """Assemble un bundle comme `cargo xtask bundle`, depuis `artefacts`.

    La campagne n'utilise pas `xtask bundle` : celui-ci reconstruit tout en
    release avec les features matérielles, ce qui n'a pas de sens en dry-run.
    Ce qui est éprouvé ici, c'est la signature, la vérification et
    l'installation — pas la compilation.

    Les binaires viennent de `campaign.sh`, qui en a strippé une copie : un
    binaire de debug non stripé dépasse `MAX_BINARY_SIZE` et ne ressemble à
    aucun artefact réellement livré.
    """
    (destination / "systemd").mkdir(parents=True)
    for binaire in BINAIRES:
        source = artefacts / binaire
        if not source.is_file():
            raise Echec(f"binaire absent : {source}")
        cible = destination / binaire
        shutil.copy2(source, cible)
        cible.chmod(0o755)
    for unite in UNITES:
        cible = destination / "systemd" / unite
        shutil.copy2(racine_depot / "deploy" / "systemd" / unite, cible)
        cible.chmod(0o644)
    cible = destination / "network.toml.example"
    shutil.copy2(racine_depot / "config" / "network.toml", cible)
    cible.chmod(0o644)


def signer(racine_depot: pathlib.Path, bundle: pathlib.Path, epoque: pathlib.Path,
           version: str, commit: str, target: str, sequence: int) -> None:
    exiger_succes(
        executer([
            "cargo", "run", "--quiet", "-p", "helios-publisher", "--",
            "bundle",
            "--dir", str(bundle),
            "--key-epoch", "4294967294",
            "--release-sequence", str(sequence),
            "--channel", "testing",
            "--version", version,
            "--git-commit", commit,
            "--target", target,
            "--ed25519-private-key", str(epoque / "ed25519-private.pk8"),
            "--ml-dsa-65-private-key", str(epoque / "ml-dsa-65-private.bin"),
            "--keyring", str(epoque / "publisher-keyring.json"),
        ]),
        f"signature du bundle (séquence {sequence})",
    )


def environnement_cible(racine: pathlib.Path) -> dict[str, str]:
    """Détourne toutes les destinations vers un faux système jetable."""
    return {
        "HELIOS_UPDATE_CHANNEL": "testing",
        "HELIOS_UPDATE_STAGING": str(racine / "var/lib/helios/updates"),
        "HELIOS_INSTALL_ROOT": str(racine / "opt/helios/releases"),
        "HELIOS_CURRENT_LINK": str(racine / "opt/helios/current"),
        "HELIOS_READY_PATH": str(racine / "run/helios/ready"),
        "HELIOS_LIBEXEC_DIR": str(racine / "usr/libexec"),
        "HELIOS_BIN_DIR": str(racine / "usr/local/bin"),
        "HELIOS_SYSTEMD_DIR": str(racine / "etc/systemd/system"),
        "HELIOS_NETWORK_CONFIG": str(racine / "var/lib/helios/network.toml"),
    }


def bootstrap(installateur: pathlib.Path, bundle: pathlib.Path,
              racine: pathlib.Path) -> subprocess.CompletedProcess:
    return executer(
        [str(installateur), "bootstrap", "--dir", str(bundle)],
        env=environnement_cible(racine),
    )


def run(racine_depot: pathlib.Path, tmp: pathlib.Path, epoque: pathlib.Path,
        version: str, commit: str, target: str, artefacts: pathlib.Path) -> None:
    # L'installateur est exécuté, pas installé : il n'entre pas dans le bundle
    # et sa taille ne regarde donc pas `MAX_BINARY_SIZE`.
    # Là où Cargo l'a écrit : le cache unique quand campaign.sh l'a épinglé.
    cible_cargo = racine_depot / os.environ.get("CARGO_TARGET_DIR", "target")
    installateur = cible_cargo / "debug" / "helios-installer"
    bundle = tmp / "bundle" / f"helios-{version}-{target}"
    assembler(racine_depot, bundle, artefacts)
    signer(racine_depot, bundle, epoque, version, commit, target, SEQUENCE)
    print(f"  ✓ bundle assemblé et signé, séquence {SEQUENCE}")

    # ── Refus : contenu altéré après signature ───────────────────────────────
    altere = tmp / "altere"
    shutil.copytree(bundle, altere)
    (altere / "heliosd").write_bytes(b"binaire substitue")
    exiger_refus(
        bootstrap(installateur, altere, tmp / "cible-altere"),
        "un bundle dont un binaire a été substitué",
        "digest mismatch",
    )
    if (tmp / "cible-altere").exists():
        raise Echec("une installation refusée a tout de même écrit sur la cible")
    print("  ✓ binaire substitué après signature refusé, rien installé")

    # ── Refus : fichier ajouté après signature ───────────────────────────────
    surnumeraire = tmp / "surnumeraire"
    shutil.copytree(bundle, surnumeraire)
    (surnumeraire / "systemd" / "pirate.service").write_text("[Service]\n")
    exiger_refus(
        bootstrap(installateur, surnumeraire, tmp / "cible-surnumeraire"),
        "un bundle enrichi d'une unité non signée",
        "unsigned file",
    )
    print("  ✓ unité systemd ajoutée après signature refusée")

    # ── Refus : signature d'une autre époque que celle compilée ──────────────
    autre = tmp / "autre-epoque"
    shutil.copytree(bundle, autre)
    (autre / "manifest.json").unlink()
    autre_epoque = tmp / "publisher-autre"
    exiger_succes(
        executer([
            "cargo", "run", "--quiet", "-p", "helios-publisher", "--",
            "keygen", "--key-epoch", "4294967293", "--output-dir", str(autre_epoque),
        ]),
        "génération d'une époque étrangère",
    )
    exiger_succes(
        executer([
            "cargo", "run", "--quiet", "-p", "helios-publisher", "--",
            "bundle", "--dir", str(autre), "--key-epoch", "4294967293",
            "--release-sequence", str(SEQUENCE), "--channel", "testing",
            "--version", version, "--git-commit", commit, "--target", target,
            "--ed25519-private-key", str(autre_epoque / "ed25519-private.pk8"),
            "--ml-dsa-65-private-key", str(autre_epoque / "ml-dsa-65-private.bin"),
            "--keyring", str(autre_epoque / "publisher-keyring.json"),
        ]),
        "signature par une époque étrangère",
    )
    exiger_refus(
        bootstrap(installateur, autre, tmp / "cible-autre"),
        "un bundle signé par une époque absente du trousseau compilé",
        "bundle signature rejected",
    )
    print("  ✓ époque éditeur inconnue refusée")

    # ── Refus : canal de production sur une cible de test ────────────────────
    canal = tmp / "canal"
    shutil.copytree(bundle, canal)
    (canal / "manifest.json").unlink()
    signer(racine_depot, canal, epoque, version, commit, target, SEQUENCE)
    resultat = executer(
        [str(installateur), "bootstrap", "--dir", str(canal)],
        env={**environnement_cible(tmp / "cible-canal"), "HELIOS_UPDATE_CHANNEL": "production"},
    )
    exiger_refus(
        resultat,
        "un bundle testing sur une gateway production",
        "channel testing refused",
    )
    print("  ✓ canal du bundle confronté à celui de la gateway")

    # ── Installation nominale ────────────────────────────────────────────────
    cible = tmp / "cible"
    sortie = exiger_succes(bootstrap(installateur, bundle, cible), "installation du bundle")
    attendus = [
        cible / "opt/helios/releases" / str(SEQUENCE) / "heliosd",
        cible / "usr/libexec/helios-installer",
        cible / "usr/local/bin/helios-ctl",
        cible / "etc/systemd/system/heliosd.service",
        cible / "etc/systemd/system/helios-update.service",
        cible / "etc/systemd/system/helios-update.path",
        cible / "etc/systemd/system/helios-log-prune.service",
        cible / "etc/systemd/system/helios-log-prune.timer",
        cible / "var/lib/helios/network.toml",
    ]
    for chemin in attendus:
        if not chemin.is_file():
            raise Echec(f"fichier non installé : {chemin}")
    lien = cible / "opt/helios/current"
    if not lien.is_symlink() or lien.resolve() != (cible / "opt/helios/releases" / str(SEQUENCE)):
        raise Echec(f"lien `current` non basculé : {lien}")
    if os.access(cible / "opt/helios/releases" / str(SEQUENCE) / "heliosd", os.X_OK) is False:
        raise Echec("le daemon installé n'est pas exécutable")
    print(f"  ✓ {len(attendus)} fichiers installés et lien `current` basculé")
    if "sequence" not in sortie:
        raise Echec(f"rapport d'installation inattendu :\n{sortie}")

    etat = json.loads((cible / "var/lib/helios/updates/state.json").read_text())
    if etat["highest_confirmed_sequence"] != SEQUENCE:
        raise Echec(f"anti-rollback non semé : {etat}")
    print(f"  ✓ anti-rollback semé à la séquence {SEQUENCE}")

    # ── Refus : rejeu de la même séquence ────────────────────────────────────
    exiger_refus(
        bootstrap(installateur, bundle, cible),
        "la réinstallation d'une séquence déjà confirmée",
        f"sequence {SEQUENCE} refused",
    )
    print("  ✓ rejeu de la séquence refusé par l'anti-rollback")

    # ── La configuration existante survit à une réinstallation ───────────────
    (cible / "var/lib/helios/network.toml").write_text('wan_iface = "deja-configure"\n')
    suivant = tmp / "suivant"
    shutil.copytree(bundle, suivant)
    (suivant / "manifest.json").unlink()
    signer(racine_depot, suivant, epoque, version, commit, target, SEQUENCE + 1)
    exiger_succes(bootstrap(installateur, suivant, cible), "mise à jour par bundle")
    if (cible / "var/lib/helios/network.toml").read_text() != 'wan_iface = "deja-configure"\n':
        raise Echec("la configuration de la gateway a été écrasée par une réinstallation")
    print("  ✓ configuration existante préservée par la réinstallation")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tmp", required=True, type=pathlib.Path)
    parser.add_argument("--epoch-dir", required=True, type=pathlib.Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--git-commit", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument(
        "--artifacts",
        required=True,
        type=pathlib.Path,
        help="répertoire des binaires strippés préparés par campaign.sh",
    )
    args = parser.parse_args()

    racine_depot = pathlib.Path(__file__).resolve().parent.parent
    try:
        run(
            racine_depot,
            args.tmp,
            args.epoch_dir,
            args.version,
            args.git_commit,
            args.target,
            args.artifacts,
        )
    except Echec as echec:
        print(f"ÉCHEC : {echec}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
