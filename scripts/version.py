#!/usr/bin/env python3
"""Compute, apply and check the Helios and Orion versions (AGENTS.md, Versions).

Every update merged to main changes the version of what it touches: a feature
raises the minor, a breaking change the major, anything else the patch.
Markdown alone changes nothing.
"""

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import sys

PATCH, MINOR, MAJOR = 1, 2, 3

# What ships in each product. The crates of PRODUCT_CRATES carry the product's
# number: the bundle label and the readiness marker both read `heliosd`'s.
PRODUCT_ROOTS = {
    "helios": ("heliosd", "helios", "helios-installer", "astra"),
    "orion": ("orion",),
}
PRODUCT_CRATES = {"helios": ("heliosd", "helios"), "orion": ("orion",)}
PRODUCT_PATHS = {"helios": ("web/", "deploy/"), "orion": ("apps/orion/",)}
# Both products ship what these pin.
SHARED_FILES = {"Cargo.lock", "Cargo.toml", "rust-toolchain", "rust-toolchain.toml"}
# Path -> how many leading "version" keys the file repeats for itself.
PRODUCT_JSON = {
    "helios": {"web/package.json": 1, "web/package-lock.json": 2},
    "orion": {
        "apps/orion/package.json": 1,
        "apps/orion/package-lock.json": 2,
        "apps/orion/src-tauri/tauri.conf.json": 1,
    },
}
# Windows Installer reads major.minor.build with these ceilings.
INSTALLER_LIMITS = {"orion": (255, 255, 65535)}
RELEASE_PREFIX = "chore(release):"
CONVENTIONAL = re.compile(r"^([a-z]+)(\([^)]*\))?(!)?:")


class VersionError(Exception):
    """A refusal to show the operator, without a stack trace."""


@dataclass
class Commit:
    subject: str
    body: str
    files: list


def level_of(commit):
    match = CONVENTIONAL.match(commit.subject)
    if (match and match.group(3)) or "BREAKING CHANGE" in commit.body:
        return MAJOR
    return MINOR if match and match.group(1) == "feat" else PATCH


def parse(number):
    return tuple(int(part) for part in number.split("."))


def next_version(number, level):
    major, minor, patch = parse(number)
    if level == MAJOR:
        return f"{major + 1}.0.0"
    if level == MINOR:
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def packages_of(metadata):
    return {package["name"]: package for package in metadata["packages"]}


def directory_of(metadata, package):
    manifest = Path(package["manifest_path"]).parent
    return manifest.relative_to(metadata["workspace_root"]).as_posix() + "/"


def closure(packages, roots):
    """The crates a product ships. Test and build-time dependencies do not ship."""
    shipped, pending = set(), [root for root in roots if root in packages]
    while pending:
        name = pending.pop()
        if name in shipped:
            continue
        shipped.add(name)
        pending += [
            dependency["name"] for dependency in packages[name]["dependencies"]
            if dependency.get("path") and dependency.get("kind") is None
            and dependency["name"] in packages
        ]
    return shipped


def plan(metadata, commits):
    """What each update asks for: a target (product or crate) -> its level."""
    packages = packages_of(metadata)
    directories = {name: directory_of(metadata, item) for name, item in packages.items()}
    shipped = {product: closure(packages, roots) for product, roots in PRODUCT_ROOTS.items()}
    numbered_by_product = {name for names in PRODUCT_CRATES.values() for name in names}
    levels = {}

    def raise_to(target, level):
        levels[target] = max(levels.get(target, 0), level)

    for commit in commits:
        if commit.subject.startswith(RELEASE_PREFIX):
            continue
        level = level_of(commit)
        files = [path for path in commit.files if not path.endswith(".md")]
        touched = {
            name for name, directory in directories.items()
            if any(path.startswith(directory) for path in files)
        }
        for name in touched - numbered_by_product:
            raise_to(name, level)
        for product, crates in shipped.items():
            if touched & crates or any(
                path in SHARED_FILES or path.startswith(PRODUCT_PATHS[product]) for path in files
            ):
                raise_to(product, level)
    return levels


def manifest_version(text):
    section = re.search(r"^\[package\]\n(.*?)(?=^\[|\Z)", text, re.MULTILINE | re.DOTALL)
    match = section and re.search(r'^version = "([^"]+)"', section.group(1), re.MULTILINE)
    return match.group(1) if match else None


def set_manifest_version(text, number):
    start = text.index("[package]")
    updated = re.sub(r'^version = "[^"]+"', f'version = "{number}"', text[start:], count=1, flags=re.MULTILINE)
    return text[:start] + updated


def set_lock_versions(text, numbers):
    """Only a workspace member: a registry package carries a `source` line."""
    for name, number in numbers.items():
        text = re.sub(
            rf'(name = "{re.escape(name)}"\nversion = )"[^"]+"(?!\nsource)',
            rf'\g<1>"{number}"',
            text,
        )
    return text


def set_json_version(text, number, count):
    return re.sub(r'"version": "[^"]+"', f'"version": "{number}"', text, count=count)


def product_number(packages, product):
    return packages[PRODUCT_CRATES[product][0]]["version"]


def current_number(packages, target):
    return product_number(packages, target) if target in PRODUCT_CRATES else packages[target]["version"]


def within_limits(product, number):
    limits = INSTALLER_LIMITS.get(product)
    return not limits or all(part <= limit for part, limit in zip(parse(number), limits))


def consistency_errors(root, metadata):
    """Every file naming a product's number must name the same one."""
    packages = packages_of(metadata)
    errors = []
    for product, crates in PRODUCT_CRATES.items():
        number = product_number(packages, product)
        if not within_limits(product, number):
            errors.append(f"{product} {number} dépasse ce que l'installeur Windows accepte")
        for crate in crates[1:]:
            if packages[crate]["version"] != number:
                errors.append(f"le crate {crate} est en {packages[crate]['version']}, {product} en {number}")
        for path in PRODUCT_JSON[product]:
            found = json.loads((Path(root) / path).read_text())["version"]
            if found != number:
                errors.append(f"{path} est en {found}, {product} en {number}")
    return errors


def git(*arguments):
    return subprocess.run(["git", *arguments], check=True, capture_output=True, text=True).stdout


def commits_since(base):
    commits = []
    for commit in git("rev-list", "--no-merges", f"{base}..HEAD").split():
        subject, _, body = git("show", "-s", "--format=%s%n%b", commit).partition("\n")
        files = git("show", "--no-renames", "--name-only", "--format=", commit).split("\n")
        commits.append(Commit(subject, body, [path for path in files if path]))
    return commits


def version_files(metadata, levels):
    """Every file a bump of these targets rewrites, relative to the root."""
    packages = packages_of(metadata)
    crates = set()
    paths = {"Cargo.lock"}
    for target in levels:
        crates |= set(PRODUCT_CRATES.get(target, (target,)))
        paths |= set(PRODUCT_JSON.get(target, ()))
    for crate in crates:
        paths.add(directory_of(metadata, packages[crate]) + "Cargo.toml")
    return sorted(paths)


def apply(root, metadata, numbers):
    """Writes target -> number into the manifests, the lockfile and the JSON files."""
    root = Path(root)
    packages = packages_of(metadata)
    crates = {}
    for target, number in numbers.items():
        for crate in PRODUCT_CRATES.get(target, (target,)):
            crates[crate] = number
        for path, count in PRODUCT_JSON.get(target, {}).items():
            file = root / path
            file.write_text(set_json_version(file.read_text(), number, count))
    for crate, number in crates.items():
        file = Path(packages[crate]["manifest_path"])
        file.write_text(set_manifest_version(file.read_text(), number))
    lock = root / "Cargo.lock"
    lock.write_text(set_lock_versions(lock.read_text(), crates))


def release_subject(numbers):
    products = [f"{name} {numbers[name]}" for name in PRODUCT_CRATES if name in numbers]
    crates = [f"{name} {number}" for name, number in sorted(numbers.items()) if name not in PRODUCT_CRATES]
    return f"{RELEASE_PREFIX} bump " + ", ".join(products or crates), crates if products else []


def bump(base, metadata, trailers=()):
    """Applies and commits what base..HEAD asks for. Returns target -> number."""
    root = metadata["workspace_root"]
    packages = packages_of(metadata)
    levels = plan(metadata, commits_since(base))
    if not levels:
        print("aucune version ne change : rien de livré n'a bougé")
        return {}
    numbers = {target: next_version(current_number(packages, target), level) for target, level in levels.items()}
    for target, number in numbers.items():
        if not within_limits(target, number):
            raise VersionError(
                f"{target} {number} dépasse ce que l'installeur Windows accepte : "
                "cette mise à jour doit monter la majeure"
            )
    paths = version_files(metadata, levels)
    if git("status", "--porcelain", "--", *paths):
        raise VersionError(f"des fichiers de version portent des changements non commités : {' '.join(paths)}")
    apply(root, metadata, numbers)
    subject, crates = release_subject(numbers)
    message = ["-m", subject] + (["-m", "\n".join(crates)] if crates else [])
    for trailer in trailers:
        message += ["--trailer", trailer]
    git("commit", "-q", *message, "--only", "--", *paths)
    print(subject)
    return numbers


def merge(branch, load, trailers=()):
    """Merges a branch into main, then commits the versions it asks for.

    `load` runs after the merge: a branch may add a crate or a dependency.
    """
    current = git("branch", "--show-current").strip()
    if current != "main":
        raise VersionError(f"la fusion se fait depuis main, pas depuis {current or 'un HEAD détaché'}")
    base = git("rev-parse", "HEAD").strip()
    try:
        git("merge", "--no-edit", branch)
    except subprocess.CalledProcessError as error:
        raise VersionError(f"la fusion de {branch} a échoué, à résoudre à la main :\n{error.stdout}{error.stderr}") from error
    return bump(base, load(), trailers)


def check(base, root, metadata):
    """What CI refuses on main: files that disagree, or code without a new number."""
    errors = consistency_errors(root, metadata)
    packages = packages_of(metadata)
    for target in plan(metadata, commits_since(base)):
        crate = PRODUCT_CRATES.get(target, (target,))[0]
        path = directory_of(metadata, packages[crate]) + "Cargo.toml"
        try:
            before = manifest_version(git("show", f"{base}:{path}"))
        except subprocess.CalledProcessError:
            continue  # A crate this range created has no earlier number.
        number = current_number(packages, target)
        if before and parse(number) <= parse(before):
            errors.append(f"{target} a changé sans nouvelle version (toujours {number}) : lancer scripts/version.py bump")
    return errors


def load_metadata():
    return json.loads(subprocess.check_output(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--offline"],
    ))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("show", help="Affiche les versions de Helios et d'Orion")
    merging = commands.add_parser("merge", help="Fusionne une branche dans main et monte les versions")
    merging.add_argument("branch")
    bumping = commands.add_parser("bump", help="Monte les versions pour les commits depuis --base")
    bumping.add_argument("--base", required=True)
    for command in (merging, bumping):
        command.add_argument("--trailer", action="append", default=[], help="Ligne de fin du commit de version")
    checking = commands.add_parser("check", help="Contrôle de la CI sur main")
    checking.add_argument("--base", required=True)
    args = parser.parse_args()

    os.chdir(Path(__file__).resolve().parents[1])
    try:
        if args.command == "merge":
            merge(args.branch, load_metadata, args.trailer)
            return 0
        metadata = load_metadata()
        root = metadata["workspace_root"]
        if args.command == "bump":
            bump(args.base, metadata, args.trailer)
        else:
            errors = check(args.base, root, metadata) if args.command == "check" else consistency_errors(root, metadata)
            if args.command == "show":
                packages = packages_of(metadata)
                for product in PRODUCT_CRATES:
                    print(f"{product} {product_number(packages, product)}")
            if errors:
                raise VersionError("\n".join(errors))
    except VersionError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
