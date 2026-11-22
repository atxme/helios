#!/usr/bin/env python3
"""Verifies that the working toolchain pins of the repository agree.

Rust pins are compared at the major.minor level, Node pins at the major level.
The first pin of a tool, or the most frequent one on a tie, is the reference.
Exit status 1 lists every pin that disagrees with it.
"""

from collections import Counter
from pathlib import Path
import re
import sys

RUST = "rust"
NODE = "node"

DOCKERFILE = "tools/build-env/Dockerfile"
CARGO_MANIFEST = "Cargo.toml"
SETUP_SCRIPT = "scripts/setup-dev.sh"
WORKFLOW_GLOB = ".github/workflows/*.yml"

DOCKER_RUST = re.compile(r"^ARG RUST_VERSION=(\S+)$", re.MULTILINE)
DOCKER_NODE = re.compile(r"^ARG NODE_VERSION=(\S+)$", re.MULTILINE)
CARGO_RUST = re.compile(r'^rust-version\s*=\s*"([^"]+)"', re.MULTILINE)
SETUP_RUST = re.compile(r'^RUST_MIN="([^"]+)"', re.MULTILINE)
WORKFLOW_RUST = re.compile(r"dtolnay/rust-toolchain@(\d+\.\d+\.\d+)\b")
WORKFLOW_NODE = re.compile(r"^\s*node-version:\s*['\"]?([0-9][^'\"\s]*)", re.MULTILINE)


def _read(path):
    return path.read_text(encoding="utf-8")


def _first(pattern, text):
    match = pattern.search(text)
    return match.group(1) if match else None


def collect_pins(root):
    """Return {tool: [(relative file, version as written)]} for the repository at root."""
    root = Path(root)
    pins = {RUST: [], NODE: []}

    dockerfile = root / DOCKERFILE
    if dockerfile.is_file():
        text = _read(dockerfile)
        pins[RUST].append((DOCKERFILE, _first(DOCKER_RUST, text)))
        pins[NODE].append((DOCKERFILE, _first(DOCKER_NODE, text)))

    cargo = root / CARGO_MANIFEST
    if cargo.is_file():
        pins[RUST].append((CARGO_MANIFEST, _first(CARGO_RUST, _read(cargo))))

    setup = root / SETUP_SCRIPT
    if setup.is_file():
        pins[RUST].append((SETUP_SCRIPT, _first(SETUP_RUST, _read(setup))))

    for workflow in sorted(root.glob(WORKFLOW_GLOB)):
        name = workflow.relative_to(root).as_posix()
        text = _read(workflow)
        for version in WORKFLOW_RUST.findall(text):
            pins[RUST].append((name, version))
        for version in WORKFLOW_NODE.findall(text):
            pins[NODE].append((name, version))

    return {tool: [(name, version) for name, version in entries if version] for tool, entries in pins.items()}


def _key(tool, version):
    parts = version.split(".")
    if tool == RUST:
        return ".".join(parts[:2])
    return parts[0]


def mismatches(pins):
    """Return one readable message per pin that disagrees with its tool's reference."""
    problems = []
    for tool, entries in pins.items():
        if not entries:
            continue
        keys = [(name, version, _key(tool, version)) for name, version in entries]
        counts = Counter(key for _, _, key in keys)
        reference_key = counts.most_common(1)[0][0]
        reference_file = next(name for name, _, key in keys if key == reference_key)
        for name, version, key in keys:
            if key != reference_key:
                problems.append(
                    f"{tool}: {name} épingle {version} ; {reference_key} attendu "
                    f"(référence : {reference_file})"
                )
    return problems


def main():
    root = Path(__file__).resolve().parents[1]
    pins = collect_pins(root)
    problems = mismatches(pins)
    if problems:
        print("Versions de toolchain en désaccord :", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print("Versions de toolchain concordantes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
