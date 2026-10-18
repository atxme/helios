"""Select CI checks from changed paths and reverse workspace dependencies."""

import argparse
import json
import re
import subprocess
from pathlib import Path

WINDOWS_PACKAGES = {
    "aether-fido", "orion-core", "orion", "astra-signer", "helios-astra-helper",
}


def plan(metadata, paths, full=False):
    full = full or any(path in {
        ".github/workflows/regression.yml", "scripts/ci-plan.py", "scripts/tests/test_ci_plan.py",
    } for path in paths)
    root = Path(metadata["workspace_root"])
    packages = {package["name"]: package for package in metadata["packages"]}
    directories = {
        name: Path(package["manifest_path"]).parent for name, package in packages.items()
    }
    # Cargo package names become CLI arguments, never shell fragments.
    if any(not re.fullmatch(r"[A-Za-z0-9_-]+", name) for name in packages):
        raise ValueError("Unsupported Cargo package name")
    all_rust = full or any(
        path in {"Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "rust-toolchain"}
        or path.startswith((".cargo/", "vendor/"))
        for path in paths
    )
    affected = set(packages) if all_rust else {
        name for name, directory in directories.items()
        if any((root / path).is_relative_to(directory) for path in paths)
    }
    # Include optional, build, dev and target-specific path dependencies.
    # A dependent's integration tests can break even when its files did not change.
    while True:
        dependents = {
            name for name, package in packages.items()
            if any(
                dependency.get("path") and Path(dependency["path"]) == directories[changed]
                for dependency in package["dependencies"] for changed in affected
            )
        }
        if dependents <= affected:
            break
        affected |= dependents

    linux = affected - {"orion"}
    windows = affected & WINDOWS_PACKAGES
    if any(path.startswith("scripts/") and path.endswith(".ps1") for path in paths):
        windows |= WINDOWS_PACKAGES & packages.keys()
    return {
        "linux": " ".join(f"-p {name}" for name in sorted(linux)),
        "windows": " ".join(f"-p {name}" for name in sorted(windows)),
        "aether": "aether" in affected,
        "embed_web": bool(linux & {"helios-api", "heliosd"}),
        "web": full or any(path.startswith("web/") for path in paths),
        "orion_ui": full or any(
            path.startswith("apps/orion/") and not path.startswith("apps/orion/src-tauri/")
            for path in paths
        ),
        "audit": full or any(
            path in {"Cargo.lock", "web/package-lock.json", "apps/orion/package-lock.json"}
            for path in paths
        ),
        "checks": full or bool(affected) or any(path.startswith("scripts/") for path in paths),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", help="Base commit; omit to check all packages")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    metadata = json.loads(subprocess.check_output([
        "cargo", "metadata", "--no-deps", "--format-version", "1", "--offline",
    ]))
    paths = []
    if args.base:
        changed = subprocess.check_output([
            "git", "diff", "--name-only", "--no-renames", "-z", args.base, "HEAD",
        ])
        paths = changed.decode().rstrip("\0").split("\0") if changed else []
    selected = plan(metadata, paths, full=not args.base)
    with args.output.open("a") as output:
        for name, value in selected.items():
            value = str(value).lower() if isinstance(value, bool) else value
            output.write(f"{name}={value}\n")
    print(json.dumps(selected, indent=2))


if __name__ == "__main__":
    main()
