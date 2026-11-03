#!/usr/bin/env python3
"""Collect Rust coverage and write a content-checked provenance record."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone


def run(args, *, cwd, stdout=None, env=None):
    return subprocess.run(args, cwd=cwd, stdout=stdout, check=True, env=env)


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def rust_hashes(root, package_dirs):
    ignored = {"target", "node_modules", ".git"}
    result = {}
    for package_dir in package_dirs:
        for directory, dirs, files in os.walk(package_dir):
            dirs[:] = sorted(d for d in dirs if d not in ignored)
            for name in sorted(files):
                if name.endswith(".rs"):
                    path = Path(directory, name)
                    result[path.relative_to(root).as_posix()] = digest(path)
    return result


def build_input_hashes(root, package_dirs):
    paths = {root / "Cargo.toml", root / "Cargo.lock"}
    paths.update(package_dir / "Cargo.toml" for package_dir in package_dirs)
    cargo_config = root / ".cargo"
    if cargo_config.is_dir():
        paths.update(cargo_config.glob("*.toml"))
    missing = [path for path in paths if not path.is_file()]
    if missing:
        raise RuntimeError(f"Cargo build input is missing: {missing[0]}")
    return {path.relative_to(root).as_posix(): digest(path) for path in sorted(paths)}


def preflight_frontends(root, metadata, view, env):
    members = set(metadata["workspace_members"])
    packages = [pkg for pkg in metadata["packages"] if pkg["id"] in members]
    embeds_web = any(pkg["name"] == "helios-api" and "embed-ui" in pkg.get("features", {}) for pkg in packages)
    if embeds_web and not (root / "web" / "dist" / "index.html").is_file():
        raise ValueError("web/dist/index.html is required by helios-api's embed-ui feature; build the web assets before collecting")

    builds_orion = view == "workspace" and any(pkg["name"] == "orion" for pkg in packages)
    if builds_orion:
        orion = root / "apps" / "orion"
        vite = orion / "node_modules" / "vite" / "bin" / "vite.js"
        if not vite.is_file():
            raise ValueError(f"Orion frontend dependencies are missing ({vite}); install them explicitly before collecting")
        env["npm_config_offline"] = "true"
        try:
            result = subprocess.run(["npm", "ls", "--depth=0", "--silent"], cwd=orion, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        except OSError as exc:
            raise ValueError(f"npm is required to verify Orion dependencies without installation: {exc}") from exc
        if result.returncode:
            raise ValueError("Orion frontend dependencies are unhealthy; repair them explicitly before collecting")


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()


def collect(root, view, output):
    root = root.resolve()
    output = output.resolve()
    if output == root or root in output.parents:
        raise ValueError("output directory must be outside the source tree")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError(f"output directory must be new or empty: {output}")
    output.mkdir(parents=True, exist_ok=True)

    # Enter the repository's existing budget policy before choosing the shared
    # target cache and lock. No task-specific target directory is created.
    setup = 'source scripts/cargo-budget.sh; helios_budget_enter "$PWD"; printf "%s\\n" "${CARGO_TARGET_DIR:-$PWD/target}"'
    target = subprocess.check_output(["bash", "-c", setup], cwd=root, text=True).splitlines()[-1]
    lock_path = Path(target) / ".helios-audit.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if any(output.iterdir()):
            raise ValueError(f"output directory became nonempty while waiting for the audit lock: {output}")
        (output / "status.json").write_text('{"status":"partial"}\n')
        env = os.environ.copy()
        env["HELIOS_AUDIT_LOCK_HELD"] = "1"
        env["CARGO_NET_OFFLINE"] = "true"
        env["npm_config_offline"] = "true"
        overridden = [name for name in ("CARGO_BUILD_TARGET", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER", "LLVM_COV", "LLVM_PROFDATA") if env.get(name)]
        if overridden:
            raise ValueError(f"unsupported build override(s): {', '.join(overridden)}")
        revision = git(root, "rev-parse", "HEAD")
        dirty_before = git(root, "status", "--porcelain")
        rustc_vv = subprocess.check_output(["rustc", "-Vv"], cwd=root, text=True).strip()
        host_line = next((line for line in rustc_vv.splitlines() if line.startswith("host: ")), None)
        if host_line is None:
            raise RuntimeError("rustc -Vv did not report a host triple")
        target_triple = host_line.split(": ", 1)[1]

        # Fail before metadata or instrumented compilation if a required
        # analyzer/export tool is unavailable.
        subprocess.check_call(["scripts/wsl-cargo", "llvm-cov", "--version"], cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        subprocess.check_call(["rustfmt", "--version"], cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.check_call(["rust-analyzer", "--version"], cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sysroot = Path(subprocess.check_output(["rustc", "--print", "sysroot"], cwd=root, text=True).strip())
        llvm_cov = sysroot / "lib" / "rustlib" / target_triple / "bin" / "llvm-cov"
        if not llvm_cov.is_file():
            raise RuntimeError(f"Rust sysroot llvm-cov is missing: {llvm_cov}")
        subprocess.check_call([str(llvm_cov), "--version"], cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        with (output / "metadata.json").open("w") as metadata:
            run(["scripts/wsl-cargo", "metadata", "--no-deps", "--all-features", "--frozen", "--format-version", "1"], cwd=root, stdout=metadata, env=env)
        metadata_data = json.loads((output / "metadata.json").read_text())
        preflight_frontends(root, metadata_data, view, env)
        env["HELIOS_AUDIT_FRONTENDS_PREFLIGHTED"] = "1"
        workspace_members = set(metadata_data["workspace_members"])
        package_dirs = [Path(pkg["manifest_path"]).resolve().parent for pkg in metadata_data["packages"] if pkg["id"] in workspace_members]
        if not package_dirs or any(root not in path.parents and path != root for path in package_dirs):
            raise RuntimeError("Cargo metadata returned no valid workspace package directories")
        source_before = rust_hashes(root, package_dirs)
        build_inputs_before = build_input_hashes(root, package_dirs)
        run(["scripts/coverage.sh", "--rust-only", "--view", view, "--output-dir", str(output)], cwd=root, env=env)

        rustc_cfg = subprocess.check_output(["rustc", "--print", "cfg"], cwd=root, text=True).splitlines()
        features = {pkg["id"]: sorted(pkg.get("features", {})) for pkg in metadata_data["packages"]}
        tools = {
            "rust_analyzer": subprocess.check_output(["rust-analyzer", "--version"], cwd=root, text=True).strip(),
            "cargo_llvm_cov": subprocess.check_output(["scripts/wsl-cargo", "llvm-cov", "--version"], cwd=root, text=True).strip(),
            "llvm_cov": subprocess.check_output([str(llvm_cov), "--version"], cwd=root, text=True).strip(),
            "rustfmt": subprocess.check_output(["rustfmt", "--version"], cwd=root, text=True).strip(),
        }
        source_after = rust_hashes(root, package_dirs)
        build_inputs_after = build_input_hashes(root, package_dirs)
        dirty_after = git(root, "status", "--porcelain")
        revision_after = git(root, "rev-parse", "HEAD")
        if source_before != source_after or build_inputs_before != build_inputs_after or dirty_before != dirty_after or revision != revision_after:
            raise RuntimeError("Source files changed during collection; provenance was not finalized")
        artifacts = {
            "coverage": digest(output / "workspace.json"),
            "lcov": digest(output / "workspace.lcov"),
            "metadata": digest(output / "metadata.json"),
        }
        provenance = {
            "schema_version": 1,
            "source_root": str(root),
            "source_revision": revision,
            "source_dirty": bool(dirty_before),
            "source_sha256": source_after,
            "build_input_sha256": build_inputs_after,
            "target": target_triple,
            "rustc_version": rustc_vv,
            "rustc_cfg": rustc_cfg,
            "features": features,
            "tools": tools,
            "artifacts_sha256": artifacts,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "tests_success": True,
            "view": view,
        }
        (output / "provenance.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n")
        run(["python3", "scripts/audit-report.py", "summarize", "--root", str(root), "--coverage", str(output / "workspace.json"), "--lcov", str(output / "workspace.lcov"), "--metadata", str(output / "metadata.json"), "--provenance", str(output / "provenance.json"), "--view", view, "--output", str(output / "report.json")], cwd=root)
        (output / "status.json").write_text('{"status":"completed"}\n')


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    command = sub.add_parser("collect")
    command.add_argument("--root", type=Path, required=True)
    command.add_argument("--view", choices=("workspace", "libraries"), required=True)
    command.add_argument("--output-dir", type=Path, required=True)
    preflight = sub.add_parser("preflight")
    preflight.add_argument("--root", type=Path, required=True)
    preflight.add_argument("--view", choices=("workspace", "libraries"), required=True)
    args = parser.parse_args()
    try:
        if args.command == "collect":
            collect(args.root, args.view, args.output_dir)
        else:
            root = args.root.resolve()
            env = os.environ.copy()
            env["CARGO_NET_OFFLINE"] = "true"
            env["npm_config_offline"] = "true"
            with subprocess.Popen(["scripts/wsl-cargo", "metadata", "--no-deps", "--all-features", "--frozen", "--format-version", "1"], cwd=root, env=env, stdout=subprocess.PIPE) as process:
                metadata = json.loads(process.stdout.read())
                if process.wait():
                    raise RuntimeError("Cargo metadata failed during frontend preflight")
            preflight_frontends(root, metadata, args.view, env)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError, json.JSONDecodeError) as exc:
        print(f"audit collection failed: {exc}", file=sys.stderr)
        sys.exit(getattr(exc, "returncode", 1) or 1)


if __name__ == "__main__":
    main()
