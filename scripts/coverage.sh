#!/usr/bin/env bash
# Reproducible Helios and Orion coverage.
#
# Rust coverage compiles every feature on the host. It therefore covers the
# non-Windows refusal paths, but never Win32 code excluded by cfg(windows), nor
# real TPM, Netlink, kernel WireGuard or WireGuard-NT effects.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

usage() {
  cat <<'USAGE'
Usage: scripts/coverage.sh [--rust-only] [--view workspace|libraries] [--output-dir PATH]
With no options, run the existing Rust and Orion UI coverage pipeline.
USAGE
}

rust_only=0
view=workspace
output_dir="$repo_root/target/coverage"
freeze_args=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --rust-only) rust_only=1; freeze_args=(--frozen); shift ;;
    --view) [ "$#" -ge 2 ] || { echo '--view requires workspace or libraries' >&2; exit 2; }; view="$2"; shift 2 ;;
    --output-dir) [ "$#" -ge 2 ] || { echo '--output-dir requires a path' >&2; exit 2; }; output_dir="$2"; shift 2 ;;
    *) echo "unknown coverage option: $1" >&2; exit 2 ;;
  esac
done
case "$view" in workspace|libraries) ;; *) echo 'view must be workspace or libraries' >&2; exit 2 ;; esac
if [ "$rust_only" = 1 ]; then
  export CARGO_NET_OFFLINE=true npm_config_offline=true
fi
# shellcheck source=scripts/cargo-budget.sh
source scripts/cargo-budget.sh
helios_budget_enter "$repo_root"

if [ "${HELIOS_AUDIT_LOCK_HELD:-0}" != 1 ]; then
  target_dir="${CARGO_TARGET_DIR:-$repo_root/target}"
  mkdir -p "$target_dir"
  exec 8>"$target_dir/.helios-audit.lock"
  flock 8
fi

if [ "$rust_only" = 1 ] && [ "${HELIOS_AUDIT_FRONTENDS_PREFLIGHTED:-0}" != 1 ]; then
  python3 scripts/audit-collect.py preflight --root "$repo_root" --view "$view"
fi

if ! scripts/wsl-cargo llvm-cov --version >/dev/null 2>&1; then
  echo 'cargo-llvm-cov is missing: cargo install cargo-llvm-cov --locked' >&2
  exit 1
fi

report_root="$output_dir"
rust_json="$report_root/workspace.json"
mkdir -p "$report_root"

echo '==> Rust workspace coverage, all features'
if [ "$view" = workspace ]; then
  scripts/wsl-cargo llvm-cov --workspace --all-features "${freeze_args[@]}" --json --output-path "$rust_json" --quiet
else
  scripts/wsl-cargo llvm-cov --workspace --lib --all-features "${freeze_args[@]}" --json --output-path "$rust_json" --quiet
fi

if [ "$rust_only" = 1 ]; then
  echo '==> Rust LCOV report'
  scripts/wsl-cargo llvm-cov report --lcov --output-path "$report_root/workspace.lcov"
fi

echo '==> Rust HTML report'
scripts/wsl-cargo llvm-cov report --html --output-dir "$report_root/rust-html"

if [ "$rust_only" = 1 ]; then
  exit 0
fi
ui_summary="$report_root/orion-ui/coverage-summary.json"

echo '==> Orion UI coverage'
npm run test:coverage --prefix apps/orion

echo '==> Product split summary'
node scripts/coverage-summary.mjs "$rust_json" "$ui_summary"
