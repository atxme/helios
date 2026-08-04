#!/usr/bin/env bash
# Reproducible Helios and Orion coverage.
#
# Rust coverage compiles every feature on the host. It therefore covers the
# non-Windows refusal paths, but never Win32 code excluded by cfg(windows), nor
# real TPM, Netlink, kernel WireGuard or WireGuard-NT effects.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if ! cargo llvm-cov --version >/dev/null 2>&1; then
  echo 'cargo-llvm-cov is missing: cargo install cargo-llvm-cov --locked' >&2
  exit 1
fi

report_root="$repo_root/target/coverage"
rust_json="$report_root/workspace.json"
ui_summary="$report_root/orion-ui/coverage-summary.json"
mkdir -p "$report_root"

echo '==> Rust workspace coverage, all features'
cargo llvm-cov --workspace --all-features --json --output-path "$rust_json" --quiet

echo '==> Rust HTML report'
cargo llvm-cov report --html --output-dir "$report_root/rust-html"

echo '==> Orion UI coverage'
npm run test:coverage --prefix apps/orion

echo '==> Product split summary'
node scripts/coverage-summary.mjs "$rust_json" "$ui_summary"
