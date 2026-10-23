#!/usr/bin/env bash
# Local Rust coverage collection and static audit driver.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
usage() { echo "Usage: scripts/audit-rust.sh collect --view workspace|libraries --output-dir PATH | static" >&2; }
[ "$#" -gt 0 ] || { usage; exit 2; }
if [ "$#" -eq 1 ] && { [ "$1" = "--help" ] || [ "$1" = "-h" ]; }; then
  usage 2>&1 | sed 's/^Usage:/Usage:/'
  exit 0
fi
command="$1"; shift
case "$command" in
  collect)
    view= output_dir=
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --view) [ "$#" -ge 2 ] || { usage; exit 2; }; view="$2"; shift 2 ;;
        --output-dir) [ "$#" -ge 2 ] || { usage; exit 2; }; output_dir="$2"; shift 2 ;;
        *) usage; exit 2 ;;
      esac
    done
    case "$view" in workspace|libraries) ;; *) usage; exit 2 ;; esac
    [ -n "$output_dir" ] || { usage; exit 2; }
    python3 scripts/audit-collect.py collect --root "$repo_root" --view "$view" --output-dir "$output_dir"
    ;;
  static)
    [ "$#" -eq 0 ] || { usage; exit 2; }
    command -v cargo-machete >/dev/null 2>&1 || { echo 'cargo-machete is required for audit-rust static' >&2; exit 127; }
    export CARGO_NET_OFFLINE=true npm_config_offline=true
    python3 scripts/audit-collect.py preflight --root "$repo_root" --view workspace
    scripts/wsl-cargo clippy --workspace --all-targets --all-features --frozen -- -D warnings
    cargo-machete
    ;;
  *) usage; exit 2 ;;
esac
