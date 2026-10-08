#!/usr/bin/env bash
# Build, sign and deploy one heliosd application release through the admin API.
# The workstation is both build host and publisher in this convenience flow;
# the gateway receives neither source code nor publisher private keys.
set -euo pipefail

SCRIPTS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPTS/.."
# shellcheck source=scripts/cargo-budget.sh
source scripts/cargo-budget.sh
helios_budget_enter "$PWD"

URL="${HELIOS_URL:-http://100.64.0.1:8080}"
EPOCH_DIR="$HOME/.helios/publisher-epoch-1"
CHANNEL="${HELIOS_DEPLOY_CHANNEL:-production}"
SEQUENCE=""
SKIP_FRONTEND=0
STAGE_ONLY=0

usage() {
    cat >&2 <<'EOF'
Usage: ./scripts/deploy-app.sh [options]

  --url URL          Helios admin API through helios0
  --sequence N       Release sequence (default: Unix timestamp)
  --channel C        testing or production (default: production)
  --skip-frontend    Reuse web/dist for a faster Rust-only iteration
  --stage-only       Upload and verify without activating

Variables: HELIOS_URL, HELIOS_DEPLOY_CHANNEL.
EOF
    exit "${1:-1}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --url) URL="${2:-}"; shift 2 ;;
        --sequence) SEQUENCE="${2:-}"; shift 2 ;;
        --channel) CHANNEL="${2:-}"; shift 2 ;;
        --skip-frontend) SKIP_FRONTEND=1; shift ;;
        --stage-only) STAGE_ONLY=1; shift ;;
        -h|--help) usage 0 ;;
        *) echo "unknown option: $1" >&2; usage ;;
    esac
done

case "$CHANNEL" in
    testing|production) ;;
    *) echo "invalid channel: $CHANNEL" >&2; exit 1 ;;
esac

[ -n "$SEQUENCE" ] || SEQUENCE="$(date +%s)"
case "$SEQUENCE" in
    ''|*[!0-9]*) echo "invalid release sequence: $SEQUENCE" >&2; exit 1 ;;
esac

for file in ed25519-private.pk8 ml-dsa-65-private.bin publisher-keyring.json; do
    if [ ! -f "$EPOCH_DIR/$file" ]; then
        echo "incomplete publisher epoch: $EPOCH_DIR/$file not found" >&2
        exit 1
    fi
done

KEY_EPOCH="$(sed -n 's/.*"key_epoch"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' \
    "$EPOCH_DIR/publisher-keyring.json" | head -1)"
[ -n "$KEY_EPOCH" ] || { echo "cannot read key epoch from publisher-keyring.json" >&2; exit 1; }

TARGET="$(rustc -vV | sed -n 's/^host: //p')"
# The daemon's own version, not the workspace's: `heliosd` does not inherit
# `version.workspace`, and the readiness marker it writes after an update
# carries its crate version. A manifest labeled with the workspace version can
# never be confirmed — the health check would compare two different numbers for
# the same release. Same source as `xtask::release_version`.
VERSION="$(sed -n '/^\[package\]/,/^\[/p' crates/heliosd/Cargo.toml |
    sed -n 's/^version = "\(.*\)"/\1/p' | head -1)"
[ -n "$VERSION" ] || { echo "version missing from crates/heliosd/Cargo.toml" >&2; exit 1; }
COMMIT="$(git rev-parse --short=16 HEAD)"
if [ -n "$(git status --porcelain)" ]; then
    COMMIT="${COMMIT}-dirty"
    echo "warning: the manifest will identify a dirty worktree as $COMMIT" >&2
fi

OUTPUT_DIR="target/app-release"
MANIFEST="$OUTPUT_DIR/heliosd-$SEQUENCE.release.json"
BINARY="${CARGO_TARGET_DIR:-target}/$TARGET/release/heliosd"
mkdir -p "$OUTPUT_DIR"

echo "==> Build heliosd $VERSION ($TARGET)"
BUILD_ARGS=(app --target "$TARGET")
if [ "$SKIP_FRONTEND" = "1" ]; then
    BUILD_ARGS+=(--skip-frontend)
fi
HELIOS_PUBLISHER_KEYRING_PATH="$EPOCH_DIR/publisher-keyring.json" \
    cargo xtask "${BUILD_ARGS[@]}"

echo "==> Sign sequence $SEQUENCE ($CHANNEL)"
cargo run --quiet -p helios-publisher -- binary-release \
    --key-epoch "$KEY_EPOCH" \
    --release-sequence "$SEQUENCE" \
    --channel "$CHANNEL" \
    --version "$VERSION" \
    --git-commit "$COMMIT" \
    --target "$TARGET" \
    --features embed-ui,netlink,tpm,wireguard \
    --binary "$BINARY" \
    --ed25519-private-key "$EPOCH_DIR/ed25519-private.pk8" \
    --ml-dsa-65-private-key "$EPOCH_DIR/ml-dsa-65-private.bin" \
    --keyring "$EPOCH_DIR/publisher-keyring.json" \
    --output "$MANIFEST"

echo "==> Transfer through $URL"
CTL_ARGS=(--url "$URL" app-update --manifest "$MANIFEST" --binary "$BINARY")
if [ "$STAGE_ONLY" = "1" ]; then
    CTL_ARGS+=(--stage-only)
else
    CTL_ARGS+=(--yes)
fi
HELIOS_PUBLISHER_KEYRING_PATH="$EPOCH_DIR/publisher-keyring.json" \
    cargo run --quiet -p helios -- "${CTL_ARGS[@]}"
