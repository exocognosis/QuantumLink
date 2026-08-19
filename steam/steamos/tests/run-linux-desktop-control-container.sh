#!/bin/sh
set -eu

fail() {
    echo "Linux desktop-control container failed: $*" >&2
    exit 1
}

command -v docker >/dev/null 2>&1 || fail "Docker is required"
docker info >/dev/null 2>&1 || fail "Docker daemon is not running"

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname "$0")" && pwd)"
REPO_ROOT="$(CDPATH='' cd -- "$SCRIPT_DIR/../../.." && pwd)"
IMAGE="${QLINK_LINUX_TEST_IMAGE:-quantumlink-steamos-systemd-test:local}"
CONTAINER="${QLINK_LINUX_TEST_CONTAINER:-quantumlink-steamos-systemd-test}"
REPORT="${QLINK_INTEGRATION_REPORT:-/tmp/quantumlink-steamos-desktop-control-linux.json}"
NETWORK_REPORT="${QLINK_NETWORK_INTEGRATION_REPORT:-/tmp/quantumlink-steamos-network-game-linux.json}"
SOURCE_REPOSITORY="${QLINK_SOURCE_REPOSITORY:-https://github.com/exocognosis/QuantumLink.git}"
STAGE_BASE="${QLINK_LINUX_STAGE_BASE:-$HOME/.codex/tmp}"
CARGO_REGISTRY_VOLUME="${QLINK_LINUX_CARGO_REGISTRY_VOLUME:-quantumlink-steamos-cargo-registry}"
CARGO_GIT_VOLUME="${QLINK_LINUX_CARGO_GIT_VOLUME:-quantumlink-steamos-cargo-git}"
CARGO_TARGET_VOLUME="${QLINK_LINUX_CARGO_TARGET_VOLUME:-quantumlink-steamos-cargo-target}"
mkdir -p "$STAGE_BASE"
STAGE_ROOT="$(mktemp -d "$STAGE_BASE/quantumlink-linux-integration.XXXXXX")"
STAGE_ROOT="$(CDPATH='' cd -- "$STAGE_ROOT" && pwd -P)"
STAGE_DIR="$STAGE_ROOT/source"

cleanup() {
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    rm -rf "$STAGE_ROOT"
}
trap cleanup EXIT INT TERM

# Docker Desktop cannot reliably bind cloud-backed source files. Start from a
# clean clone, then overlay the current SteamOS backend and integration assets.
git clone --depth 1 "$SOURCE_REPOSITORY" "$STAGE_DIR"
cp -X "$REPO_ROOT/Cargo.toml" "$STAGE_DIR/Cargo.toml"
cp -X "$REPO_ROOT/Cargo.lock" "$STAGE_DIR/Cargo.lock"
rm -rf "$STAGE_DIR/qlink-core/src"
cp -X "$REPO_ROOT/qlink-core/Cargo.toml" "$STAGE_DIR/qlink-core/Cargo.toml"
cp -R -X "$REPO_ROOT/qlink-core/src" "$STAGE_DIR/qlink-core/src"
for crate in qlink-desktop qlink-game qlink-linux qlink-proto qlinkctl qlinkd; do
    source_crate="$REPO_ROOT/steam/steamos/rust/$crate"
    staged_crate="$STAGE_DIR/steam/steamos/rust/$crate"
    rm -rf "$staged_crate/src"
    mkdir -p "$staged_crate"
    cp -X "$source_crate/Cargo.toml" "$staged_crate/Cargo.toml"
    cp -R -X "$source_crate/src" "$staged_crate/src"
done
cp -X "$REPO_ROOT/steam/steamos/tests/linux-desktop-control-integration.sh" \
    "$STAGE_DIR/steam/steamos/tests/linux-desktop-control-integration.sh"
cp -X "$REPO_ROOT/steam/steamos/tests/linux-network-game-integration.sh" \
    "$STAGE_DIR/steam/steamos/tests/linux-network-game-integration.sh"
mkdir -p "$STAGE_DIR/steam/steamos/tests/fixtures"
cp -X \
    "$REPO_ROOT/steam/steamos/tests/fixtures/40-quantumlink-service-control-integration.rules" \
    "$STAGE_DIR/steam/steamos/tests/fixtures/40-quantumlink-service-control-integration.rules"
mkdir -p \
    "$STAGE_DIR/steam/steamos/config/games" \
    "$STAGE_DIR/steam/steamos/packaging/libexec" \
    "$STAGE_DIR/steam/steamos/packaging/polkit" \
    "$STAGE_DIR/steam/steamos/packaging/systemd/qlinkd.service.d"
cp -X "$REPO_ROOT/steam/steamos/config/steam-bypass.toml" \
    "$STAGE_DIR/steam/steamos/config/steam-bypass.toml"
cp -X "$REPO_ROOT"/steam/steamos/config/games/*.toml \
    "$STAGE_DIR/steam/steamos/config/games/"
cp -X "$REPO_ROOT/steam/steamos/packaging/systemd/qlinkd.service" \
    "$STAGE_DIR/steam/steamos/packaging/systemd/qlinkd.service"
cp -X \
    "$REPO_ROOT/steam/steamos/packaging/systemd/qlinkd.service.d/planning-only.conf.sample" \
    "$STAGE_DIR/steam/steamos/packaging/systemd/qlinkd.service.d/planning-only.conf.sample"
cp -X "$REPO_ROOT/steam/steamos/packaging/libexec/quantumlink-service-control" \
    "$STAGE_DIR/steam/steamos/packaging/libexec/quantumlink-service-control"
cp -X "$REPO_ROOT/steam/steamos/packaging/polkit/49-quantumlink-service-control.rules" \
    "$STAGE_DIR/steam/steamos/packaging/polkit/49-quantumlink-service-control.rules"

# The integration needs qlink-core as a Rust dependency. Do not link unused
# static and shared library artifacts inside the constrained Linux test VM.
python3 - "$STAGE_DIR/qlink-core/Cargo.toml" <<'PY'
from pathlib import Path
import sys

manifest = Path(sys.argv[1])
source = manifest.read_text()
old = 'crate-type = ["rlib", "staticlib", "cdylib"]'
if old not in source:
    raise SystemExit(f"expected qlink-core crate-type declaration in {manifest}")
manifest.write_text(source.replace(old, 'crate-type = ["rlib"]', 1))
PY

docker build \
    --file "$SCRIPT_DIR/docker/desktop-control-systemd.Dockerfile" \
    --tag "$IMAGE" \
    "$SCRIPT_DIR/docker"

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run --detach \
    --name "$CONTAINER" \
    --privileged \
    --cgroupns=private \
    --tmpfs /run \
    --tmpfs /run/lock \
    --volume "$STAGE_DIR:/workspace:ro" \
    --volume "$CARGO_REGISTRY_VOLUME:/usr/local/cargo/registry" \
    --volume "$CARGO_GIT_VOLUME:/usr/local/cargo/git" \
    --volume "$CARGO_TARGET_VOLUME:/tmp/quantumlink-target" \
    "$IMAGE" >/dev/null

attempts=30
while [ "$attempts" -gt 0 ]; do
    state="$(docker exec "$CONTAINER" systemctl is-system-running 2>/dev/null || true)"
    case "$state" in
        running|degraded) break ;;
    esac
    attempts=$((attempts - 1))
    sleep 1
done
[ "$attempts" -gt 0 ] || {
    docker logs "$CONTAINER" >&2 || true
    fail "systemd did not become ready"
}

docker exec \
    --env QLINK_INTEGRATION_ISOLATED=1 \
    --env QLINK_REPO_ROOT=/workspace \
    --env CARGO_TARGET_DIR=/tmp/quantumlink-target \
    --env CARGO_PROFILE_DEV_DEBUG=0 \
    --env QLINK_INTEGRATION_REPORT=/tmp/desktop-control-report.json \
    "$CONTAINER" \
    /bin/sh /workspace/steam/steamos/tests/linux-desktop-control-integration.sh

docker cp "$CONTAINER:/tmp/desktop-control-report.json" "$REPORT"
echo "Linux integration report: $REPORT"

docker exec \
    --env QLINK_INTEGRATION_ISOLATED=1 \
    --env QLINK_INTEGRATION_REPORT=/tmp/network-game-report.json \
    "$CONTAINER" \
    /bin/sh /workspace/steam/steamos/tests/linux-network-game-integration.sh

docker cp "$CONTAINER:/tmp/network-game-report.json" "$NETWORK_REPORT"
echo "Linux network-game report: $NETWORK_REPORT"
