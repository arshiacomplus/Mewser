#!/usr/bin/env bash
#
# Mewser Gateway Release Packaging Script
# Assembles dist/gateway/linux-x86_64 and packages mewser-gateway-linux-x86_64.tar.gz
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PKG_DIR="${REPO_ROOT}/dist/gateway/linux-x86_64"
DIST_DIR="${REPO_ROOT}/dist/gateway"

VERSION_INPUT="${1:-${MEWSER_VERSION:-}}"
if [[ -z "$VERSION_INPUT" ]]; then
    VERSION_INPUT="$(grep -m1 '^version = ' "${REPO_ROOT}/crates/mewser-gateway/Cargo.toml" | cut -d'"' -f2)"
fi

# Strip leading 'v' if present (e.g. v0.1.0 -> 0.1.0)
VERSION="${VERSION_INPUT#v}"

# Validate SemVer format: X.Y.Z or X.Y.Z-prerelease
SEMVER_REGEX='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'
if [[ ! "$VERSION" =~ $SEMVER_REGEX ]]; then
    echo "ERROR: Version '${VERSION_INPUT}' is not a valid Semantic Version (expected format: X.Y.Z or vX.Y.Z)" >&2
    exit 1
fi

CARGO_VERSION="$(grep -m1 '^version = ' "${REPO_ROOT}/crates/mewser-gateway/Cargo.toml" | cut -d'"' -f2)"
if [[ "$VERSION" != "$CARGO_VERSION" ]]; then
    echo "ERROR: Specified release version '${VERSION}' does not match crates/mewser-gateway/Cargo.toml version ('${CARGO_VERSION}')." >&2
    echo "Ensure Cargo.toml version is updated before tagging release." >&2
    exit 1
fi

echo "======================================================================"
echo "  Mewser Gateway Release Packaging (v${VERSION})"
echo "======================================================================"

# 1. Locate release binary
BIN_CANDIDATE="${REPO_ROOT}/target/x86_64-unknown-linux-gnu/release/mewser-gateway"
if [[ ! -f "$BIN_CANDIDATE" ]]; then
    BIN_CANDIDATE="${REPO_ROOT}/target/release/mewser-gateway"
fi

if [[ ! -f "$BIN_CANDIDATE" ]]; then
    echo "ERROR: mewser-gateway binary not found at:" >&2
    echo "  ${REPO_ROOT}/target/x86_64-unknown-linux-gnu/release/mewser-gateway or" >&2
    echo "  ${REPO_ROOT}/target/release/mewser-gateway" >&2
    echo "Run 'cargo build --release -p mewser-gateway' first." >&2
    exit 1
fi

echo "[INFO] Using Gateway binary: ${BIN_CANDIDATE}"
mkdir -p "${PKG_DIR}" "${DIST_DIR}"

# 2. Copy artifacts to packaging directory
cp -f "${BIN_CANDIDATE}" "${PKG_DIR}/mewser-gateway"
chmod 0755 "${PKG_DIR}/mewser-gateway"

cp -f "${REPO_ROOT}/scripts/deploy-gateway.sh" "${PKG_DIR}/deploy-gateway.sh"
chmod 0755 "${PKG_DIR}/deploy-gateway.sh"

cp -f "${REPO_ROOT}/packaging/gateway/systemd/mewser-gateway.service" "${PKG_DIR}/mewser-gateway.service"
chmod 0644 "${PKG_DIR}/mewser-gateway.service"

cp -f "${REPO_ROOT}/packaging/gateway/environment/gateway.env.example" "${PKG_DIR}/gateway.env.example"
chmod 0644 "${PKG_DIR}/gateway.env.example"

cp -f "${REPO_ROOT}/LICENSE" "${PKG_DIR}/LICENSE"
chmod 0644 "${PKG_DIR}/LICENSE"

# Copy package README and build metadata from source
cp -f "${REPO_ROOT}/packaging/gateway/README.md" "${PKG_DIR}/README.md"
chmod 0644 "${PKG_DIR}/README.md"

cp -f "${REPO_ROOT}/packaging/gateway/build-metadata.json" "${PKG_DIR}/build-metadata.json"
chmod 0644 "${PKG_DIR}/build-metadata.json"

# Ensure version in build-metadata.json matches release version
sed -i -E 's/"version": "[^"]+"/"version": "'"${VERSION}"'"/' "${PKG_DIR}/build-metadata.json"

# 3. Regenerate SHA256SUMS inside package directory
echo "[INFO] Generating package SHA256SUMS..."
(
    cd "${PKG_DIR}"
    sha256sum build-metadata.json deploy-gateway.sh gateway.env.example LICENSE mewser-gateway mewser-gateway.service README.md > SHA256SUMS
    sha256sum -c SHA256SUMS
)

# 4. Create release tarball (both versioned and unversioned alias)
TARBALL_VERSIONED="${DIST_DIR}/mewser-gateway-${VERSION}-linux-x86_64.tar.gz"
TARBALL_ALIAS="${DIST_DIR}/mewser-gateway-linux-x86_64.tar.gz"
echo "[INFO] Packaging ${TARBALL_VERSIONED}..."
tar -czf "${TARBALL_VERSIONED}" -C "${PKG_DIR}" .
cp -f "${TARBALL_VERSIONED}" "${TARBALL_ALIAS}"

# 5. Generate and verify archive checksums
(
    cd "${DIST_DIR}"
    sha256sum "mewser-gateway-${VERSION}-linux-x86_64.tar.gz" > "mewser-gateway-${VERSION}-linux-x86_64.tar.gz.sha256"
    sha256sum "mewser-gateway-linux-x86_64.tar.gz" > "mewser-gateway-linux-x86_64.tar.gz.sha256"
    sha256sum "mewser-gateway-${VERSION}-linux-x86_64.tar.gz" "mewser-gateway-linux-x86_64.tar.gz" > SHA256SUMS
    sha256sum -c SHA256SUMS
)

echo "======================================================================"
echo "  Gateway Release Packaging Complete"
echo "  Archive      : ${TARBALL_VERSIONED}"
echo "  Archive Alias: ${TARBALL_ALIAS}"
echo "  Checksum     : $(cat "${DIST_DIR}/mewser-gateway-linux-x86_64.tar.gz.sha256")"
echo "======================================================================"
