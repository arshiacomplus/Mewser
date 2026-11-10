#!/usr/bin/env bash
#
# Mewser Desktop Release Packaging Script
# Assembles Debian package (.deb) and generic Linux archive (.tar.gz)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

DIST_DIR="${REPO_ROOT}/dist/desktop"
PACKAGING_SRC="${REPO_ROOT}/packaging/desktop"

VERSION_INPUT="${1:-${MEWSER_VERSION:-}}"
if [[ -z "$VERSION_INPUT" ]]; then
    VERSION_INPUT="$(grep -m1 '^version = ' "${REPO_ROOT}/crates/mewser-desktop/Cargo.toml" | cut -d'"' -f2)"
fi

# Strip leading 'v' if present (e.g. v0.1.0 -> 0.1.0)
VERSION="${VERSION_INPUT#v}"

# Validate SemVer format: X.Y.Z or X.Y.Z-prerelease
SEMVER_REGEX='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'
if [[ ! "$VERSION" =~ $SEMVER_REGEX ]]; then
    echo "ERROR: Version '${VERSION_INPUT}' is not a valid Semantic Version (expected format: X.Y.Z or vX.Y.Z)" >&2
    exit 1
fi

CARGO_VERSION="$(grep -m1 '^version = ' "${REPO_ROOT}/crates/mewser-desktop/Cargo.toml" | cut -d'"' -f2)"
if [[ "$VERSION" != "$CARGO_VERSION" ]]; then
    echo "ERROR: Specified release version '${VERSION}' does not match crates/mewser-desktop/Cargo.toml version ('${CARGO_VERSION}')." >&2
    echo "Ensure Cargo.toml version is updated before tagging release." >&2
    exit 1
fi

ARCH="amd64"

echo "======================================================================"
echo "  Mewser Desktop Release Packaging (v${VERSION})"
echo "======================================================================"

# 1. Locate release binary
BIN_CANDIDATE="${REPO_ROOT}/target/x86_64-unknown-linux-gnu/release/mewser-desktop"
if [[ ! -f "$BIN_CANDIDATE" ]]; then
    BIN_CANDIDATE="${REPO_ROOT}/target/release/mewser-desktop"
fi

if [[ ! -f "$BIN_CANDIDATE" ]]; then
    echo "ERROR: mewser-desktop binary not found at:" >&2
    echo "  ${REPO_ROOT}/target/x86_64-unknown-linux-gnu/release/mewser-desktop or" >&2
    echo "  ${REPO_ROOT}/target/release/mewser-desktop" >&2
    echo "Run 'cargo build --release -p mewser-desktop' first." >&2
    exit 1
fi

echo "[INFO] Using Desktop binary: ${BIN_CANDIDATE}"
mkdir -p "${DIST_DIR}"

# 2. Build Debian package (.deb)
echo "[INFO] Building Debian package..."
STAGING_DEB="$(mktemp -d /tmp/mewser_deb_staging_XXXXXX)"
trap 'rm -rf "${STAGING_DEB}"' EXIT

mkdir -p "${STAGING_DEB}/DEBIAN"
mkdir -p "${STAGING_DEB}/usr/bin"
mkdir -p "${STAGING_DEB}/usr/share/applications"
mkdir -p "${STAGING_DEB}/usr/share/icons/hicolor/scalable/apps"
mkdir -p "${STAGING_DEB}/usr/share/doc/mewser-desktop"

cat > "${STAGING_DEB}/DEBIAN/control" <<EOF
Package: mewser-desktop
Version: ${VERSION}
Section: web
Priority: optional
Architecture: ${ARCH}
Maintainer: Mewser Developers <https://github.com/arshiacomplus/Mewser>
Depends: libc6 (>= 2.34), libgtk-3-0 (>= 3.24.0) | libgtk-3-0t64 (>= 3.24.0), libwebkit2gtk-4.1-0 (>= 2.40.0), libsoup-3.0-0 (>= 3.0.0)
Homepage: https://github.com/arshiacomplus/Mewser
Description: Mewser Resilient Browser for Linux
 Mewser is a dual-mode browser featuring standard web rendering and a resilient
 server-side text extraction mode over encrypted DNS tunnels.
EOF

cp -f "${BIN_CANDIDATE}" "${STAGING_DEB}/usr/bin/mewser-desktop"
chmod 0755 "${STAGING_DEB}/usr/bin/mewser-desktop"

cp -f "${PACKAGING_SRC}/mewser-desktop.desktop" "${STAGING_DEB}/usr/share/applications/mewser-desktop.desktop"
chmod 0644 "${STAGING_DEB}/usr/share/applications/mewser-desktop.desktop"

cp -f "${PACKAGING_SRC}/mewser-desktop.svg" "${STAGING_DEB}/usr/share/icons/hicolor/scalable/apps/mewser-desktop.svg"
chmod 0644 "${STAGING_DEB}/usr/share/icons/hicolor/scalable/apps/mewser-desktop.svg"

cp -f "${PACKAGING_SRC}/README.md" "${STAGING_DEB}/usr/share/doc/mewser-desktop/README.md"
chmod 0644 "${STAGING_DEB}/usr/share/doc/mewser-desktop/README.md"

cp -f "${REPO_ROOT}/LICENSE" "${STAGING_DEB}/usr/share/doc/mewser-desktop/copyright"
chmod 0644 "${STAGING_DEB}/usr/share/doc/mewser-desktop/copyright"

DEB_NAME="mewser-desktop_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "${STAGING_DEB}" "${DIST_DIR}/${DEB_NAME}"
echo "[OK] Created Debian package: ${DIST_DIR}/${DEB_NAME}"

# 3. Build Generic Linux Archive (.tar.gz)
echo "[INFO] Building Generic Linux distribution archive..."
TAR_STAGING="${DIST_DIR}/mewser-desktop-linux-x86_64"
rm -rf "${TAR_STAGING}"
mkdir -p "${TAR_STAGING}"

cp -f "${BIN_CANDIDATE}" "${TAR_STAGING}/mewser-desktop"
chmod 0755 "${TAR_STAGING}/mewser-desktop"

cp -f "${PACKAGING_SRC}/mewser-desktop.desktop" "${TAR_STAGING}/mewser-desktop.desktop"
chmod 0644 "${TAR_STAGING}/mewser-desktop.desktop"

cp -f "${PACKAGING_SRC}/mewser-desktop.svg" "${TAR_STAGING}/mewser-desktop.svg"
chmod 0644 "${TAR_STAGING}/mewser-desktop.svg"

cp -f "${PACKAGING_SRC}/README.md" "${TAR_STAGING}/README.md"
chmod 0644 "${TAR_STAGING}/README.md"

cp -f "${REPO_ROOT}/LICENSE" "${TAR_STAGING}/LICENSE"
chmod 0644 "${TAR_STAGING}/LICENSE"

# Installer helper for generic archive
cat > "${TAR_STAGING}/install.sh" << 'INSTALL_EOF'
#!/usr/bin/env bash
set -euo pipefail

PREFIX="/usr/local"
if [[ "${1:-}" == "--user" || $EUID -ne 0 ]]; then
    PREFIX="${HOME}/.local"
fi

echo "Installing Mewser Desktop to ${PREFIX}..."
mkdir -p "${PREFIX}/bin"
mkdir -p "${PREFIX}/share/applications"
mkdir -p "${PREFIX}/share/icons/hicolor/scalable/apps"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp -f "${SCRIPT_DIR}/mewser-desktop" "${PREFIX}/bin/mewser-desktop"
chmod 0755 "${PREFIX}/bin/mewser-desktop"

cp -f "${SCRIPT_DIR}/mewser-desktop.desktop" "${PREFIX}/share/applications/mewser-desktop.desktop"
chmod 0644 "${PREFIX}/share/applications/mewser-desktop.desktop"

cp -f "${SCRIPT_DIR}/mewser-desktop.svg" "${PREFIX}/share/icons/hicolor/scalable/apps/mewser-desktop.svg"
chmod 0644 "${PREFIX}/share/icons/hicolor/scalable/apps/mewser-desktop.svg"

# Install uninstaller helper
cat > "${PREFIX}/bin/mewser-desktop-uninstall" << UNINSTALL_SCRIPT
#!/usr/bin/env bash
rm -f "${PREFIX}/bin/mewser-desktop"
rm -f "${PREFIX}/bin/mewser-desktop-uninstall"
rm -f "${PREFIX}/share/applications/mewser-desktop.desktop"
rm -f "${PREFIX}/share/icons/hicolor/scalable/apps/mewser-desktop.svg"
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "${PREFIX}/share/applications" 2>/dev/null || true
command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -f -t "${PREFIX}/share/icons/hicolor" 2>/dev/null || true
echo "Mewser Desktop uninstalled successfully from ${PREFIX}."
UNINSTALL_SCRIPT
chmod 0755 "${PREFIX}/bin/mewser-desktop-uninstall"

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "${PREFIX}/share/applications" 2>/dev/null || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t "${PREFIX}/share/icons/hicolor" 2>/dev/null || true
fi

echo "Mewser Desktop installed successfully to ${PREFIX}."
echo "Launch with: mewser-desktop"
INSTALL_EOF
chmod 0755 "${TAR_STAGING}/install.sh"

cat > "${TAR_STAGING}/uninstall.sh" << 'UNINSTALL_EOF'
#!/usr/bin/env bash
set -euo pipefail
PREFIX="/usr/local"
if [[ "${1:-}" == "--user" || $EUID -ne 0 ]]; then
    PREFIX="${HOME}/.local"
fi
if [[ -x "${PREFIX}/bin/mewser-desktop-uninstall" ]]; then
    "${PREFIX}/bin/mewser-desktop-uninstall"
else
    rm -f "${PREFIX}/bin/mewser-desktop"
    rm -f "${PREFIX}/share/applications/mewser-desktop.desktop"
    rm -f "${PREFIX}/share/icons/hicolor/scalable/apps/mewser-desktop.svg"
    echo "Removed Mewser Desktop files from ${PREFIX}."
fi
UNINSTALL_EOF
chmod 0755 "${TAR_STAGING}/uninstall.sh"

(
    cd "${TAR_STAGING}"
    sha256sum install.sh LICENSE mewser-desktop mewser-desktop.desktop mewser-desktop.svg README.md uninstall.sh > SHA256SUMS
)

TAR_NAME="mewser-desktop-${VERSION}-linux-x86_64.tar.gz"
TAR_ALIAS="mewser-desktop-linux-x86_64.tar.gz"
tar -czf "${DIST_DIR}/${TAR_NAME}" -C "${DIST_DIR}" "mewser-desktop-linux-x86_64"
cp -f "${DIST_DIR}/${TAR_NAME}" "${DIST_DIR}/${TAR_ALIAS}"
echo "[OK] Created generic archive: ${DIST_DIR}/${TAR_NAME} (alias: ${TAR_ALIAS})"

# 4. Generate SHA256 Checksums
echo "[INFO] Generating SHA256 checksums..."
(
    cd "${DIST_DIR}"
    sha256sum "${DEB_NAME}" > "${DEB_NAME}.sha256"
    sha256sum "${TAR_NAME}" > "${TAR_NAME}.sha256"
    sha256sum "${TAR_ALIAS}" > "${TAR_ALIAS}.sha256"
    sha256sum "${DEB_NAME}" "${TAR_NAME}" "${TAR_ALIAS}" > SHA256SUMS
    sha256sum -c SHA256SUMS
)

echo "======================================================================"
echo "  Mewser Desktop Release Packaging Complete"
echo "  Debian Package : ${DIST_DIR}/${DEB_NAME}"
echo "  Generic Archive: ${DIST_DIR}/${TAR_NAME}"
echo "  Archive Alias  : ${DIST_DIR}/${TAR_ALIAS}"
echo "======================================================================"
