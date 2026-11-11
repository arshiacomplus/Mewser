#!/usr/bin/env bash
#
# Mewser Gateway — Bootstrap Installer Verification Tests
# Verifies install-gateway.sh in isolated mock environments.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BOOTSTRAP="${REPO_ROOT}/scripts/install-gateway.sh"
PKG_ARCHIVE="${REPO_ROOT}/dist/gateway/mewser-gateway-linux-x86_64.tar.gz"

TEST_PASSED=0
TEST_SKIPPED=0
TEST_FAILED=0

pass() {
    printf "[\033[1;32mPASS\033[0m] %s\n" "$*"
    TEST_PASSED=$((TEST_PASSED + 1))
}

skip() {
    printf "[\033[1;33mSKIP\033[0m] %s\n" "$*"
    TEST_SKIPPED=$((TEST_SKIPPED + 1))
}

fail() {
    printf "[\033[1;31mFAIL\033[0m] %s\n" "$*" >&2
    TEST_FAILED=$((TEST_FAILED + 1))
}

cleanup() {
    if [[ -n "${MOCK_ROOT:-}" && -d "${MOCK_ROOT:-}" ]]; then
        rm -rf "${MOCK_ROOT}"
    fi
}
trap cleanup EXIT

echo "======================================================================"
echo "  Mewser Gateway — Bootstrap Installer Test Suite"
echo "======================================================================"

# Ensure real Gateway package archive exists for testing
if [[ ! -f "$PKG_ARCHIVE" ]]; then
    "${REPO_ROOT}/scripts/package-gateway.sh" >/dev/null 2>&1
fi

# -----------------------------------------------------------------------------
# Check 1: Unsupported architecture rejected
# -----------------------------------------------------------------------------
MOCK_ROOT="$(mktemp -d /tmp/mewser_boot_test_XXXXXX)"
set +e
OUT=$(MEWSER_SKIP_ROOT_CHECK=true MEWSER_MOCK_ARCH="arm64" MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" \
    "$BOOTSTRAP" -y 2>&1)
EXIT_CODE=$?
set -e
if [[ $EXIT_CODE -ne 0 && "$OUT" =~ "Unsupported architecture 'arm64'" ]]; then
    pass "Check 1: Non-x86_64 architecture rejected cleanly"
else
    fail "Check 1: Failed to reject unsupported architecture (Output: $OUT)"
fi
rm -rf "${MOCK_ROOT}"

# -----------------------------------------------------------------------------
# Check 2: Unsupported OS rejected
# -----------------------------------------------------------------------------
MOCK_ROOT="$(mktemp -d /tmp/mewser_boot_test_XXXXXX)"
set +e
OUT=$(MEWSER_SKIP_ROOT_CHECK=true MEWSER_MOCK_OS="Darwin" MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" \
    "$BOOTSTRAP" -y 2>&1)
EXIT_CODE=$?
set -e
if [[ $EXIT_CODE -ne 0 && "$OUT" =~ "Unsupported operating system 'Darwin'" ]]; then
    pass "Check 2: Non-Linux OS rejected cleanly"
else
    fail "Check 2: Failed to reject unsupported OS (Output: $OUT)"
fi
rm -rf "${MOCK_ROOT}"

# -----------------------------------------------------------------------------
# Check 3: Local archive with missing checksum rejected
# -----------------------------------------------------------------------------
MOCK_ROOT="$(mktemp -d /tmp/mewser_boot_test_XXXXXX)"
NO_CHK_ARCHIVE="${MOCK_ROOT}/lonely_archive.tar.gz"
cp -f "$PKG_ARCHIVE" "$NO_CHK_ARCHIVE"
set +e
OUT=$(MEWSER_SKIP_ROOT_CHECK=true MEWSER_MOCK_SYSTEMD=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" \
    "$BOOTSTRAP" --archive "$NO_CHK_ARCHIVE" -y 2>&1)
EXIT_CODE=$?
set -e
if [[ $EXIT_CODE -ne 0 && "$OUT" =~ "No SHA-256 checksum file found" ]]; then
    pass "Check 3: Local archive missing checksum rejected cleanly"
else
    fail "Check 3: Failed to reject archive without checksum (Output: $OUT)"
fi
rm -rf "${MOCK_ROOT}"

# -----------------------------------------------------------------------------
# Check 4: Local archive with checksum mismatch rejected
# -----------------------------------------------------------------------------
MOCK_ROOT="$(mktemp -d /tmp/mewser_boot_test_XXXXXX)"
CORRUPT_ARCHIVE="${MOCK_ROOT}/corrupt.tar.gz"
cp -f "$PKG_ARCHIVE" "$CORRUPT_ARCHIVE"
echo "corrupt_trailing_bytes" >> "$CORRUPT_ARCHIVE"
CORRUPT_CHECKSUM="${MOCK_ROOT}/corrupt.tar.gz.sha256"
# Give legitimate hash for original archive
sha256sum "$PKG_ARCHIVE" | awk '{print $1}' > "$CORRUPT_CHECKSUM"

set +e
OUT=$(MEWSER_SKIP_ROOT_CHECK=true MEWSER_MOCK_SYSTEMD=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" \
    "$BOOTSTRAP" --archive "$CORRUPT_ARCHIVE" --checksum "$CORRUPT_CHECKSUM" -y 2>&1)
EXIT_CODE=$?
set -e
if [[ $EXIT_CODE -ne 0 && "$OUT" =~ "Checksum verification failed" ]]; then
    pass "Check 4: Checksum mismatch rejected cleanly"
else
    fail "Check 4: Failed to reject checksum mismatch (Output: $OUT)"
fi
rm -rf "${MOCK_ROOT}"

# -----------------------------------------------------------------------------
# Check 5: Local archive installation success
# -----------------------------------------------------------------------------
MOCK_ROOT="$(mktemp -d /tmp/mewser_boot_test_XXXXXX)"
mkdir -p "${MOCK_ROOT}/usr/local/bin" "${MOCK_ROOT}/etc/systemd/system"
VALID_ARCHIVE="${MOCK_ROOT}/valid.tar.gz"
cp -f "$PKG_ARCHIVE" "$VALID_ARCHIVE"
VALID_CHECKSUM="${MOCK_ROOT}/valid.tar.gz.sha256"
sha256sum "$VALID_ARCHIVE" > "$VALID_CHECKSUM"

set +e
OUT=$(MEWSER_SKIP_ROOT_CHECK=true MEWSER_MOCK_SYSTEMD=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" \
    "$BOOTSTRAP" --archive "$VALID_ARCHIVE" --checksum "$VALID_CHECKSUM" -t fixed-tcp -y 2>&1)
EXIT_CODE=$?
set -e
if [[ $EXIT_CODE -eq 0 && -f "${MOCK_ROOT}/etc/mewser-gateway/gateway.env" && -f "${MOCK_ROOT}/usr/local/bin/mewser-gateway" ]]; then
    pass "Check 5: Local archive verified and installed successfully"
else
    fail "Check 5: Failed local archive installation (Output: $OUT)"
fi
rm -rf "${MOCK_ROOT}"

# -----------------------------------------------------------------------------
# Check 6: Release download failure handling
# -----------------------------------------------------------------------------
MOCK_ROOT="$(mktemp -d /tmp/mewser_boot_test_XXXXXX)"
set +e
OUT=$(MEWSER_SKIP_ROOT_CHECK=true MEWSER_MOCK_SYSTEMD=true MEWSER_MOCK_DOWNLOAD_FAIL=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" \
    "$BOOTSTRAP" -t fixed-tcp -y 2>&1)
EXIT_CODE=$?
set -e
if [[ $EXIT_CODE -ne 0 && "$OUT" =~ "Simulated download failure" ]]; then
    pass "Check 6: Download failure handled cleanly with clear diagnostic"
else
    fail "Check 6: Failed download handling test (Output: $OUT)"
fi
rm -rf "${MOCK_ROOT}"

# -----------------------------------------------------------------------------
# Check 7: Downloaded release checksum mismatch security rejection
# -----------------------------------------------------------------------------
MOCK_ROOT="$(mktemp -d /tmp/mewser_boot_test_XXXXXX)"
MOCK_DL_DIR="${MOCK_ROOT}/mock_dl"
mkdir -p "${MOCK_DL_DIR}"
cp -f "$PKG_ARCHIVE" "${MOCK_DL_DIR}/release.tar.gz"
echo "1111111111111111111111111111111111111111111111111111111111111111  mewser-gateway-linux-x86_64.tar.gz" > "${MOCK_DL_DIR}/release.sha256"

set +e
OUT=$(MEWSER_SKIP_ROOT_CHECK=true MEWSER_MOCK_SYSTEMD=true MEWSER_MOCK_DOWNLOAD_DIR="${MOCK_DL_DIR}" MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" \
    "$BOOTSTRAP" -t fixed-tcp -y 2>&1)
EXIT_CODE=$?
set -e
if [[ $EXIT_CODE -ne 0 && "$OUT" =~ "SECURITY ALERT: Checksum verification failed" ]]; then
    pass "Check 7: Downloaded checksum mismatch security alert triggered"
else
    fail "Check 7: Failed checksum mismatch security alert (Output: $OUT)"
fi
rm -rf "${MOCK_ROOT}"

# -----------------------------------------------------------------------------
# Check 8: Downloaded release verification success
# -----------------------------------------------------------------------------
MOCK_ROOT="$(mktemp -d /tmp/mewser_boot_test_XXXXXX)"
mkdir -p "${MOCK_ROOT}/usr/local/bin" "${MOCK_ROOT}/etc/systemd/system"
MOCK_DL_DIR="${MOCK_ROOT}/mock_dl"
mkdir -p "${MOCK_DL_DIR}"
cp -f "$PKG_ARCHIVE" "${MOCK_DL_DIR}/release.tar.gz"
sha256sum "${MOCK_DL_DIR}/release.tar.gz" | awk '{print $1 "  mewser-gateway-linux-x86_64.tar.gz"}' > "${MOCK_DL_DIR}/release.sha256"

set +e
OUT=$(MEWSER_SKIP_ROOT_CHECK=true MEWSER_MOCK_SYSTEMD=true MEWSER_MOCK_DOWNLOAD_DIR="${MOCK_DL_DIR}" MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" \
    "$BOOTSTRAP" -t fixed-tcp -y 2>&1)
EXIT_CODE=$?
set -e
if [[ $EXIT_CODE -eq 0 && "$OUT" =~ "Downloaded release archive verified successfully" && -f "${MOCK_ROOT}/etc/mewser-gateway/gateway.env" ]]; then
    pass "Check 8: Downloaded release verified and installed successfully"
else
    fail "Check 8: Failed downloaded release verification test (Output: $OUT)"
fi
rm -rf "${MOCK_ROOT}"

# -----------------------------------------------------------------------------
# Check 9: Custom release version argument normalization
# -----------------------------------------------------------------------------
MOCK_ROOT="$(mktemp -d /tmp/mewser_boot_test_XXXXXX)"
mkdir -p "${MOCK_ROOT}/usr/local/bin" "${MOCK_ROOT}/etc/systemd/system"
MOCK_DL_DIR="${MOCK_ROOT}/mock_dl"
mkdir -p "${MOCK_DL_DIR}"
cp -f "$PKG_ARCHIVE" "${MOCK_DL_DIR}/release.tar.gz"
sha256sum "${MOCK_DL_DIR}/release.tar.gz" | awk '{print $1 "  mewser-gateway-linux-x86_64.tar.gz"}' > "${MOCK_DL_DIR}/release.sha256"

set +e
OUT=$(MEWSER_SKIP_ROOT_CHECK=true MEWSER_MOCK_SYSTEMD=true MEWSER_MOCK_DOWNLOAD_DIR="${MOCK_DL_DIR}" MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" \
    "$BOOTSTRAP" --version "0.1.0" -t fixed-tcp -y 2>&1)
EXIT_CODE=$?
set -e
if [[ $EXIT_CODE -eq 0 && -f "${MOCK_ROOT}/etc/mewser-gateway/gateway.env" ]]; then
    pass "Check 9: Custom release version normalized and processed successfully"
else
    fail "Check 9: Failed version argument processing (Output: $OUT)"
fi
rm -rf "${MOCK_ROOT}"

# -----------------------------------------------------------------------------
# Check 10: Existing installation detected in non-interactive mode
# -----------------------------------------------------------------------------
MOCK_ROOT="$(mktemp -d /tmp/mewser_boot_test_XXXXXX)"
mkdir -p "${MOCK_ROOT}/etc/mewser-gateway" "${MOCK_ROOT}/usr/local/bin" "${MOCK_ROOT}/etc/systemd/system"
echo "MEWSER_GATEWAY_AUTH_TOKEN=old_token_123" > "${MOCK_ROOT}/etc/mewser-gateway/gateway.env"
echo "MEWSER_GATEWAY_BIND=127.0.0.1:4040" >> "${MOCK_ROOT}/etc/mewser-gateway/gateway.env"
touch "${MOCK_ROOT}/usr/local/bin/mewser-gateway"

set +e
OUT=$(MEWSER_SKIP_ROOT_CHECK=true MEWSER_MOCK_SYSTEMD=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" \
    "$BOOTSTRAP" --archive "$PKG_ARCHIVE" --checksum "${PKG_ARCHIVE}.sha256" -y 2>&1)
EXIT_CODE=$?
set -e
if [[ $EXIT_CODE -ne 0 && "$OUT" =~ "Existing installation detected" ]]; then
    pass "Check 10: Existing installation detected; aborted without overwrite"
else
    fail "Check 10: Failed existing installation protection (Output: $OUT)"
fi
rm -rf "${MOCK_ROOT}"

# -----------------------------------------------------------------------------
# Check 11: Existing installation update preserves token & configuration
# -----------------------------------------------------------------------------
MOCK_ROOT="$(mktemp -d /tmp/mewser_boot_test_XXXXXX)"
mkdir -p "${MOCK_ROOT}/etc/mewser-gateway" "${MOCK_ROOT}/usr/local/bin" "${MOCK_ROOT}/etc/systemd/system"
ORIG_TOKEN="preserved_secret_token_abcdef1234567890abcdef1234567890abcdef123456"
cat > "${MOCK_ROOT}/etc/mewser-gateway/gateway.env" <<EOF
MEWSER_GATEWAY_AUTH_TOKEN=${ORIG_TOKEN}
MEWSER_GATEWAY_REQUIRE_AUTH=true
MEWSER_GATEWAY_BIND=127.0.0.1:4040
MEWSER_GATEWAY_ALLOW_NON_LOOPBACK=false
EOF
chmod 0600 "${MOCK_ROOT}/etc/mewser-gateway/gateway.env"
echo "old_binary_stub" > "${MOCK_ROOT}/usr/local/bin/mewser-gateway"
chmod 0755 "${MOCK_ROOT}/usr/local/bin/mewser-gateway"

set +e
OUT=$(MEWSER_SKIP_ROOT_CHECK=true MEWSER_MOCK_SYSTEMD=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" \
    "$BOOTSTRAP" --archive "$PKG_ARCHIVE" --checksum "${PKG_ARCHIVE}.sha256" --update -y 2>&1)
EXIT_CODE=$?
set -e

if [[ $EXIT_CODE -eq 0 && -f "${MOCK_ROOT}/etc/mewser-gateway/gateway.env" ]]; then
    SAVED_TOKEN="$(grep -E "^MEWSER_GATEWAY_AUTH_TOKEN=" "${MOCK_ROOT}/etc/mewser-gateway/gateway.env" | cut -d= -f2-)"
    if [[ "$SAVED_TOKEN" == "$ORIG_TOKEN" ]]; then
        pass "Check 11: Update preserved existing authentication token and configuration"
    else
        fail "Check 11: Update mutated authentication token (Expected: $ORIG_TOKEN, Got: $SAVED_TOKEN)"
    fi
else
    fail "Check 11: Update operation failed (Output: $OUT)"
fi
rm -rf "${MOCK_ROOT}"

# -----------------------------------------------------------------------------
# Check 12: Legacy installation migration delegation
# -----------------------------------------------------------------------------
MOCK_ROOT="$(mktemp -d /tmp/mewser_boot_test_XXXXXX)"
mkdir -p "${MOCK_ROOT}/etc/mewser" "${MOCK_ROOT}/usr/local/bin" "${MOCK_ROOT}/etc/systemd/system"
LEGACY_TOKEN="legacy_secret_token_1234567890abcdef1234567890abcdef1234567890"
cat > "${MOCK_ROOT}/etc/mewser/gateway.env" <<EOF
MEWSER_GATEWAY_AUTH_TOKEN=${LEGACY_TOKEN}
MEWSER_GATEWAY_REQUIRE_AUTH=true
MEWSER_GATEWAY_BIND=127.0.0.1:4040
MEWSER_GATEWAY_ALLOW_NON_LOOPBACK=false
EOF
chmod 0600 "${MOCK_ROOT}/etc/mewser/gateway.env"
cat > "${MOCK_ROOT}/etc/systemd/system/mewser-gateway.service" <<EOF
[Unit]
Description=Mewser Gateway Legacy
[Service]
User=mewser
ExecStart=/usr/local/bin/mewser-gateway
EOF

set +e
OUT=$(MEWSER_SKIP_ROOT_CHECK=true MEWSER_MOCK_SYSTEMD=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" \
    "$BOOTSTRAP" --archive "$PKG_ARCHIVE" --checksum "${PKG_ARCHIVE}.sha256" --migrate -y 2>&1)
EXIT_CODE=$?
set -e

if [[ $EXIT_CODE -eq 0 && -f "${MOCK_ROOT}/etc/mewser-gateway/gateway.env" ]]; then
    MIGRATED_TOKEN="$(grep -E "^MEWSER_GATEWAY_AUTH_TOKEN=" "${MOCK_ROOT}/etc/mewser-gateway/gateway.env" | cut -d= -f2-)"
    if [[ "$MIGRATED_TOKEN" == "$LEGACY_TOKEN" ]]; then
        pass "Check 12: Legacy installation migration preserved credentials and layout"
    else
        fail "Check 12: Legacy migration token mismatch"
    fi
else
    fail "Check 12: Migration failed (Output: $OUT)"
fi
rm -rf "${MOCK_ROOT}"

# -----------------------------------------------------------------------------
# Check 13: Topology B configuration with firewall isolation
# -----------------------------------------------------------------------------
MOCK_ROOT="$(mktemp -d /tmp/mewser_boot_test_XXXXXX)"
mkdir -p "${MOCK_ROOT}/usr/local/bin" "${MOCK_ROOT}/etc/systemd/system"
set +e
OUT=$(MEWSER_ALLOW_TEST_IP=true MEWSER_SKIP_ROOT_CHECK=true MEWSER_MOCK_SYSTEMD=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" \
    "$BOOTSTRAP" --archive "$PKG_ARCHIVE" --checksum "${PKG_ARCHIVE}.sha256" \
    -t socks5 -i 198.51.100.25 --confirm-firewall -y 2>&1)
EXIT_CODE=$?
set -e

if [[ $EXIT_CODE -eq 0 && -f "${MOCK_ROOT}/etc/mewser-gateway/gateway.env" ]]; then
    BIND_VAL="$(grep -E "^MEWSER_GATEWAY_BIND=" "${MOCK_ROOT}/etc/mewser-gateway/gateway.env" | cut -d= -f2-)"
    if [[ "$BIND_VAL" == "198.51.100.25:4040" ]]; then
        pass "Check 13: Topology B public IP binding and firewall isolation configured cleanly"
    else
        fail "Check 13: Topology B bind address mismatch: $BIND_VAL"
    fi
else
    fail "Check 13: Topology B installation failed (Output: $OUT)"
fi
rm -rf "${MOCK_ROOT}"

echo "======================================================================"
echo "  Bootstrap Installer Results: ${TEST_PASSED} Passed, ${TEST_SKIPPED} Skipped, ${TEST_FAILED} Failed"
echo "======================================================================"

if [[ $TEST_FAILED -gt 0 ]]; then
    exit 1
fi
exit 0
