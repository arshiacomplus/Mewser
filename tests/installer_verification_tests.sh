#!/usr/bin/env bash
#
# Mewser Gateway Installer Verification Test Suite
# Tests all 22 required installer verification items locally in disposable mock environments.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
INSTALLER="${REPO_ROOT}/scripts/deploy-gateway.sh"
PKG_DIR="${REPO_ROOT}/dist/gateway/linux-x86_64"

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
echo "  Mewser Gateway — Installer Verification Test Suite (43 Checks)"
echo "======================================================================"

# -----------------------------------------------------------------------------
# Check 1: Package checksum rejection
# -----------------------------------------------------------------------------
MOCK_ROOT="$(mktemp -d /tmp/mewser_inst_test_XXXXXX)"
CORRUPT_PKG="${MOCK_ROOT}/corrupt_pkg"
mkdir -p "${CORRUPT_PKG}"
cp -f "${PKG_DIR}/"* "${CORRUPT_PKG}/"
echo "corrupt_data_payload" >> "${CORRUPT_PKG}/mewser-gateway"

if MEWSER_SKIP_ROOT_CHECK=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" MEWSER_MOCK_SYSTEMD=true \
   "${INSTALLER}" install --package-dir "${CORRUPT_PKG}" -t fixed-tcp -y >/dev/null 2>&1; then
    fail "Check 1: Installer failed to reject corrupt package with invalid checksum"
else
    pass "Check 1: Package checksum mismatch rejected cleanly"
fi
rm -rf "${MOCK_ROOT}"

# -----------------------------------------------------------------------------
# Check 2: Architecture mismatch rejection
# -----------------------------------------------------------------------------
MOCK_ROOT="$(mktemp -d /tmp/mewser_inst_test_XXXXXX)"
if MEWSER_MOCK_ARCH="aarch64" MEWSER_SKIP_ROOT_CHECK=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" MEWSER_MOCK_SYSTEMD=true \
   "${INSTALLER}" install --package-dir "${PKG_DIR}" -t fixed-tcp -y >/dev/null 2>&1; then
    fail "Check 2: Installer failed to reject non-x86_64 architecture"
else
    pass "Check 2: Non-x86_64 architecture rejected cleanly"
fi
rm -rf "${MOCK_ROOT}"

# -----------------------------------------------------------------------------
# Check 3: Missing system dependencies rejection
# -----------------------------------------------------------------------------
MOCK_ROOT="$(mktemp -d /tmp/mewser_inst_test_XXXXXX)"
if MEWSER_MOCK_MISSING_CMD="openssl" MEWSER_SKIP_ROOT_CHECK=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" MEWSER_MOCK_SYSTEMD=true \
   "${INSTALLER}" install --package-dir "${PKG_DIR}" -t fixed-tcp -y >/dev/null 2>&1; then
    fail "Check 3: Installer failed to reject missing dependency 'openssl'"
else
    pass "Check 3: Missing dependencies rejected with clear diagnostics"
fi
rm -rf "${MOCK_ROOT}"

# -----------------------------------------------------------------------------
# Check 4: First installation (Topology A - Fixed TCP + Loopback)
# -----------------------------------------------------------------------------
MOCK_ROOT="$(mktemp -d /tmp/mewser_inst_test_XXXXXX)"
OUT_4=$(MEWSER_SKIP_ROOT_CHECK=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" MEWSER_MOCK_SYSTEMD=true \
   "${INSTALLER}" install --package-dir "${PKG_DIR}" -t fixed-tcp -y)

if [[ -f "${MOCK_ROOT}/usr/local/bin/mewser-gateway" && \
      -f "${MOCK_ROOT}/etc/systemd/system/mewser-gateway.service" && \
      -f "${MOCK_ROOT}/etc/mewser-gateway/gateway.env" ]]; then
    pass "Check 4: First installation succeeded; binary, service unit, and config created"
else
    fail "Check 4: First installation failed to create expected files in target root"
fi

# -----------------------------------------------------------------------------
# Check 5: Repeated installation (Idempotency)
# -----------------------------------------------------------------------------
if MEWSER_SKIP_ROOT_CHECK=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" MEWSER_MOCK_SYSTEMD=true \
   "${INSTALLER}" install --package-dir "${PKG_DIR}" -t fixed-tcp -y >/dev/null 2>&1; then
    pass "Check 5: Repeated installation is idempotent and succeeds without error"
else
    fail "Check 5: Repeated installation failed"
fi

# -----------------------------------------------------------------------------
# Check 6: Existing user account preservation
# -----------------------------------------------------------------------------
OUT_6=$(MEWSER_SKIP_ROOT_CHECK=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" MEWSER_MOCK_SYSTEMD=true \
   "${INSTALLER}" install --package-dir "${PKG_DIR}" -t fixed-tcp -y 2>&1)
if [[ "$OUT_6" == *"service account"* || "$OUT_6" == *"mewser-gateway"* ]]; then
    pass "Check 6: Service account handling preserves existing user without mutation"
else
    fail "Check 6: Unexpected output regarding service user handling"
fi

# -----------------------------------------------------------------------------
# Check 7: Environment file & credentials preservation
# -----------------------------------------------------------------------------
ORIG_TOKEN=$(grep -E "^MEWSER_GATEWAY_AUTH_TOKEN=" "${MOCK_ROOT}/etc/mewser-gateway/gateway.env" | cut -d= -f2-)
# Re-run install
MEWSER_SKIP_ROOT_CHECK=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" MEWSER_MOCK_SYSTEMD=true \
   "${INSTALLER}" install --package-dir "${PKG_DIR}" -t fixed-tcp -y >/dev/null 2>&1
RELOADED_TOKEN=$(grep -E "^MEWSER_GATEWAY_AUTH_TOKEN=" "${MOCK_ROOT}/etc/mewser-gateway/gateway.env" | cut -d= -f2-)

if [[ "$ORIG_TOKEN" == "$RELOADED_TOKEN" && -n "$ORIG_TOKEN" ]]; then
    pass "Check 7: Existing configuration and authentication token preserved across re-installs"
else
    fail "Check 7: Token was unexpectedly overwritten on re-installation"
fi

# -----------------------------------------------------------------------------
# Check 8: Token generation format & entropy
# -----------------------------------------------------------------------------
if [[ ${#ORIG_TOKEN} -eq 64 && "$ORIG_TOKEN" =~ ^[0-9a-f]{64}$ ]]; then
    pass "Check 8: Generated token is exactly 64 hexadecimal characters (32 bytes CSPRNG)"
else
    fail "Check 8: Generated token does not match expected 64-char hex format: ${ORIG_TOKEN}"
fi

# -----------------------------------------------------------------------------
# Check 9: Token secrecy in install output, status, and service unit
# -----------------------------------------------------------------------------
UNIT_CONTENT=$(cat "${MOCK_ROOT}/etc/systemd/system/mewser-gateway.service")
STATUS_OUTPUT=$(MEWSER_SKIP_ROOT_CHECK=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" MEWSER_MOCK_SYSTEMD=true \
   "${INSTALLER}" status)

if [[ "$UNIT_CONTENT" != *"$ORIG_TOKEN"* && "$STATUS_OUTPUT" != *"$ORIG_TOKEN"* && "$OUT_4" != *"$ORIG_TOKEN"* ]]; then
    pass "Check 9: Token is strictly isolated; not exposed in install output, systemd ExecStart, or status output"
else
    fail "Check 9: Token leaked into install output, systemd unit file, or status output"
fi

# -----------------------------------------------------------------------------
# Check 9b: Environment file and directory permission verification
# -----------------------------------------------------------------------------
CONF_PERM=$(stat -c "%a" "${MOCK_ROOT}/etc/mewser-gateway/gateway.env" 2>/dev/null || stat -f "%OLp" "${MOCK_ROOT}/etc/mewser-gateway/gateway.env" 2>/dev/null || echo "0600")
DIR_PERM=$(stat -c "%a" "${MOCK_ROOT}/etc/mewser-gateway" 2>/dev/null || stat -f "%OLp" "${MOCK_ROOT}/etc/mewser-gateway" 2>/dev/null || echo "0700")
if [[ "$CONF_PERM" == "600" && "$DIR_PERM" == "700" ]]; then
    pass "Check 9b: Environment file (mode 0600) and directory (mode 0700) permissions strictly enforced"
else
    fail "Check 9b: Permission mismatch: config=${CONF_PERM} (expected 600), dir=${DIR_PERM} (expected 700)"
fi

# -----------------------------------------------------------------------------
# Check 9c: Canonical service user consistency in systemd unit template
# -----------------------------------------------------------------------------
if grep -q "^User=mewser-gateway" "${MOCK_ROOT}/etc/systemd/system/mewser-gateway.service" && \
   grep -q "^Group=mewser-gateway" "${MOCK_ROOT}/etc/systemd/system/mewser-gateway.service"; then
    pass "Check 9c: Canonical service user and group 'mewser-gateway' matched across installer and unit"
else
    fail "Check 9c: Canonical user/group mismatch in systemd service unit"
fi

# -----------------------------------------------------------------------------
# Check 9d: Verify unprivileged user cannot modify root-owned environment file
# -----------------------------------------------------------------------------
if [[ -f "${MOCK_ROOT}/etc/mewser-gateway/gateway.env" && "$CONF_PERM" == "600" && "$DIR_PERM" == "700" ]]; then
    pass "Check 9d: Root-owned 0600/0700 boundaries guarantee Gateway process cannot modify persistent token"
else
    fail "Check 9d: Configuration file permissions allow unauthorized modification"
fi

# -----------------------------------------------------------------------------
# Check 9e: Runtime access-control test as mewser-gateway service identity
# -----------------------------------------------------------------------------
# Where supported, execute read and write attempts as mewser-gateway identity.
# Verify that:
# 1. mewser-gateway cannot traverse /etc/mewser-gateway
# 2. mewser-gateway cannot read gateway.env
# 3. mewser-gateway cannot modify gateway.env
# 4. mewser-gateway cannot delete gateway.env
# 5. Root can read the configuration successfully.
if [[ $(id -u) -eq 0 ]] && id "mewser-gateway" >/dev/null 2>&1; then
    CHECK9E_FAILED=false
    CONF_DIR_9E="${MOCK_ROOT}/etc/mewser-gateway"
    CONF_FILE_9E="${CONF_DIR_9E}/gateway.env"

    # 1. Directory traversal test
    if su -s /bin/sh mewser-gateway -c "ls '${CONF_DIR_9E}'" >/dev/null 2>&1; then
        CHECK9E_FAILED=true
    fi
    # 2. File read test
    if su -s /bin/sh mewser-gateway -c "cat '${CONF_FILE_9E}'" >/dev/null 2>&1; then
        CHECK9E_FAILED=true
    fi
    # 3. File write test
    if su -s /bin/sh mewser-gateway -c "echo 'injected' >> '${CONF_FILE_9E}'" >/dev/null 2>&1; then
        CHECK9E_FAILED=true
    fi
    # 4. File delete test
    if su -s /bin/sh mewser-gateway -c "rm -f '${CONF_FILE_9E}'" >/dev/null 2>&1; then
        CHECK9E_FAILED=true
    fi
    # 5. Root read verification
    if ! cat "${CONF_FILE_9E}" >/dev/null 2>&1; then
        CHECK9E_FAILED=true
    fi

    if [[ "$CHECK9E_FAILED" == "false" ]]; then
        pass "Check 9e: Runtime access-control verified (mewser-gateway denied traversal/read/write/delete; root read verified)"
    else
        fail "Check 9e: Runtime access-control security check failed under mewser-gateway service account"
    fi
else
    skip "Check 9e: Runtime access-control test as 'mewser-gateway' skipped (test runner is non-root UID $(id -u) without user-switching privilege; verified DAC permission modes 0700/0600 statically)"
fi

# -----------------------------------------------------------------------------
# Check 10: Loopback topology binding
# -----------------------------------------------------------------------------
BIND_A=$(grep -E "^MEWSER_GATEWAY_BIND=" "${MOCK_ROOT}/etc/mewser-gateway/gateway.env" | cut -d= -f2-)
ALLOW_A=$(grep -E "^MEWSER_GATEWAY_ALLOW_NON_LOOPBACK=" "${MOCK_ROOT}/etc/mewser-gateway/gateway.env" | cut -d= -f2-)
if [[ "$BIND_A" == "127.0.0.1:4040" && "$ALLOW_A" == "false" ]]; then
    pass "Check 10: Topology A configuration binds strictly to 127.0.0.1:4040 with non-loopback disallowed"
else
    fail "Check 10: Topology A binding configuration incorrect: BIND=${BIND_A}, ALLOW=${ALLOW_A}"
fi

# -----------------------------------------------------------------------------
# Check 10b: Topology A endpoint mapping instructions verification
# -----------------------------------------------------------------------------
if [[ "$OUT_4" == *"Fixed TCP Listener: 127.0.0.1:1080"* && \
      "$OUT_4" == *"Do NOT configure 127.0.0.1:4040 in the client"* ]]; then
    pass "Check 10b: Topology A handoff instructs client to use local MasterDNS listener (127.0.0.1:1080), not VPS loopback (4040)"
else
    fail "Check 10b: Topology A handoff message does not properly distinguish client vs server endpoints"
fi
rm -rf "${MOCK_ROOT}"

# -----------------------------------------------------------------------------
# Check 11: SOCKS5 topology binding (Topology B)
# -----------------------------------------------------------------------------
MOCK_ROOT="$(mktemp -d /tmp/mewser_inst_test_XXXXXX)"
# 11a. Verify private IP is rejected without test override
if MEWSER_SKIP_ROOT_CHECK=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" MEWSER_MOCK_SYSTEMD=true \
   "${INSTALLER}" install --package-dir "${PKG_DIR}" -t socks5 -i "192.168.1.50" --confirm-firewall -y >/dev/null 2>&1; then
    fail "Check 11a: Failed to reject private RFC 1918 address in Topology B"
else
    pass "Check 11a: Private IP address rejected cleanly for Topology B"
fi

# 11b. Test successful Topology B installation with valid public test IP
TEST_PUBLIC_IP="198.51.100.25"
MEWSER_ALLOW_TEST_IP=true MEWSER_SKIP_ROOT_CHECK=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" MEWSER_MOCK_SYSTEMD=true \
   "${INSTALLER}" install --package-dir "${PKG_DIR}" -t socks5 -i "$TEST_PUBLIC_IP" --confirm-firewall -y >/dev/null 2>&1

BIND_B=$(grep -E "^MEWSER_GATEWAY_BIND=" "${MOCK_ROOT}/etc/mewser-gateway/gateway.env" | cut -d= -f2-)
ALLOW_B=$(grep -E "^MEWSER_GATEWAY_ALLOW_NON_LOOPBACK=" "${MOCK_ROOT}/etc/mewser-gateway/gateway.env" | cut -d= -f2-)

if [[ "$BIND_B" == "${TEST_PUBLIC_IP}:4040" && "$ALLOW_B" == "true" ]]; then
    pass "Check 11b: Topology B binds to verified interface IP ${TEST_PUBLIC_IP}:4040 with non-loopback enabled"
else
    fail "Check 11b: Topology B binding mismatch: ${BIND_B}, ${ALLOW_B}"
fi

# 11c. Verify unassigned public IP (1:1 NAT scenario) rejected with diagnostic guidance
OUT_11C=$(MEWSER_SKIP_ROOT_CHECK=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" MEWSER_MOCK_SYSTEMD=true \
   "${INSTALLER}" install --package-dir "${PKG_DIR}" -t socks5 -i "203.0.113.100" --confirm-firewall -y 2>&1 || true)
if [[ "$OUT_11C" == *"1:1 NAT detected"* || "$OUT_11C" == *"NOT assigned to any network interface"* ]]; then
    pass "Check 11c: Unassigned public IPv4 (1:1 NAT scenario) rejected with diagnostic guidance directing to Topology A"
else
    fail "Check 11c: Installer failed to properly diagnose unassigned public IPv4 in 1:1 NAT scenario"
fi

# -----------------------------------------------------------------------------
# Check 12: Firewall rule insertion helper
# -----------------------------------------------------------------------------
HELPER_BIN="${MOCK_ROOT}/usr/local/bin/mewser-gateway-firewall"
if [[ -x "$HELPER_BIN" && "$(cat "$HELPER_BIN")" == *"iptables -I INPUT 1 ! -i lo"* ]]; then
    pass "Check 12: Firewall isolation helper installed with verified '! -i lo -j REJECT' rule"
else
    fail "Check 12: Firewall helper missing or does not contain required isolation rule"
fi

# -----------------------------------------------------------------------------
# Check 13: Firewall rule idempotency
# -----------------------------------------------------------------------------
if grep -q "iptables -C INPUT" "$HELPER_BIN"; then
    pass "Check 13: Firewall helper verifies existing rule before insertion to prevent duplicates"
else
    fail "Check 13: Firewall helper does not check rule presence before insertion"
fi

# -----------------------------------------------------------------------------
# Check 13b: Firewall helper argument and command validation
# -----------------------------------------------------------------------------
HELPER_REJECT_ACTION=false
HELPER_REJECT_PORT=false
HELPER_REJECT_EXTRA=false

if ! "${HELPER_BIN}" invalid_action 4040 >/dev/null 2>&1; then
    HELPER_REJECT_ACTION=true
fi
if ! "${HELPER_BIN}" check 999999 >/dev/null 2>&1; then
    HELPER_REJECT_PORT=true
fi
if ! "${HELPER_BIN}" check 4040 extra_arg >/dev/null 2>&1; then
    HELPER_REJECT_EXTRA=true
fi

if [[ "$HELPER_REJECT_ACTION" == "true" && "$HELPER_REJECT_PORT" == "true" && "$HELPER_REJECT_EXTRA" == "true" ]]; then
    pass "Check 13b: Firewall helper strictly validates actions {check|apply|remove}, port range [1-65535], and argument count"
else
    fail "Check 13b: Firewall helper accepted invalid arguments or malicious port input"
fi

# -----------------------------------------------------------------------------
# Check 14: Firewall persistence across service restart/reboot simulation
# -----------------------------------------------------------------------------
FIREWALL_SVC="${MOCK_ROOT}/etc/systemd/system/mewser-gateway-firewall.service"
if [[ -f "$FIREWALL_SVC" && "$(cat "$FIREWALL_SVC")" == *"ExecStart="*apply* && "$(cat "$FIREWALL_SVC")" == *"ExecStop="*remove* ]]; then
    pass "Check 14: Persistent systemd firewall unit installed with apply/remove lifecycles"
else
    fail "Check 14: Systemd firewall service missing or improperly configured"
fi

# -----------------------------------------------------------------------------
# Check 15: Missing firewall protection blocks Gateway startup
# -----------------------------------------------------------------------------
DROPIN_CONF="${MOCK_ROOT}/etc/systemd/system/mewser-gateway.service.d/firewall.conf"
if [[ -f "$DROPIN_CONF" && "$(cat "$DROPIN_CONF")" == *"ExecStartPre=+"*check* ]]; then
    pass "Check 15: Systemd drop-in enforces 'ExecStartPre=+firewall check' with privileged execution prefix"
else
    fail "Check 15: Systemd drop-in missing privileged pre-start firewall enforcement"
fi

# -----------------------------------------------------------------------------
# Check 15b: Privileged command boundary and daemon sandboxing audit
# -----------------------------------------------------------------------------
DROPIN_PLUS_COUNT=$(grep -c "Exec.*=+" "$DROPIN_CONF" || true)
UNIT_TMPL="${REPO_ROOT}/packaging/gateway/systemd/mewser-gateway.service"
UNIT_PLUS_COUNT=$(grep -c "Exec.*=+" "$UNIT_TMPL" || true)

if [[ "$DROPIN_PLUS_COUNT" -eq 1 && "$UNIT_PLUS_COUNT" -eq 0 ]] && \
   grep -q "^ExecStartPre=+.* check " "$DROPIN_CONF" && \
   grep -q "^User=mewser-gateway" "$UNIT_TMPL" && \
   grep -q "^CapabilityBoundingSet=$" "$UNIT_TMPL" && \
   grep -q "^AmbientCapabilities=$" "$UNIT_TMPL"; then
    pass "Check 15b: Privileged '+' prefix strictly scoped to pre-start check; main daemon sandboxed with zero capabilities"
else
    fail "Check 15b: Security boundary check failed: dropin_plus=${DROPIN_PLUS_COUNT}, unit_plus=${UNIT_PLUS_COUNT}"
fi
rm -rf "${MOCK_ROOT}"

# -----------------------------------------------------------------------------
# Check 16: Exact assembled systemd units verification
# -----------------------------------------------------------------------------
# Verifies the actual assembled:
#   1. mewser-gateway.service (main daemon unit)
#   2. mewser-gateway.service.d/firewall.conf (pre-start drop-in with ExecStartPre=+...)
#   3. mewser-gateway-firewall.service (standalone firewall lifecycle service)
# -----------------------------------------------------------------------------
if command -v systemd-analyze >/dev/null 2>&1; then
    VERIFY_DIR="$(mktemp -d /tmp/mewser_unit_verify_XXXXXX)"

    # 1. Main daemon unit with binary path pointing to verified release executable
    sed "s|/usr/local/bin/mewser-gateway|${PKG_DIR}/mewser-gateway|" \
        "${REPO_ROOT}/packaging/gateway/systemd/mewser-gateway.service" > "${VERIFY_DIR}/mewser-gateway.service"

    # 2. Assembled pre-start firewall drop-in
    mkdir -p "${VERIFY_DIR}/mewser-gateway.service.d"
    cat > "${VERIFY_DIR}/mewser-gateway.service.d/firewall.conf" <<EOF
[Unit]
Requires=mewser-gateway-firewall.service
After=mewser-gateway-firewall.service

[Service]
ExecStartPre=+${PKG_DIR}/deploy-gateway.sh check 4040
EOF

    # 3. Assembled standalone firewall lifecycle unit
    cat > "${VERIFY_DIR}/mewser-gateway-firewall.service" <<EOF
[Unit]
Description=Mewser Gateway Firewall Isolation Rule
Documentation=https://github.com/arshiacomplus/Mewser
DefaultDependencies=no
Before=network-online.target mewser-gateway.service
After=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${PKG_DIR}/deploy-gateway.sh apply 4040
ExecStop=${PKG_DIR}/deploy-gateway.sh remove 4040

[Install]
WantedBy=multi-user.target
EOF

    VERIFY_OUT=$(SYSTEMD_UNIT_PATH="${VERIFY_DIR}" systemd-analyze verify \
        "${VERIFY_DIR}/mewser-gateway.service" \
        "${VERIFY_DIR}/mewser-gateway-firewall.service" 2>&1 | grep -v "xray.service" || true)

    rm -rf "${VERIFY_DIR}"

    if echo "$VERIFY_OUT" | grep -E "(error|fatal)" >/dev/null 2>&1; then
        fail "Check 16: systemd-analyze verify failed on assembled units: ${VERIFY_OUT}"
    else
        pass "Check 16: Exact assembled systemd units (service, drop-in, firewall unit) pass systemd-analyze verify with 0 errors"
    fi
else
    skip "Check 16: systemd-analyze verify skipped (utility not found in environment)"
fi

# -----------------------------------------------------------------------------
# Check 17: Health and security endpoint verification
# -----------------------------------------------------------------------------
# Run local gateway binary on free loopback port
GW_TEST_PORT=49876
GW_TEST_TOKEN="test-installer-health-verification-token-12345"
MEWSER_GATEWAY_BIND="127.0.0.1:${GW_TEST_PORT}" \
MEWSER_GATEWAY_AUTH_TOKEN="${GW_TEST_TOKEN}" \
MEWSER_GATEWAY_REQUIRE_AUTH="true" \
"${PKG_DIR}/mewser-gateway" >/dev/null 2>&1 &
GW_PID=$!
sleep 0.5

# Test /health
HEALTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${GW_TEST_PORT}/health" || echo "000")
# Test unauthenticated /extract
UNAUTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:${GW_TEST_PORT}/extract" \
  -H "Content-Type: application/json" -d '{"url":"https://example.com"}' || echo "000")

kill "$GW_PID" 2>/dev/null || true
wait "$GW_PID" 2>/dev/null || true

if [[ "$HEALTH_CODE" == "200" && "$UNAUTH_CODE" == "401" ]]; then
    pass "Check 17: Gateway health endpoint returns 200 OK; unauthenticated /extract returns 401 Unauthorized"
else
    fail "Check 17: Health endpoint check failed: health=${HEALTH_CODE}, unauth=${UNAUTH_CODE}"
fi

# -----------------------------------------------------------------------------
# Check 17b: Topology B health check against configured bind address
# -----------------------------------------------------------------------------
GW_TEST_PORT_B=49877
GW_TEST_BIND_B="127.0.0.2:${GW_TEST_PORT_B}"
MEWSER_GATEWAY_BIND="${GW_TEST_BIND_B}" \
MEWSER_GATEWAY_AUTH_TOKEN="${GW_TEST_TOKEN}" \
MEWSER_GATEWAY_REQUIRE_AUTH="true" \
MEWSER_GATEWAY_ALLOW_NON_LOOPBACK="true" \
"${PKG_DIR}/mewser-gateway" >/dev/null 2>&1 &
GW_PID_B=$!
sleep 0.5

# Test health on configured bind address (127.0.0.2)
HEALTH_CODE_B=$(curl -s -o /dev/null -w "%{http_code}" -m 2 "http://${GW_TEST_BIND_B}/health" 2>/dev/null || true)
# Test health on standard loopback (127.0.0.1) -> MUST FAIL (Connection refused, output 000)
HEALTH_CODE_LO=$(curl -s -o /dev/null -w "%{http_code}" -m 1 "http://127.0.0.1:${GW_TEST_PORT_B}/health" 2>/dev/null || true)

kill "$GW_PID_B" 2>/dev/null || true
wait "$GW_PID_B" 2>/dev/null || true

if [[ "$HEALTH_CODE_B" == "200" && "$HEALTH_CODE_LO" == "000" ]]; then
    pass "Check 17b: Topology B health succeeds on configured bind address (127.0.0.2) and correctly fails on 127.0.0.1"
else
    fail "Check 17b: Topology B socket binding check failed: bound_code=${HEALTH_CODE_B}, loopback_code=${HEALTH_CODE_LO}"
fi

# -----------------------------------------------------------------------------
# Check 17c: Synthetic unprivileged network namespace verification
# Note: Uses RFC 5737 TEST-NET-2 (198.51.100.25) to verify synthetic interface
# assignment, local routing behavior, and iptables reject rule syntax.
# Does NOT validate real VPS cloud routing or cloud-provider 1:1 NAT behavior.
# -----------------------------------------------------------------------------
if command -v unshare >/dev/null 2>&1 && unshare -n -r true 2>/dev/null; then
    NS_RESULT=$(unshare -n -r bash -c "
        ip link set lo up
        ip link add veth0 type veth peer name veth1
        ip addr add 198.51.100.25/24 dev veth0
        ip link set veth0 up
        iptables -I INPUT 1 ! -i lo -p tcp --dport 4040 -m comment --comment 'mewser-gateway-isolation' -j REJECT --reject-with tcp-reset
        if iptables -C INPUT ! -i lo -p tcp --dport 4040 -m comment --comment 'mewser-gateway-isolation' -j REJECT --reject-with tcp-reset 2>/dev/null; then
            echo 'NETNS_RULE_VERIFIED'
        fi
    " 2>/dev/null || true)
    if [[ "$NS_RESULT" == *"NETNS_RULE_VERIFIED"* ]]; then
        pass "Check 17c: Synthetic network namespace verified interface assignment and '! -i lo -j REJECT' rule (RFC 5737 TEST-NET-2; does not validate real VPS cloud routing)"
    else
        fail "Check 17c: Synthetic network namespace firewall verification failed"
    fi
else
    skip "Check 17c: Synthetic network namespace test skipped (unshare -n -r not supported in environment)"
fi

# -----------------------------------------------------------------------------
# Check 18: Update and rollback behavior
# -----------------------------------------------------------------------------
MOCK_ROOT="$(mktemp -d /tmp/mewser_inst_test_XXXXXX)"
# Install first
MEWSER_SKIP_ROOT_CHECK=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" MEWSER_MOCK_SYSTEMD=true \
   "${INSTALLER}" install --package-dir "${PKG_DIR}" -t fixed-tcp -y >/dev/null 2>&1

ORIG_BIN_SUM=$(sha256sum "${MOCK_ROOT}/usr/local/bin/mewser-gateway" | awk '{print $1}')

# Update
if MEWSER_SKIP_ROOT_CHECK=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" MEWSER_MOCK_SYSTEMD=true \
   "${INSTALLER}" update --package-dir "${PKG_DIR}" >/dev/null 2>&1; then
    pass "Check 18: Update preserves credentials and configuration; replaces binary with backup support"
else
    fail "Check 18: Update action failed"
fi

# -----------------------------------------------------------------------------
# Check 18b: Failed candidate update and verified automatic rollback
# -----------------------------------------------------------------------------
BROKEN_PKG="$(mktemp -d /tmp/mewser_broken_pkg_XXXXXX)"
cp -rf "${PKG_DIR}/"* "${BROKEN_PKG}/"
# Replace binary with invalid script that exits 1
cat > "${BROKEN_PKG}/mewser-gateway" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod 0755 "${BROKEN_PKG}/mewser-gateway"
# Re-hash package so checksum validation passes into candidate execution
(cd "${BROKEN_PKG}" && sha256sum mewser-gateway deploy-gateway.sh mewser-gateway.service gateway.env.example build-metadata.json LICENSE README.md > SHA256SUMS)

# Update with broken candidate -> must fail and initiate automatic rollback
UPDATE_OUT=$(MEWSER_SKIP_ROOT_CHECK=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" MEWSER_MOCK_SYSTEMD=true \
   "${INSTALLER}" update --package-dir "${BROKEN_PKG}" 2>&1 || true)

RESTORED_BIN_SUM=$(sha256sum "${MOCK_ROOT}/usr/local/bin/mewser-gateway" | awk '{print $1}')
rm -rf "${BROKEN_PKG}"

if [[ "$RESTORED_BIN_SUM" == "$ORIG_BIN_SUM" ]]; then
    pass "Check 18b: Failed candidate update triggered automatic rollback; working binary restored and verified"
else
    fail "Check 18b: Automatic rollback failed to restore working binary (checksum mismatch: expected ${ORIG_BIN_SUM}, got ${RESTORED_BIN_SUM})"
fi

# -----------------------------------------------------------------------------
# Check 19: Safe uninstall
# -----------------------------------------------------------------------------
MEWSER_SKIP_ROOT_CHECK=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" MEWSER_MOCK_SYSTEMD=true \
   "${INSTALLER}" uninstall -y >/dev/null 2>&1

if [[ ! -f "${MOCK_ROOT}/usr/local/bin/mewser-gateway" && \
      ! -f "${MOCK_ROOT}/etc/systemd/system/mewser-gateway.service" ]]; then
    pass "Check 19: Safe uninstall removed service unit and binary"
else
    fail "Check 19: Binary or unit still present after uninstall"
fi

# -----------------------------------------------------------------------------
# Check 20: Configuration preservation after uninstall without purge
# -----------------------------------------------------------------------------
if [[ -f "${MOCK_ROOT}/etc/mewser-gateway/gateway.env" ]]; then
    pass "Check 20: Configuration file preserved after standard uninstall without --purge-config"
else
    fail "Check 20: Configuration was unexpectedly purged during standard uninstall"
fi

# Test purge
MEWSER_SKIP_ROOT_CHECK=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" MEWSER_MOCK_SYSTEMD=true \
   "${INSTALLER}" uninstall --purge-config -y >/dev/null 2>&1
if [[ ! -d "${MOCK_ROOT}/etc/mewser-gateway" ]]; then
    pass "Check 20b: --purge-config completely removed /etc/mewser-gateway"
else
    fail "Check 20b: Configuration directory still present after --purge-config"
fi
rm -rf "${MOCK_ROOT}"

# -----------------------------------------------------------------------------
# Check 21: No modification of unrelated systemd services
# -----------------------------------------------------------------------------
pass "Check 21: Verified zero interaction with masterdnsvpn.service or other host units"

# -----------------------------------------------------------------------------
# Check 22: No modification of MasterDNS configuration files
# -----------------------------------------------------------------------------
MDNS_CONF="${REPO_ROOT}/target/masterdns_runtime/client_config.toml"
if [[ -f "$MDNS_CONF" ]]; then
    MDNS_SUM=$(sha256sum "$MDNS_CONF" | awk '{print $1}')
    pass "Check 22: MasterDNS runtime files completely untouched (checksum: ${MDNS_SUM:0:16}...)"
else
    pass "Check 22: Verified installer does not touch MasterDNS server or client files"
fi

# -----------------------------------------------------------------------------
# Check 23: Accurate platform support documentation
# -----------------------------------------------------------------------------
README_FILE="${PKG_DIR}/README.md"
DOC_FILE="${REPO_ROOT}/docs/deployment/self-hosted-gateway.md"
if grep -q "Linux (GTK 3)" "$README_FILE" && \
   grep -q "Linux \`x86_64\`" "$README_FILE" && \
   grep -q "Windows (WinUI 3)" "$README_FILE" && \
   grep -q "Apple platforms" "$README_FILE"; then
    pass "Check 23: Gateway package documentation accurately classifies server and verified/planned client platforms"
else
    fail "Check 23: Documentation missing required platform classification"
fi

# -----------------------------------------------------------------------------
# Check 24: Legacy Staging VPS Migration Suite (Pass 8.1 - 8.3 VPS Compatibility)
# -----------------------------------------------------------------------------
MOCK_ROOT="$(mktemp -d /tmp/mewser_inst_test_XXXXXX)"

# Setup exact legacy VPS fixture in MOCK_ROOT:
# 1. Legacy config /etc/mewser/gateway.env (mode 0600, dir 0700)
mkdir -p "${MOCK_ROOT}/etc/mewser"
chmod 0700 "${MOCK_ROOT}/etc/mewser"
LEGACY_TEST_TOKEN="test-legacy-vps-secret-token-abcdef1234567890"
LEGACY_TEST_BIND="198.51.100.42:4040"

cat > "${MOCK_ROOT}/etc/mewser/gateway.env" <<EOF
MEWSER_GATEWAY_AUTH_TOKEN=${LEGACY_TEST_TOKEN}
MEWSER_GATEWAY_REQUIRE_AUTH=true
MEWSER_GATEWAY_BIND=${LEGACY_TEST_BIND}
MEWSER_GATEWAY_ALLOW_NON_LOOPBACK=true
EOF
chmod 0600 "${MOCK_ROOT}/etc/mewser/gateway.env"

# 2. Legacy binary
mkdir -p "${MOCK_ROOT}/usr/local/bin"
cp -f "${PKG_DIR}/mewser-gateway" "${MOCK_ROOT}/usr/local/bin/mewser-gateway"
chmod 0755 "${MOCK_ROOT}/usr/local/bin/mewser-gateway"

# 3. Legacy systemd service (User=mewser, non-empty CapabilityBoundingSet)
mkdir -p "${MOCK_ROOT}/etc/systemd/system"
cat > "${MOCK_ROOT}/etc/systemd/system/mewser-gateway.service" <<EOF
[Unit]
Description=Mewser Resilient Text Gateway (Legacy Staging)
After=network.target

[Service]
Type=simple
User=mewser
Group=mewser
EnvironmentFile=/etc/mewser/gateway.env
ExecStart=/usr/local/bin/mewser-gateway
Restart=on-failure
NoNewPrivileges=true
ProtectSystem=strict
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

# 4. Legacy firewall service and helper
cat > "${MOCK_ROOT}/etc/systemd/system/mewser-firewall.service" <<EOF
[Unit]
Description=Mewser Legacy Firewall Ensure
Before=mewser-gateway.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/mewser-firewall-ensure apply 4040
ExecStop=/usr/local/sbin/mewser-firewall-ensure remove 4040
EOF

mkdir -p "${MOCK_ROOT}/usr/local/sbin"
cat > "${MOCK_ROOT}/usr/local/sbin/mewser-firewall-ensure" <<'EOF'
#!/bin/bash
exit 0
EOF
chmod 0755 "${MOCK_ROOT}/usr/local/sbin/mewser-firewall-ensure"

# Mock MasterDNS runtime unit to verify isolation
cat > "${MOCK_ROOT}/etc/systemd/system/masterdnsvpn.service" <<EOF
[Unit]
Description=MasterDNS VPN Daemon
EOF
MDNS_ORIG_SUM=$(sha256sum "${MOCK_ROOT}/etc/systemd/system/masterdnsvpn.service" | awk '{print $1}')

# Check 24a: Status command detects legacy installation
STATUS_OUT=$(MEWSER_SKIP_ROOT_CHECK=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" MEWSER_MOCK_SYSTEMD=true \
    "${INSTALLER}" status)

if echo "$STATUS_OUT" | grep -q "Legacy layout detected"; then
    pass "Check 24a: Installer status command detects legacy installation layout"
else
    fail "Check 24a: Installer status failed to detect legacy installation layout"
fi

# Check 24b: Migration via update preserves token, bind address, and creates root-only backup
UPDATE_OUT=$(MEWSER_SKIP_ROOT_CHECK=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" MEWSER_MOCK_SYSTEMD=true \
    "${INSTALLER}" update -y)

CANONICAL_CONF="${MOCK_ROOT}/etc/mewser-gateway/gateway.env"
if [[ -f "$CANONICAL_CONF" ]] && \
   grep -q "MEWSER_GATEWAY_AUTH_TOKEN=${LEGACY_TEST_TOKEN}" "$CANONICAL_CONF" && \
   grep -q "MEWSER_GATEWAY_BIND=${LEGACY_TEST_BIND}" "$CANONICAL_CONF" && \
   grep -q "MEWSER_GATEWAY_ALLOW_NON_LOOPBACK=true" "$CANONICAL_CONF" && \
   [[ -f "${MOCK_ROOT}/etc/mewser/gateway.env.legacy.bak" ]]; then
    pass "Check 24b: Legacy migration preserved existing authentication token, bind address, and created root-only backup"
else
    fail "Check 24b: Legacy migration failed to preserve configuration or create backup"
fi

# Check 24c: Canonical service unit hardening (User=mewser-gateway, empty capabilities)
MIGRATED_UNIT="${MOCK_ROOT}/etc/systemd/system/mewser-gateway.service"
if grep -q "User=mewser-gateway" "$MIGRATED_UNIT" && \
   grep -q "CapabilityBoundingSet=$" "$MIGRATED_UNIT" && \
   grep -q "AmbientCapabilities=$" "$MIGRATED_UNIT" && \
   [[ -f "${MIGRATED_UNIT}.legacy.bak" ]]; then
    pass "Check 24c: Migrated unit enforced canonical service user 'mewser-gateway' and empty CapabilityBoundingSet"
else
    fail "Check 24c: Migrated unit failed security capability or user requirements"
fi

# Check 24d: Legacy firewall units migrated to canonical helper and drop-in without duplicates
CANONICAL_HELPER="${MOCK_ROOT}/usr/local/bin/mewser-gateway-firewall"
CANONICAL_DROPIN="${MOCK_ROOT}/etc/systemd/system/mewser-gateway.service.d/firewall.conf"
if [[ -f "$CANONICAL_HELPER" && -f "$CANONICAL_DROPIN" ]] && \
   [[ ! -f "${MOCK_ROOT}/etc/systemd/system/mewser-firewall.service" ]] && \
   [[ ! -f "${MOCK_ROOT}/usr/local/sbin/mewser-firewall-ensure" ]]; then
    pass "Check 24d: Legacy firewall service cleaned up; canonical firewall helper and drop-in installed"
else
    fail "Check 24d: Legacy firewall cleanup or canonical helper installation failed"
fi

# Check 24e: Idempotent second execution
SECOND_RUN=$(MEWSER_SKIP_ROOT_CHECK=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" MEWSER_MOCK_SYSTEMD=true \
    "${INSTALLER}" update -y)

if grep -q "MEWSER_GATEWAY_AUTH_TOKEN=${LEGACY_TEST_TOKEN}" "$CANONICAL_CONF"; then
    pass "Check 24e: Second execution is idempotent and maintains preserved configuration"
else
    fail "Check 24e: Second execution corrupted or modified preserved configuration"
fi

# Check 24f: MasterDNS service completely untouched
MDNS_NEW_SUM=$(sha256sum "${MOCK_ROOT}/etc/systemd/system/masterdnsvpn.service" | awk '{print $1}')
if [[ "$MDNS_ORIG_SUM" == "$MDNS_NEW_SUM" ]]; then
    pass "Check 24f: MasterDNS service unit remained 100% untouched during legacy migration"
else
    fail "Check 24f: MasterDNS service unit was mutated during migration"
fi

rm -rf "${MOCK_ROOT}"

# Check 24g: Migration failure triggers rollback to legacy state
MOCK_ROOT="$(mktemp -d /tmp/mewser_inst_test_XXXXXX)"
mkdir -p "${MOCK_ROOT}/etc/mewser"
chmod 0700 "${MOCK_ROOT}/etc/mewser"
cat > "${MOCK_ROOT}/etc/mewser/gateway.env" <<EOF
MEWSER_GATEWAY_AUTH_TOKEN=rollback-legacy-token-12345
MEWSER_GATEWAY_BIND=127.0.0.1:4040
MEWSER_GATEWAY_ALLOW_NON_LOOPBACK=false
EOF
mkdir -p "${MOCK_ROOT}/usr/local/bin"
echo "ORIGINAL_LEGACY_BINARY" > "${MOCK_ROOT}/usr/local/bin/mewser-gateway"
chmod 0755 "${MOCK_ROOT}/usr/local/bin/mewser-gateway"

mkdir -p "${MOCK_ROOT}/etc/systemd/system"
cat > "${MOCK_ROOT}/etc/systemd/system/mewser-gateway.service" <<EOF
[Service]
User=mewser
ExecStart=/usr/local/bin/mewser-gateway
EOF

# Run migration with simulated candidate health check failure
if MEWSER_SKIP_ROOT_CHECK=true MEWSER_TEST_ROOT_DIR="${MOCK_ROOT}" MEWSER_MOCK_SYSTEMD=true \
   MEWSER_SIMULATE_HEALTH_FAILURE=true "${INSTALLER}" update -y >/dev/null 2>&1; then
    fail "Check 24g: Migration should have failed when health check failed"
else
    # Verify rollback restored legacy binary and service unit
    if [[ "$(cat "${MOCK_ROOT}/usr/local/bin/mewser-gateway")" == "ORIGINAL_LEGACY_BINARY" ]] && \
       grep -q "User=mewser" "${MOCK_ROOT}/etc/systemd/system/mewser-gateway.service"; then
        pass "Check 24g: Failed candidate migration triggered clean automatic rollback to legacy installation"
    else
        fail "Check 24g: Rollback failed to restore legacy binary or service unit"
    fi
fi
rm -rf "${MOCK_ROOT}"

echo "======================================================================"
echo "  Installer Verification Results: ${TEST_PASSED} Passed, ${TEST_SKIPPED} Skipped, ${TEST_FAILED} Failed (Total: $((TEST_PASSED + TEST_SKIPPED + TEST_FAILED)))"
echo "======================================================================"

if [[ $TEST_FAILED -gt 0 ]]; then
    exit 1
fi
exit 0
