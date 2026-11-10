#!/usr/bin/env bash
#
# Mewser Gateway Deployment Installer
#
# Allows each Mewser user to deploy and manage their own standalone Gateway
# on their own Linux server infrastructure.
#
# Usage:
#   sudo ./deploy-gateway.sh install   [options]
#   sudo ./deploy-gateway.sh update    [options]
#   sudo ./deploy-gateway.sh status    [options]
#   sudo ./deploy-gateway.sh show-token [options]
#   sudo ./deploy-gateway.sh uninstall [options]
#
set -euo pipefail

# Invariant: Never allow execution tracing to leak secret tokens into logs
set +x

SCRIPT_NAME="deploy-gateway.sh"
VERSION="0.1.0"

TEST_ROOT_DIR="${MEWSER_TEST_ROOT_DIR:-}"

INSTALL_BIN_PATH="${TEST_ROOT_DIR}/usr/local/bin/mewser-gateway"
FIREWALL_HELPER_PATH="${TEST_ROOT_DIR}/usr/local/bin/mewser-gateway-firewall"
SYSTEMD_UNIT_PATH="${TEST_ROOT_DIR}/etc/systemd/system/mewser-gateway.service"
FIREWALL_UNIT_PATH="${TEST_ROOT_DIR}/etc/systemd/system/mewser-gateway-firewall.service"
SYSTEMD_DROPIN_DIR="${TEST_ROOT_DIR}/etc/systemd/system/mewser-gateway.service.d"
CONFIG_DIR="${TEST_ROOT_DIR}/etc/mewser-gateway"
CONFIG_FILE="${CONFIG_DIR}/gateway.env"
SERVICE_USER="mewser-gateway"
SERVICE_GROUP="mewser-gateway"

# Legacy layout constants (Pass 8.1 - 8.3 staging VPS compatibility)
LEGACY_CONFIG_DIR="${TEST_ROOT_DIR}/etc/mewser"
LEGACY_CONFIG_FILE="${LEGACY_CONFIG_DIR}/gateway.env"
LEGACY_FIREWALL_UNIT="${TEST_ROOT_DIR}/etc/systemd/system/mewser-firewall.service"
LEGACY_FIREWALL_HELPER="${TEST_ROOT_DIR}/usr/local/sbin/mewser-firewall-ensure"
LEGACY_SERVICE_USER="mewser"
LEGACY_SERVICE_GROUP="mewser"

DEFAULT_PORT=4040
DEFAULT_TOPOLOGY=""
PARAM_TOPOLOGY=""
PARAM_PUBLIC_IP=""
PARAM_TOKEN=""
PARAM_PORT="${DEFAULT_PORT}"
PARAM_CONFIRM_FIREWALL=false
PARAM_NON_INTERACTIVE=false
PARAM_PACKAGE_DIR=""
PARAM_PURGE_CONFIG=false
PARAM_CONFIRM_SHOW=false

# -----------------------------------------------------------------------------
# Logging and Output Helpers
# -----------------------------------------------------------------------------
log_info() {
    printf "[\033[1;34mINFO\033[0m] %s\n" "$*"
}

log_success() {
    printf "[\033[1;32mOK\033[0m] %s\n" "$*"
}

log_warn() {
    printf "[\033[1;33mWARN\033[0m] %s\n" "$*" >&2
}

log_error() {
    printf "[\033[1;31mERROR\033[0m] %s\n" "$*" >&2
}

die() {
    log_error "$*"
    exit 1
}

# -----------------------------------------------------------------------------
# Usage and Help
# -----------------------------------------------------------------------------
show_help() {
    cat <<EOF
Mewser Gateway Deployment Installer v${VERSION}

Usage:
  sudo ./${SCRIPT_NAME} <command> [options]

Commands:
  install      Install and configure Mewser Gateway as a systemd service.
  update       Update the Gateway binary while preserving existing configuration and credentials.
  migrate      Safely migrate a legacy installation (user 'mewser', /etc/mewser) to canonical layout.
  status       Display current Gateway service status, bind address, and health checks.
  show-token   Securely display the active authentication token (requires confirmation).
  uninstall    Safely stop, disable, and remove the Gateway service and binary.

Options:
  -t, --topology <fixed-tcp|socks5>
               Deployment topology:
                 fixed-tcp : Topology A - Bind strictly to loopback (127.0.0.1:4040). Designed for 1:1 NAT and direct-IP hosts.
                 socks5    : Topology B - Bind to server public IPv4 with firewall isolation. Requires directly assigned public IP.
  -i, --public-ip <IPv4>
               Server's public IPv4 address (required for Topology B). Must be directly
               assigned to an active local network interface (not behind 1:1 NAT).
  -k, --token <TOKEN>
               Specify a custom 32+ char Bearer token (otherwise generated automatically).
  -p, --port <PORT>
               Listening port (default: 4040).
  --confirm-firewall
               Explicitly authorize insertion of protective firewall rule for Topology B.
  -y, --non-interactive
               Run non-interactively. Required parameters must be provided via flags.
  --package-dir <DIR>
               Path to release package containing binary and metadata.
  --purge-config
               Used with 'uninstall' to completely delete /etc/mewser-gateway and credentials.
  --confirm
               Used with 'show-token' to skip the interactive confirmation prompt.
  -h, --help   Show this help message.

EOF
}

# -----------------------------------------------------------------------------
# Permission and Environment Preflights
# -----------------------------------------------------------------------------
require_root() {
    if [[ "${MEWSER_SKIP_ROOT_CHECK:-false}" == "true" ]]; then
        return 0
    fi
    if [[ "$(id -u)" -ne 0 ]]; then
        die "This operation requires root privileges. Please run with 'sudo'."
    fi
}

safe_chown() {
    if [[ "${MEWSER_SKIP_ROOT_CHECK:-false}" == "true" ]]; then
        return 0
    fi
    chown "$@"
}

sysctl_cmd() {
    if [[ "${MEWSER_MOCK_SYSTEMD:-false}" == "true" ]]; then
        return 0
    fi
    systemctl "$@"
}

check_dependencies() {
    local missing=()
    for cmd in sha256sum openssl systemctl curl file; do
        if [[ -n "${MEWSER_MOCK_MISSING_CMD:-}" && "$cmd" == "$MEWSER_MOCK_MISSING_CMD" ]]; then
            missing+=("$cmd")
        elif ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Missing required system utilities: ${missing[*]}. Please install them using your package manager (e.g. apt-get install coreutils openssl systemd curl file)."
    fi

    local arch
    arch="${MEWSER_MOCK_ARCH:-$(uname -m)}"
    if [[ "$arch" != "x86_64" ]]; then
        die "Unsupported architecture '${arch}'. Mewser Gateway currently targets 'x86_64'."
    fi

    if [[ "${MEWSER_MOCK_SYSTEMD:-false}" != "true" && ! -d /run/systemd/system ]]; then
        die "systemd is not running as the active init system on this server. Mewser Gateway requires systemd."
    fi
}

# -----------------------------------------------------------------------------
# Package Location and Verification
# -----------------------------------------------------------------------------
locate_package_dir() {
    if [[ -n "$PARAM_PACKAGE_DIR" ]]; then
        if [[ -d "$PARAM_PACKAGE_DIR" ]]; then
            echo "$PARAM_PACKAGE_DIR"
            return 0
        else
            die "Specified --package-dir '${PARAM_PACKAGE_DIR}' does not exist."
        fi
    fi

    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Case 1: Script is inside the standalone release package directory
    if [[ -f "${script_dir}/mewser-gateway" && -f "${script_dir}/SHA256SUMS" ]]; then
        echo "${script_dir}"
        return 0
    fi

    # Case 2: Script is in scripts/ inside the repository root
    local repo_dist="${script_dir}/../dist/gateway/linux-x86_64"
    if [[ -f "${repo_dist}/mewser-gateway" && -f "${repo_dist}/SHA256SUMS" ]]; then
        echo "$(cd "${repo_dist}" && pwd)"
        return 0
    fi

    die "Could not locate Mewser Gateway package files (mewser-gateway and SHA256SUMS). Use --package-dir <DIR>."
}

verify_package() {
    local pkg_dir="$1"
    log_info "Verifying Gateway release package in: ${pkg_dir}"

    local bin_path="${pkg_dir}/mewser-gateway"
    local sums_path="${pkg_dir}/SHA256SUMS"

    if [[ ! -f "$bin_path" ]]; then
        die "Missing binary 'mewser-gateway' in package directory."
    fi

    if [[ ! -f "$sums_path" ]]; then
        die "Missing 'SHA256SUMS' file in package directory."
    fi

    # 1. Verify binary format
    local file_type
    file_type="$(file -b "$bin_path")"
    if [[ "$file_type" != *"ELF 64-bit"* || "$file_type" != *"x86-64"* ]]; then
        die "Binary '${bin_path}' is not a valid 64-bit x86-64 ELF executable: ${file_type}"
    fi

    # 2. Verify SHA256 checksum
    local expected_hash
    expected_hash="$(grep -E "mewser-gateway\$" "$sums_path" | awk '{print $1}' || true)"
    if [[ -z "$expected_hash" ]]; then
        die "Could not find checksum for 'mewser-gateway' inside ${sums_path}."
    fi

    local actual_hash
    actual_hash="$(sha256sum "$bin_path" | awk '{print $1}')"

    if [[ "$expected_hash" != "$actual_hash" ]]; then
        die "Checksum verification failed for '${bin_path}'! Expected ${expected_hash}, got ${actual_hash}."
    fi

    log_success "Package checksum verified: ${actual_hash:0:16}..."
}

# -----------------------------------------------------------------------------
# Service User & Filesystem Setup
# -----------------------------------------------------------------------------
ensure_service_account() {
    if [[ "${MEWSER_SKIP_ROOT_CHECK:-false}" == "true" ]]; then
        log_info "Test mode: skipped service account creation."
        return 0
    fi

    # Check for legacy account naming
    if id -u "mewser-gw" >/dev/null 2>&1 && ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
        log_info "Detected legacy service account 'mewser-gw'; creating canonical account '${SERVICE_USER}'..."
    fi

    if id -u "${SERVICE_USER}" >/dev/null 2>&1; then
        log_info "Service account '${SERVICE_USER}' already exists."
    else
        log_info "Creating dedicated unprivileged system account '${SERVICE_USER}'..."
        useradd --system \
            --no-create-home \
            --shell /usr/sbin/nologin \
            --comment "Mewser Gateway Service Account" \
            "${SERVICE_USER}"
        log_success "Created system user '${SERVICE_USER}'."
    fi
}

ensure_config_dir() {
    mkdir -p "${CONFIG_DIR}"
    chmod 0700 "${CONFIG_DIR}"
    safe_chown root:root "${CONFIG_DIR}"
}

# -----------------------------------------------------------------------------
# Topology Selection & Validation
# -----------------------------------------------------------------------------
validate_ipv4() {
    local ip="$1"
    local rx='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    if [[ ! "$ip" =~ $rx ]]; then
        return 1
    fi
    IFS='.' read -r -a octets <<< "$ip"
    for oct in "${octets[@]}"; do
        if (( oct < 0 || oct > 255 )); then
            return 1
        fi
    done
    return 0
}

is_private_or_loopback_ip() {
    local ip="$1"
    IFS='.' read -r -a o <<< "$ip"
    # Loopback (127.0.0.0/8)
    if (( o[0] == 127 )); then return 0; fi
    # 10.0.0.0/8
    if (( o[0] == 10 )); then return 0; fi
    # 172.16.0.0/12
    if (( o[0] == 172 && o[1] >= 16 && o[1] <= 31 )); then return 0; fi
    # 192.168.0.0/16
    if (( o[0] == 192 && o[1] == 168 )); then return 0; fi
    # 169.254.0.0/16 (Link-local)
    if (( o[0] == 169 && o[1] == 254 )); then return 0; fi
    # 0.0.0.0/8
    if (( o[0] == 0 )); then return 0; fi
    return 1
}

select_topology() {
    if [[ -n "$PARAM_TOPOLOGY" ]]; then
        case "$PARAM_TOPOLOGY" in
            fixed-tcp|A|a|1)
                DEFAULT_TOPOLOGY="fixed-tcp"
                ;;
            socks5|B|b|2)
                DEFAULT_TOPOLOGY="socks5"
                ;;
            *)
                die "Invalid --topology value '${PARAM_TOPOLOGY}'. Choose 'fixed-tcp' or 'socks5'."
                ;;
        esac
        return 0
    fi

    if [[ "$PARAM_NON_INTERACTIVE" == "true" ]]; then
        die "Non-interactive mode requires explicit --topology flag ('fixed-tcp' or 'socks5')."
    fi

    echo ""
    echo "======================================================================"
    echo "  Mewser Gateway — Select Deployment Topology"
    echo "======================================================================"
    echo "  1) Topology A: Fixed TCP + Loopback (Recommended)"
    echo "     - Gateway binds strictly to 127.0.0.1:${PARAM_PORT}"
    echo "     - MasterDNS server operates in TCP mode (PROTOCOL_TYPE = \"TCP\")"
    echo "     - Incoming traffic is forwarded locally (FORWARD_IP = \"127.0.0.1\")"
    echo "     - Completely isolated with zero public port exposure"
    echo "     - Architecturally designed for 1:1 NAT cloud hosts (AWS EC2, GCP, Azure, Oracle Cloud)"
    echo "       and standard direct-public-IP servers (subject to live VPS verification)"
    echo ""
    echo "  2) Topology B: SOCKS5 + Firewall Isolation"
    echo "     - Gateway binds to server public IPv4:${PARAM_PORT}"
    echo "     - MasterDNS server operates in SOCKS5 mode (PROTOCOL_TYPE = \"SOCKS5\")"
    echo "     - A protective firewall rule blocks all external inbound access"
    echo "     - Traffic is accepted ONLY via the server's internal loopback routing"
    echo "     - Requires public IPv4 directly assigned to a local network interface"
    echo "       (e.g., Hetzner, OVH, Linode, DigitalOcean, bare-metal)"
    echo "     - Incompatible with 1:1 NAT cloud providers (use Topology A instead)"
    echo "======================================================================"
    printf "Choose topology [1 or 2] (default: 1): "
    local choice
    read -r choice || true
    choice="${choice:-1}"

    case "$choice" in
        1|fixed-tcp|A|a)
            DEFAULT_TOPOLOGY="fixed-tcp"
            ;;
        2|socks5|B|b)
            DEFAULT_TOPOLOGY="socks5"
            ;;
        *)
            die "Invalid selection '${choice}'."
            ;;
    esac
}

configure_topology_b_ip() {
    if [[ -n "$PARAM_PUBLIC_IP" ]]; then
        local candidate="$PARAM_PUBLIC_IP"
    elif [[ "$PARAM_NON_INTERACTIVE" == "true" ]]; then
        die "Topology B in non-interactive mode requires --public-ip <IPv4>."
    else
        echo ""
        log_info "Detecting local interface IPv4 addresses..."
        local detected_ips
        detected_ips="$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 || true)"

        if [[ -n "$detected_ips" ]]; then
            echo "Available network addresses on this host:"
            for ip in $detected_ips; do
                echo "  - $ip"
            done
        fi
        printf "Enter your server's public IPv4 address: "
        local candidate
        read -r candidate || true
    fi

    candidate="$(echo "$candidate" | tr -d '[:space:]')"

    if ! validate_ipv4 "$candidate"; then
        die "Invalid IPv4 address format: '${candidate}'"
    fi

    if [[ "${MEWSER_ALLOW_TEST_IP:-false}" != "true" ]]; then
        if is_private_or_loopback_ip "$candidate"; then
            echo "" >&2
            echo "ERROR: Address '${candidate}' is private, loopback, or invalid." >&2
            echo "MasterDNS upstream SOCKS5 strictly rejects RFC 1918 private and loopback destinations." >&2
            echo "On 1:1 NAT cloud providers (AWS EC2, Google Cloud, Azure, Oracle Cloud), private interface" >&2
            echo "addresses cannot be reached through MasterDNS SOCKS5." >&2
            echo "Topology B is UNSUPPORTED in 1:1 NAT environments." >&2
            echo "RECOMMENDATION: Use Topology A (Fixed TCP + Loopback), architecturally designed for 1:1 NAT environments:" >&2
            echo "  sudo ./deploy-gateway.sh install -t fixed-tcp" >&2
            echo "" >&2
            die "Topology B rejected: address '${candidate}' is private/loopback and incompatible with MasterDNS SOCKS5."
        fi

        # Crucial security verification: Ensure candidate IP is actually assigned to an interface on this server
        if ! ip -4 addr show | grep -qw "$candidate"; then
            echo "" >&2
            echo "ERROR: Public IPv4 address '${candidate}' is NOT assigned to any network interface on this server." >&2
            echo "Binding to an unassigned IP fails with EADDRNOTAVAIL." >&2
            echo "This host appears to use 1:1 NAT (e.g. AWS EC2, GCP, Azure) where the public IP is managed" >&2
            echo "by the cloud provider and only private IPs exist on local network interfaces." >&2
            echo "Topology B requires a directly assigned public IPv4 (e.g. Hetzner, OVH, Linode, DigitalOcean)." >&2
            echo "Topology B is UNSUPPORTED on 1:1 NAT cloud hosts." >&2
            echo "RECOMMENDATION: Use Topology A (Fixed TCP + Loopback), architecturally designed for 1:1 NAT environments:" >&2
            echo "  sudo ./deploy-gateway.sh install -t fixed-tcp" >&2
            echo "" >&2
            die "Topology B rejected: public IP '${candidate}' is not assigned to any local interface (1:1 NAT detected)."
        fi
    fi

    PARAM_PUBLIC_IP="$candidate"
    log_success "Verified public IPv4 address assigned to local interface: ${PARAM_PUBLIC_IP}"
}

# -----------------------------------------------------------------------------
# Firewall Isolation Management (Topology B)
# -----------------------------------------------------------------------------
install_firewall_helper() {
    log_info "Installing firewall management helper: ${FIREWALL_HELPER_PATH}"
    mkdir -p "$(dirname "${FIREWALL_HELPER_PATH}")"

    cat > "${FIREWALL_HELPER_PATH}" <<'EOF'
#!/usr/bin/env bash
# Mewser Gateway Firewall Management Helper
# Ensures non-loopback traffic to the Gateway extraction port is strictly rejected.
set -euo pipefail

if [[ "$#" -gt 2 ]]; then
    echo "ERROR: Too many arguments." >&2
    echo "Usage: $0 {check|apply|remove} [port]" >&2
    exit 1
fi

ACTION="${1:-check}"
PORT="${2:-4040}"
COMMENT="mewser-gateway-isolation"

if ! [[ "$PORT" =~ ^[0-9]+$ ]] || (( PORT < 1 || PORT > 65535 )); then
    echo "ERROR: Port must be a valid integer between 1 and 65535, got: '${PORT}'" >&2
    exit 1
fi

if ! command -v iptables >/dev/null 2>&1; then
    echo "ERROR: iptables utility not found." >&2
    exit 1
fi

case "$ACTION" in
    check)
        if iptables -C INPUT ! -i lo -p tcp --dport "$PORT" -m comment --comment "$COMMENT" -j REJECT --reject-with tcp-reset 2>/dev/null; then
            exit 0
        elif iptables -C INPUT ! -i lo -p tcp --dport "$PORT" -j REJECT --reject-with tcp-reset 2>/dev/null; then
            exit 0
        else
            echo "ERROR: Protective firewall rule for port ${PORT} is NOT active in kernel iptables." >&2
            echo "Mewser Gateway will refuse to start on a public IP without verified firewall isolation." >&2
            exit 1
        fi
        ;;

    apply)
        if iptables -C INPUT ! -i lo -p tcp --dport "$PORT" -m comment --comment "$COMMENT" -j REJECT --reject-with tcp-reset 2>/dev/null; then
            echo "Firewall isolation rule for port ${PORT} already active."
            exit 0
        fi
        echo "Applying firewall isolation rule for port ${PORT}..."
        iptables -I INPUT 1 ! -i lo -p tcp --dport "$PORT" -m comment --comment "$COMMENT" -j REJECT --reject-with tcp-reset

        # Attempt persistence save if netfilter-persistent / iptables-persistent is available
        if command -v netfilter-persistent >/dev/null 2>&1; then
            netfilter-persistent save >/dev/null 2>&1 || true
        fi
        ;;

    remove)
        echo "Removing firewall isolation rule for port ${PORT}..."
        while iptables -D INPUT ! -i lo -p tcp --dport "$PORT" -m comment --comment "$COMMENT" -j REJECT --reject-with tcp-reset 2>/dev/null; do
            :
        done
        while iptables -D INPUT ! -i lo -p tcp --dport "$PORT" -j REJECT --reject-with tcp-reset 2>/dev/null; do
            :
        done
        if command -v netfilter-persistent >/dev/null 2>&1; then
            netfilter-persistent save >/dev/null 2>&1 || true
        fi
        ;;

    *)
        echo "ERROR: Invalid action '${ACTION}'." >&2
        echo "Usage: $0 {check|apply|remove} [port]" >&2
        exit 1
        ;;
esac
EOF

    chmod 0700 "${FIREWALL_HELPER_PATH}"
    safe_chown root:root "${FIREWALL_HELPER_PATH}"
}

setup_topology_b_firewall() {
    if [[ "$PARAM_CONFIRM_FIREWALL" != "true" ]]; then
        if [[ "$PARAM_NON_INTERACTIVE" == "true" ]]; then
            die "Topology B requires explicit firewall confirmation. Pass --confirm-firewall."
        fi
        echo ""
        log_warn "Topology B binds Gateway to ${PARAM_PUBLIC_IP}:${PARAM_PORT}."
        echo "To prevent external attackers and port scanners from accessing plain-HTTP extraction,"
        echo "a protective firewall rule must be installed in kernel iptables:"
        echo "  iptables -I INPUT 1 ! -i lo -p tcp --dport ${PARAM_PORT} -j REJECT --reject-with tcp-reset"
        echo "This rule permits MasterDNS tunnel traffic via local loopback while rejecting all external ingress."
        printf "Authorize installation of this firewall rule? [y/N]: "
        local ans
        read -r ans || true
        if [[ "$ans" != "y" && "$ans" != "Y" && "$ans" != "yes" ]]; then
            die "Firewall rule authorization declined. Aborting deployment."
        fi
    fi

    install_firewall_helper

    if [[ "${MEWSER_MOCK_SYSTEMD:-false}" != "true" ]]; then
        # 1. Apply rule immediately
        "${FIREWALL_HELPER_PATH}" apply "${PARAM_PORT}"

        # 2. Verify rule is active in the running kernel
        if ! "${FIREWALL_HELPER_PATH}" check "${PARAM_PORT}"; then
            die "Firewall rule verification failed after insertion. Gateway will not start."
        fi
        log_success "Active firewall isolation rule verified in kernel iptables."
    else
        log_info "Test mode (MEWSER_MOCK_SYSTEMD=true): skipped live iptables execution."
    fi

    # 3. Install persistent systemd firewall service
    mkdir -p "$(dirname "${FIREWALL_UNIT_PATH}")"
    cat > "${FIREWALL_UNIT_PATH}" <<EOF
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
ExecStart=${FIREWALL_HELPER_PATH} apply ${PARAM_PORT}
ExecStop=${FIREWALL_HELPER_PATH} remove ${PARAM_PORT}

[Install]
WantedBy=multi-user.target
EOF

    chmod 0644 "${FIREWALL_UNIT_PATH}"
    safe_chown root:root "${FIREWALL_UNIT_PATH}"

    sysctl_cmd daemon-reload
    sysctl_cmd enable "${FIREWALL_UNIT_PATH##*/}"
    sysctl_cmd start "${FIREWALL_UNIT_PATH##*/}"

    # 4. Install systemd drop-in requiring firewall check before Gateway starts.
    # Privilege Boundary: The '+' prefix causes systemd to execute this pre-start check
    # with full root privileges, bypassing User=, Group=, and sandbox restrictions described
    # by systemd for this command only. The main daemon (ExecStart) retains unprivileged
    # User=mewser-gateway with zero capabilities and full sandboxing.
    mkdir -p "${SYSTEMD_DROPIN_DIR}"
    cat > "${SYSTEMD_DROPIN_DIR}/firewall.conf" <<EOF
[Unit]
Requires=${FIREWALL_UNIT_PATH##*/}
After=${FIREWALL_UNIT_PATH##*/}

[Service]
ExecStartPre=+${FIREWALL_HELPER_PATH} check ${PARAM_PORT}
EOF
    chmod 0644 "${SYSTEMD_DROPIN_DIR}/firewall.conf"
    log_success "Installed persistent firewall service and systemd pre-start enforcement."
}

remove_topology_b_firewall() {
    if [[ -f "${FIREWALL_HELPER_PATH}" ]]; then
        if [[ "${MEWSER_MOCK_SYSTEMD:-false}" != "true" ]]; then
            "${FIREWALL_HELPER_PATH}" remove "${PARAM_PORT}" || true
        fi
        rm -f "${FIREWALL_HELPER_PATH}"
    fi

    if [[ -f "${FIREWALL_UNIT_PATH}" ]]; then
        sysctl_cmd stop "${FIREWALL_UNIT_PATH##*/}" 2>/dev/null || true
        sysctl_cmd disable "${FIREWALL_UNIT_PATH##*/}" 2>/dev/null || true
        rm -f "${FIREWALL_UNIT_PATH}"
    fi

    rm -rf "${SYSTEMD_DROPIN_DIR}"
    sysctl_cmd daemon-reload 2>/dev/null || true
    log_info "Cleaned up firewall isolation rules and services."
}

# -----------------------------------------------------------------------------
# Configuration Generation & Token Management
# -----------------------------------------------------------------------------
detect_legacy_installation() {
    # 1. Legacy config file exists while canonical is absent
    if [[ -f "${LEGACY_CONFIG_FILE}" && ! -f "${CONFIG_FILE}" ]]; then
        return 0
    fi
    # 2. Existing service unit references legacy user, legacy config, or non-empty CapabilityBoundingSet
    if [[ -f "${SYSTEMD_UNIT_PATH}" ]]; then
        if grep -q "User=mewser" "${SYSTEMD_UNIT_PATH}" 2>/dev/null || \
           grep -q "/etc/mewser/gateway.env" "${SYSTEMD_UNIT_PATH}" 2>/dev/null || \
           grep -q "CapabilityBoundingSet=CAP_" "${SYSTEMD_UNIT_PATH}" 2>/dev/null; then
            return 0
        fi
    fi
    # 3. Legacy firewall unit or legacy helper exists
    if [[ -f "${LEGACY_FIREWALL_UNIT}" || -f "${LEGACY_FIREWALL_HELPER}" ]]; then
        return 0
    fi
    return 1
}

generate_or_load_token() {
    # If custom token supplied via CLI, use it
    if [[ -n "$PARAM_TOKEN" ]]; then
        echo "$PARAM_TOKEN"
        return 0
    fi

    # If configuration file already exists, preserve existing token
    if [[ -f "${CONFIG_FILE}" ]]; then
        local existing_token
        existing_token="$(grep -E "^MEWSER_GATEWAY_AUTH_TOKEN=" "${CONFIG_FILE}" | cut -d= -f2- | tr -d '[:space:]' || true)"
        if [[ -n "$existing_token" ]]; then
            echo "$existing_token"
            return 0
        fi
    fi

    # If legacy configuration file exists, preserve legacy token
    if [[ -f "${LEGACY_CONFIG_FILE}" ]]; then
        local legacy_token
        legacy_token="$(grep -E "^MEWSER_GATEWAY_AUTH_TOKEN=" "${LEGACY_CONFIG_FILE}" | cut -d= -f2- | tr -d '[:space:]' || true)"
        if [[ -n "$legacy_token" ]]; then
            echo "$legacy_token"
            return 0
        fi
    fi

    # Generate new cryptographically secure 32-byte hex token (64 hex characters)
    openssl rand -hex 32
}

write_environment_file() {
    local token="$1"
    local bind_addr="$2"
    local allow_non_loopback="$3"

    ensure_config_dir

    local tmp_file
    tmp_file="$(mktemp "${CONFIG_DIR}/gateway.env.tmp.XXXXXX")"
    chmod 0600 "$tmp_file"
    safe_chown root:root "$tmp_file"

    cat > "$tmp_file" <<EOF
# Mewser Gateway Environment Configuration
# Automatically generated by ${SCRIPT_NAME}
# Owner: root:root (mode 0600)
MEWSER_GATEWAY_AUTH_TOKEN=${token}
MEWSER_GATEWAY_REQUIRE_AUTH=true
MEWSER_GATEWAY_BIND=${bind_addr}
MEWSER_GATEWAY_ALLOW_NON_LOOPBACK=${allow_non_loopback}
EOF

    mv -f "$tmp_file" "${CONFIG_FILE}"
    chmod 0600 "${CONFIG_FILE}"
    safe_chown root:root "${CONFIG_FILE}"
    log_success "Saved configuration to ${CONFIG_FILE} (mode 0600 owned by root:root)."
}

# -----------------------------------------------------------------------------
# systemd Unit Installation
# -----------------------------------------------------------------------------
install_systemd_unit() {
    local pkg_dir="$1"
    local src_unit="${pkg_dir}/mewser-gateway.service"

    if [[ ! -f "$src_unit" ]]; then
        # Check standard packaging location
        local repo_unit="${pkg_dir}/../../packaging/gateway/systemd/mewser-gateway.service"
        if [[ -f "$repo_unit" ]]; then
            src_unit="$repo_unit"
        else
            die "Could not find 'mewser-gateway.service' template."
        fi
    fi

    log_info "Installing systemd unit to ${SYSTEMD_UNIT_PATH}..."
    mkdir -p "$(dirname "${SYSTEMD_UNIT_PATH}")"
    cp -f "$src_unit" "${SYSTEMD_UNIT_PATH}"
    chmod 0644 "${SYSTEMD_UNIT_PATH}"
    safe_chown root:root "${SYSTEMD_UNIT_PATH}"

    sysctl_cmd daemon-reload

    if [[ "${MEWSER_MOCK_SYSTEMD:-false}" != "true" && -z "${MEWSER_TEST_ROOT_DIR:-}" ]] && command -v systemd-analyze >/dev/null 2>&1; then
        if systemd-analyze verify "${SYSTEMD_UNIT_PATH}" 2>&1 | grep -E "mewser-gateway.*(error|fatal)" >/dev/null 2>&1; then
            die "systemd-analyze verify reported errors on ${SYSTEMD_UNIT_PATH}."
        fi
    fi
}

# -----------------------------------------------------------------------------
# Health Verification
# -----------------------------------------------------------------------------
verify_gateway_health() {
    local bind_addr="$1"
    local token="$2"

    if [[ "${MEWSER_MOCK_SYSTEMD:-false}" == "true" ]]; then
        if [[ "${MEWSER_SIMULATE_HEALTH_FAILURE:-false}" == "true" ]]; then
            log_error "Test mode: simulated health verification failure."
            return 1
        fi
        log_info "Test mode: simulated health verification passed."
        return 0
    fi

    log_info "Verifying Gateway health and authentication enforcement..."

    # Wait up to 5 seconds for service to enter active running state
    local start_time
    start_time="$(date +%s)"
    local is_active=false

    while (( $(date +%s) - start_time < 6 )); do
        if systemctl is-active --quiet "${SYSTEMD_UNIT_PATH##*/}"; then
            is_active=true
            break
        fi
        sleep 0.2
    done

    if [[ "$is_active" != "true" ]]; then
        log_error "Service '${SYSTEMD_UNIT_PATH##*/}' failed to reach active state."
        journalctl -u "${SYSTEMD_UNIT_PATH##*/}" --no-pager -n 25 >&2 || true
        return 1
    fi

    # Query health endpoint derived from actual bound address
    local health_url="http://${bind_addr}/health"
    local health_resp
    health_resp="$(curl -s -f -m 3 "$health_url" || true)"

    if [[ "$health_resp" != *"\"status\":\"ok\""* && "$health_resp" != *"\"status\": \"ok\""* ]]; then
        log_error "Health check query to ${health_url} failed. Response: '${health_resp}'"
        journalctl -u "${SYSTEMD_UNIT_PATH##*/}" --no-pager -n 25 >&2 || true
        return 1
    fi
    log_success "Gateway health check passed (${health_url} -> 200 OK)."

    # Verify unauthenticated request to /extract is rejected with 401
    local extract_url="http://${bind_addr}/extract"
    local http_code
    http_code="$(curl -s -o /dev/null -w "%{http_code}" -m 3 -X POST "$extract_url" \
        -H "Content-Type: application/json" \
        -d '{"url":"https://example.com"}' || true)"

    if [[ "$http_code" != "401" ]]; then
        log_error "Security invariant failed: Unauthenticated request to /extract returned HTTP ${http_code} (expected 401 Unauthorized)."
        return 1
    fi
    log_success "Security verification passed: Extraction endpoint requires valid Bearer token."
    return 0
}

# -----------------------------------------------------------------------------
# Client Configuration Handoff
# -----------------------------------------------------------------------------
display_client_handoff() {
    local topology="$1"
    local bind_addr="$2"
    local token="$3"
    local is_new_install="$4"

    echo ""
    echo "======================================================================"
    echo "  Mewser Gateway — Deployment Successful! 🎉"
    echo "======================================================================"
    echo ""
    echo "Platform Status:"
    echo "  - Verified Client: Mewser Desktop on Linux (GTK 3)"
    echo "  - Roadmap (Planned): Windows (WinUI 3), Android (Jetpack Compose)"
    echo "  - Out of Scope: Apple platforms (iOS, macOS)"
    echo ""
    echo "Configure Mewser Desktop (Settings -> Resilient Gateway):"
    echo ""
    if [[ "$topology" == "fixed-tcp" ]]; then
        echo "  [Topology A: Fixed TCP via MasterDNS Tunnel]"
        echo "  1. Server Side (VPS):"
        echo "     - Gateway listening locally on: 127.0.0.1:${PARAM_PORT}"
        echo "     - In your VPS MasterDNS server configuration, ensure:"
        echo "         PROTOCOL_TYPE = \"TCP\""
        echo "         FORWARD_IP = \"127.0.0.1\""
        echo "         FORWARD_PORT = ${PARAM_PORT}"
        echo ""
        echo "  2. Client Side (Mewser Desktop Settings):"
        echo "     - Transport Protocol: Fixed TCP"
        echo "     - Fixed TCP Listener: 127.0.0.1:1080 (or your local MasterDNS client port)"
        echo "     - Note: The client connects to its local MasterDNS client listener,"
        echo "       which tunnels traffic directly to the VPS Gateway on 127.0.0.1:${PARAM_PORT}."
        echo "       Do NOT configure 127.0.0.1:4040 in the client, as that would target your local PC."
    else
        echo "  [Topology B: SOCKS5 with Firewall Isolation]"
        echo "  1. Server Side (VPS):"
        echo "     - Gateway bound to public IP: ${bind_addr}"
        echo "     - Protected by kernel firewall: ! -i lo -p tcp --dport ${PARAM_PORT} -j REJECT"
        echo "     - MasterDNS server operates in SOCKS5 mode (PROTOCOL_TYPE = \"SOCKS5\")"
        echo ""
        echo "  2. Client Side (Mewser Desktop Settings):"
        echo "     - Transport Protocol: SOCKS5"
        echo "     - SOCKS5 Proxy Address: 127.0.0.1:1080 (or your local MasterDNS client port)"
        echo "     - Gateway Endpoint: ${bind_addr}"
    fi
    echo ""

    if [[ "$is_new_install" == "true" ]]; then
        echo "  3. Gateway Authentication Token:"
        echo "     ================================================================"
        echo "     ${token}"
        echo "     ================================================================"
        echo "     Copy this token into 'Gateway Authentication Token' in Mewser."
        echo "     (Stored in ${CONFIG_FILE} mode 0600 owned by root:root)."
        echo "     To view it again later, run: sudo ./${SCRIPT_NAME} show-token"
    else
        echo "  3. Gateway Authentication Token: [Preserved Existing Token]"
        echo "     To display the existing token, run: sudo ./${SCRIPT_NAME} show-token"
    fi
    echo ""
    echo "======================================================================"
}

# -----------------------------------------------------------------------------
# Action: migrate (Legacy Staging VPS to Canonical Layout)
# -----------------------------------------------------------------------------
migrate_legacy_installation() {
    local pkg_dir="$1"

    log_info "======================================================================"
    log_info "  Mewser Gateway — Migrating Legacy Installation"
    log_info "======================================================================"

    # 1. Read existing legacy configuration
    local legacy_token=""
    local legacy_bind=""
    local legacy_allow="false"
    local legacy_port="${DEFAULT_PORT}"
    local legacy_topology="fixed-tcp"

    if [[ -f "${LEGACY_CONFIG_FILE}" ]]; then
        legacy_token="$(grep -E "^MEWSER_GATEWAY_AUTH_TOKEN=" "${LEGACY_CONFIG_FILE}" 2>/dev/null | cut -d= -f2- | tr -d '[:space:]' || true)"
        legacy_bind="$(grep -E "^MEWSER_GATEWAY_BIND=" "${LEGACY_CONFIG_FILE}" 2>/dev/null | cut -d= -f2- | tr -d '[:space:]' || true)"
        legacy_allow="$(grep -E "^MEWSER_GATEWAY_ALLOW_NON_LOOPBACK=" "${LEGACY_CONFIG_FILE}" 2>/dev/null | cut -d= -f2- | tr -d '[:space:]' || echo "false")"
    fi

    # Fallback to canonical if legacy config was partially migrated
    if [[ -z "$legacy_token" && -f "${CONFIG_FILE}" ]]; then
        legacy_token="$(grep -E "^MEWSER_GATEWAY_AUTH_TOKEN=" "${CONFIG_FILE}" 2>/dev/null | cut -d= -f2- | tr -d '[:space:]' || true)"
    fi
    if [[ -z "$legacy_bind" && -f "${CONFIG_FILE}" ]]; then
        legacy_bind="$(grep -E "^MEWSER_GATEWAY_BIND=" "${CONFIG_FILE}" 2>/dev/null | cut -d= -f2- | tr -d '[:space:]' || true)"
    fi

    legacy_token="${legacy_token:-$(generate_or_load_token)}"
    legacy_bind="${legacy_bind:-127.0.0.1:4040}"

    if [[ "$legacy_bind" =~ :([0-9]+)$ ]]; then
        legacy_port="${BASH_REMATCH[1]}"
    fi

    if [[ "$legacy_allow" == "true" ]] || [[ "$legacy_bind" != 127.* && "$legacy_bind" != localhost* ]]; then
        legacy_topology="socks5"
    else
        legacy_topology="fixed-tcp"
    fi

    log_info "Preserving existing Gateway Bearer authentication token."
    log_info "Preserving existing bind address: ${legacy_bind} (Topology: ${legacy_topology})."

    # 2. Atomic backup of legacy configuration and service units (mode 0600 / root:root)
    local backup_legacy_env="${LEGACY_CONFIG_FILE}.legacy.bak"
    local backup_bin="${INSTALL_BIN_PATH}.legacy.bak"
    local backup_unit="${SYSTEMD_UNIT_PATH}.legacy.bak"
    local backup_firewall_unit="${LEGACY_FIREWALL_UNIT}.legacy.bak"
    local backup_firewall_helper="${LEGACY_FIREWALL_HELPER}.legacy.bak"

    if [[ -f "${LEGACY_CONFIG_FILE}" ]]; then
        cp -p "${LEGACY_CONFIG_FILE}" "$backup_legacy_env"
        chmod 0600 "$backup_legacy_env"
        safe_chown root:root "$backup_legacy_env"
    fi
    if [[ -f "${INSTALL_BIN_PATH}" ]]; then
        cp -p "${INSTALL_BIN_PATH}" "$backup_bin"
    fi
    if [[ -f "${SYSTEMD_UNIT_PATH}" ]]; then
        cp -p "${SYSTEMD_UNIT_PATH}" "$backup_unit"
    fi
    if [[ -f "${LEGACY_FIREWALL_UNIT}" ]]; then
        cp -p "${LEGACY_FIREWALL_UNIT}" "$backup_firewall_unit"
    fi
    if [[ -f "${LEGACY_FIREWALL_HELPER}" ]]; then
        cp -p "${LEGACY_FIREWALL_HELPER}" "$backup_firewall_helper"
    fi

    # 3. Ensure canonical unprivileged service account exists (mewser-gateway)
    ensure_service_account

    # 4. Write canonical configuration file (/etc/mewser-gateway/gateway.env, mode 0600 root:root)
    write_environment_file "$legacy_token" "$legacy_bind" "$legacy_allow"

    # 5. Install new candidate binary atomically
    local tmp_bin="${INSTALL_BIN_PATH}.candidate.$$"
    cp -f "${pkg_dir}/mewser-gateway" "$tmp_bin"
    chmod 0755 "$tmp_bin"
    safe_chown root:root "$tmp_bin"
    mv -f "$tmp_bin" "${INSTALL_BIN_PATH}"

    # 6. Install canonical systemd service unit (with empty CapabilityBoundingSet and AmbientCapabilities)
    install_systemd_unit "$pkg_dir"

    # 7. Migrate firewall services if Topology B or if legacy firewall service existed
    if [[ "$legacy_topology" == "socks5" || -f "$backup_firewall_unit" || -f "$backup_firewall_helper" ]]; then
        log_info "Migrating firewall isolation to canonical helper and drop-in..."
        PARAM_PORT="$legacy_port"
        PARAM_CONFIRM_FIREWALL=true
        install_firewall_helper
        setup_topology_b_firewall

        # Safely disable and remove legacy firewall service
        if [[ -f "${LEGACY_FIREWALL_UNIT}" ]]; then
            sysctl_cmd stop "${LEGACY_FIREWALL_UNIT##*/}" 2>/dev/null || true
            sysctl_cmd disable "${LEGACY_FIREWALL_UNIT##*/}" 2>/dev/null || true
            rm -f "${LEGACY_FIREWALL_UNIT}"
        fi
        if [[ -f "${LEGACY_FIREWALL_HELPER}" ]]; then
            rm -f "${LEGACY_FIREWALL_HELPER}"
        fi
    fi

    # 8. Reload systemd and start canonical service
    log_info "Reloading systemd and restarting mewser-gateway.service..."
    sysctl_cmd daemon-reload
    sysctl_cmd enable "${SYSTEMD_UNIT_PATH##*/}"
    sysctl_cmd restart "${SYSTEMD_UNIT_PATH##*/}"

    # 9. Verify candidate health with automatic rollback
    if ! verify_gateway_health "$legacy_bind" "$legacy_token"; then
        log_error "Candidate binary failed health verification! Initiating automatic rollback to legacy layout..."

        sysctl_cmd stop "${SYSTEMD_UNIT_PATH##*/}" 2>/dev/null || true

        # Restore binary
        if [[ -f "$backup_bin" ]]; then
            mv -f "$backup_bin" "${INSTALL_BIN_PATH}"
        fi

        # Restore systemd unit
        if [[ -f "$backup_unit" ]]; then
            mv -f "$backup_unit" "${SYSTEMD_UNIT_PATH}"
            sysctl_cmd daemon-reload 2>/dev/null || true
        fi

        # Restore legacy firewall unit and helper if backed up
        if [[ -f "$backup_firewall_unit" ]]; then
            mv -f "$backup_firewall_unit" "${LEGACY_FIREWALL_UNIT}"
            sysctl_cmd enable "${LEGACY_FIREWALL_UNIT##*/}" 2>/dev/null || true
        fi
        if [[ -f "$backup_firewall_helper" ]]; then
            mv -f "$backup_firewall_helper" "${LEGACY_FIREWALL_HELPER}"
        fi

        # Clean up canonical drop-in if rolled back
        rm -rf "${SYSTEMD_DROPIN_DIR}"

        # Restart legacy service
        sysctl_cmd daemon-reload 2>/dev/null || true
        sysctl_cmd restart "${SYSTEMD_UNIT_PATH##*/}" 2>/dev/null || true

        if verify_gateway_health "$legacy_bind" "$legacy_token"; then
            log_warn "Automatic rollback SUCCEEDED. Gateway restored to legacy working version."
            die "Migration aborted due to candidate failure. Rollback completed successfully."
        else
            log_error "CRITICAL: Rollback failed to restore service health! Manual operator intervention required."
            die "Migration and rollback both failed."
        fi
    fi

    # 10. Clean up temporary candidate backup files
    rm -f "$backup_bin"
    log_success "Migration to canonical Mewser Gateway completed successfully."
    log_info "Legacy configuration backup preserved: ${backup_legacy_env}"
    log_info "Legacy systemd service backup preserved: ${backup_unit}"
    log_info "Canonical configuration active: ${CONFIG_FILE}"

    display_client_handoff "$legacy_topology" "$legacy_bind" "$legacy_token" false
}

do_migrate() {
    require_root
    check_dependencies

    local pkg_dir
    pkg_dir="$(locate_package_dir)"
    verify_package "$pkg_dir"

    if ! detect_legacy_installation; then
        if [[ -f "${CONFIG_FILE}" && -f "${INSTALL_BIN_PATH}" ]]; then
            log_success "Gateway is already running the canonical installation layout (${CONFIG_FILE})."
            log_info "Use '${SCRIPT_NAME} update' to update the binary."
            return 0
        fi
        die "No legacy Mewser Gateway installation detected. Run '${SCRIPT_NAME} install' instead."
    fi

    migrate_legacy_installation "$pkg_dir"
}

# -----------------------------------------------------------------------------
# Action: install
# -----------------------------------------------------------------------------
do_install() {
    require_root
    check_dependencies

    local pkg_dir
    pkg_dir="$(locate_package_dir)"
    verify_package "$pkg_dir"

    if detect_legacy_installation && [[ ! -f "${CONFIG_FILE}" ]]; then
        log_info "Legacy installation detected during install. Migrating to canonical layout..."
        migrate_legacy_installation "$pkg_dir"
        return 0
    fi

    ensure_service_account
    ensure_config_dir

    select_topology

    local bind_addr
    local allow_non_loopback
    if [[ "$DEFAULT_TOPOLOGY" == "fixed-tcp" ]]; then
        bind_addr="127.0.0.1:${PARAM_PORT}"
        allow_non_loopback="false"
        log_info "Configuring Topology A (Fixed TCP + Loopback on ${bind_addr})."
        remove_topology_b_firewall
    else
        configure_topology_b_ip
        bind_addr="${PARAM_PUBLIC_IP}:${PARAM_PORT}"
        allow_non_loopback="true"
        log_info "Configuring Topology B (SOCKS5 + Firewall on ${bind_addr})."
        setup_topology_b_firewall
    fi

    local is_new_install=true
    if [[ -f "${CONFIG_FILE}" ]]; then
        is_new_install=false
    fi

    local token
    token="$(generate_or_load_token)"

    # Copy binary
    log_info "Installing Gateway executable to ${INSTALL_BIN_PATH}..."
    mkdir -p "$(dirname "${INSTALL_BIN_PATH}")"
    cp -f "${pkg_dir}/mewser-gateway" "${INSTALL_BIN_PATH}"
    chmod 0755 "${INSTALL_BIN_PATH}"
    safe_chown root:root "${INSTALL_BIN_PATH}"

    # Write environment configuration
    write_environment_file "$token" "$bind_addr" "$allow_non_loopback"

    # Install systemd unit
    install_systemd_unit "$pkg_dir"

    # Enable and start service
    log_info "Enabling and starting mewser-gateway.service..."
    sysctl_cmd enable "${SYSTEMD_UNIT_PATH##*/}"
    sysctl_cmd restart "${SYSTEMD_UNIT_PATH##*/}"

    # Verify health
    if ! verify_gateway_health "$bind_addr" "$token"; then
        die "Gateway service installation failed health or security verification."
    fi

    # Handoff instructions
    display_client_handoff "$DEFAULT_TOPOLOGY" "$bind_addr" "$token" "$is_new_install"
}

# -----------------------------------------------------------------------------
# Action: update
# -----------------------------------------------------------------------------
do_update() {
    require_root
    check_dependencies

    local pkg_dir
    pkg_dir="$(locate_package_dir)"
    verify_package "$pkg_dir"

    if detect_legacy_installation; then
        log_info "Legacy installation components detected during update. Migrating to canonical layout..."
        migrate_legacy_installation "$pkg_dir"
        return 0
    fi

    if [[ ! -f "${INSTALL_BIN_PATH}" || ! -f "${CONFIG_FILE}" ]]; then
        die "Mewser Gateway is not currently installed. Run '${SCRIPT_NAME} install' first."
    fi

    log_info "Updating Mewser Gateway binary..."

    # 1. Atomic backup of current working binary and systemd service unit
    local backup_bin="${INSTALL_BIN_PATH}.bak"
    local backup_unit="${SYSTEMD_UNIT_PATH}.bak"
    log_info "Creating atomic backup of current binary and unit..."
    cp -p "${INSTALL_BIN_PATH}" "$backup_bin"
    if [[ -f "${SYSTEMD_UNIT_PATH}" ]]; then
        cp -p "${SYSTEMD_UNIT_PATH}" "$backup_unit"
    fi

    # 2. Install candidate binary atomically
    local tmp_bin="${INSTALL_BIN_PATH}.candidate.$$"
    cp -f "${pkg_dir}/mewser-gateway" "$tmp_bin"
    chmod 0755 "$tmp_bin"
    safe_chown root:root "$tmp_bin"
    mv -f "$tmp_bin" "${INSTALL_BIN_PATH}"

    # 3. Update systemd unit template if needed
    install_systemd_unit "$pkg_dir"

    # 4. Restart service
    log_info "Restarting mewser-gateway.service..."
    sysctl_cmd restart "${SYSTEMD_UNIT_PATH##*/}"

    # Read current bind address from config
    local bind_addr
    bind_addr="$(grep -E "^MEWSER_GATEWAY_BIND=" "${CONFIG_FILE}" | cut -d= -f2- | tr -d '[:space:]' || echo "127.0.0.1:4040")"
    local token
    token="$(grep -E "^MEWSER_GATEWAY_AUTH_TOKEN=" "${CONFIG_FILE}" | cut -d= -f2- | tr -d '[:space:]' || true)"

    # 5. Verify health of candidate; automatic rollback on failure
    if ! verify_gateway_health "$bind_addr" "$token"; then
        log_error "Candidate binary failed health verification! Initiating automatic rollback..."

        # Stop failed candidate service
        sysctl_cmd stop "${SYSTEMD_UNIT_PATH##*/}" 2>/dev/null || true

        # Atomically restore previous working binary
        mv -f "$backup_bin" "${INSTALL_BIN_PATH}"

        # Restore systemd unit if backed up
        if [[ -f "$backup_unit" ]]; then
            mv -f "$backup_unit" "${SYSTEMD_UNIT_PATH}"
            sysctl_cmd daemon-reload 2>/dev/null || true
            rm -f "$backup_unit"
        fi

        # Restart previous version
        log_info "Restarting previous working Gateway version..."
        sysctl_cmd restart "${SYSTEMD_UNIT_PATH##*/}"

        # Verify health of rolled-back version
        if verify_gateway_health "$bind_addr" "$token"; then
            log_warn "Automatic rollback SUCCEEDED. Gateway restored to previous working version."
            die "Update aborted due to candidate failure. Rollback completed successfully."
        else
            log_error "CRITICAL: Rollback failed to restore service health! Service is currently unavailable."
            log_error "Diagnostic logs preserved. Manual operator intervention required."
            die "Update and rollback both failed. Gateway service is inactive."
        fi
    fi

    rm -f "$backup_bin" "$backup_unit"
    log_success "Mewser Gateway updated successfully to version $(grep -E "\"version\"" "${pkg_dir}/build-metadata.json" 2>/dev/null | cut -d: -f2 | tr -d ' ",' || echo "latest")."
}

# -----------------------------------------------------------------------------
# Action: status
# -----------------------------------------------------------------------------
do_status() {
    echo "======================================================================"
    echo "  Mewser Gateway Service Status"
    echo "======================================================================"

    local installed=false
    if [[ -f "${INSTALL_BIN_PATH}" && -f "${SYSTEMD_UNIT_PATH}" ]]; then
        installed=true
        echo "Binary Installed : ${INSTALL_BIN_PATH}"
    else
        echo "Binary Installed : No (Not installed)"
    fi

    if [[ -f "${CONFIG_FILE}" ]]; then
        echo "Configuration    : ${CONFIG_FILE} (mode $(stat -c "%a" "${CONFIG_FILE}" 2>/dev/null || echo "0600"))"
        local bind_addr
        bind_addr="$(grep -E "^MEWSER_GATEWAY_BIND=" "${CONFIG_FILE}" 2>/dev/null | cut -d= -f2- | tr -d '[:space:]' || echo "unknown")"
        echo "Bind Address     : ${bind_addr}"
        local allow_non_loopback
        allow_non_loopback="$(grep -E "^MEWSER_GATEWAY_ALLOW_NON_LOOPBACK=" "${CONFIG_FILE}" 2>/dev/null | cut -d= -f2- | tr -d '[:space:]' || echo "false")"
        echo "Allow Non-Loop   : ${allow_non_loopback}"
        if grep -q "MEWSER_GATEWAY_AUTH_TOKEN=" "${CONFIG_FILE}" 2>/dev/null; then
            echo "Auth Token       : [Configured] (use 'show-token' to view)"
        else
            echo "Auth Token       : [Missing]"
        fi
    elif [[ -f "${LEGACY_CONFIG_FILE}" ]]; then
        echo "Configuration    : Legacy layout detected (${LEGACY_CONFIG_FILE})"
        local bind_addr
        bind_addr="$(grep -E "^MEWSER_GATEWAY_BIND=" "${LEGACY_CONFIG_FILE}" 2>/dev/null | cut -d= -f2- | tr -d '[:space:]' || echo "unknown")"
        echo "Bind Address     : ${bind_addr}"
        local allow_non_loopback
        allow_non_loopback="$(grep -E "^MEWSER_GATEWAY_ALLOW_NON_LOOPBACK=" "${LEGACY_CONFIG_FILE}" 2>/dev/null | cut -d= -f2- | tr -d '[:space:]' || echo "false")"
        echo "Allow Non-Loop   : ${allow_non_loopback}"
        if grep -q "MEWSER_GATEWAY_AUTH_TOKEN=" "${LEGACY_CONFIG_FILE}" 2>/dev/null; then
            echo "Auth Token       : [Configured] (in legacy config)"
        fi
        echo "Migration Status : Action required - Legacy installation detected. Run '${SCRIPT_NAME} update' or '${SCRIPT_NAME} migrate'."
    else
        echo "Configuration    : Missing (${CONFIG_FILE})"
    fi

    local svc_active=false
    if [[ "${MEWSER_MOCK_SYSTEMD:-false}" == "true" ]]; then
        svc_active=true
        echo -e "Service State    : \033[1;32mactive (running) [mock]\033[0m"
    elif command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active --quiet "${SYSTEMD_UNIT_PATH##*/}" 2>/dev/null; then
            svc_active=true
            echo -e "Service State    : \033[1;32mactive (running)\033[0m"
        else
            echo -e "Service State    : \033[1;31minactive\033[0m"
        fi
    fi

    # Check firewall status if Topology B
    if [[ -f "${FIREWALL_HELPER_PATH}" ]]; then
        if "${FIREWALL_HELPER_PATH}" check "${PARAM_PORT}" >/dev/null 2>&1; then
            echo -e "Firewall Rule    : \033[1;32mActive (Port ${PARAM_PORT} isolated from external ingress)\033[0m"
        else
            echo -e "Firewall Rule    : \033[1;31mINACTIVE (WARNING: Port ${PARAM_PORT} may be unprotected!)\033[0m"
        fi
    fi

    # Query local health if service is active
    if [[ "$svc_active" == "true" && -n "${bind_addr:-}" && "$bind_addr" != "unknown" ]]; then
        local health_url="http://${bind_addr}/health"
        local health_resp
        health_resp="$(curl -s -f -m 2 "$health_url" 2>/dev/null || true)"
        if [[ "$health_resp" == *"\"status\":\"ok\""* || "$health_resp" == *"\"status\": \"ok\""* ]]; then
            echo -e "Health Endpoint  : \033[1;32mOK (200 Response)\033[0m"
        else
            echo -e "Health Endpoint  : \033[1;31mFAIL (Could not reach ${health_url})\033[0m"
        fi
        echo "Note             : Local health check verifies listener on this server."
        echo "                   Client-side tunnel connectivity requires active MasterDNS client."
    fi
    echo "======================================================================"
}

# -----------------------------------------------------------------------------
# Action: show-token
# -----------------------------------------------------------------------------
do_show_token() {
    require_root

    local target_cfg="${CONFIG_FILE}"
    if [[ ! -f "$target_cfg" && -f "${LEGACY_CONFIG_FILE}" ]]; then
        target_cfg="${LEGACY_CONFIG_FILE}"
    fi

    if [[ ! -f "$target_cfg" ]]; then
        die "Configuration file '${CONFIG_FILE}' not found. Gateway may not be installed."
    fi

    local token
    token="$(grep -E "^MEWSER_GATEWAY_AUTH_TOKEN=" "$target_cfg" | cut -d= -f2- | tr -d '[:space:]' || true)"

    if [[ -z "$token" ]]; then
        die "No MEWSER_GATEWAY_AUTH_TOKEN found in ${target_cfg}."
    fi

    if [[ "$PARAM_CONFIRM_SHOW" != "true" && "$PARAM_NON_INTERACTIVE" != "true" ]]; then
        echo "Notice: Displaying the secret Bearer token in your terminal."
        printf "Proceed and show token? [y/N]: "
        local ans
        read -r ans || true
        if [[ "$ans" != "y" && "$ans" != "Y" && "$ans" != "yes" ]]; then
            echo "Cancelled."
            return 0
        fi
    fi

    echo ""
    echo "======================================================================"
    echo "  Mewser Gateway Authentication Token"
    echo "======================================================================"
    echo "${token}"
    echo "======================================================================"
    echo ""
}

# -----------------------------------------------------------------------------
# Action: uninstall
# -----------------------------------------------------------------------------
do_uninstall() {
    require_root

    echo "======================================================================"
    echo "  Mewser Gateway Uninstall"
    echo "======================================================================"
    echo "The following components will be stopped and removed:"
    echo "  - Service: ${SYSTEMD_UNIT_PATH##*/}"
    echo "  - Executable: ${INSTALL_BIN_PATH}"
    if [[ -f "${FIREWALL_HELPER_PATH}" ]]; then
        echo "  - Firewall rule and helper: ${FIREWALL_HELPER_PATH}"
    fi

    if [[ "$PARAM_PURGE_CONFIG" == "true" ]]; then
        echo "  - Configuration & Credentials: ${CONFIG_DIR} (PURGE REQUESTED)"
        echo "  - Service User: ${SERVICE_USER}"
    else
        echo "  - Configuration: ${CONFIG_DIR} (PRESERVED)"
        echo "    (Use --purge-config to remove credentials and configuration directory)"
    fi
    echo "======================================================================"

    if [[ "$PARAM_NON_INTERACTIVE" != "true" ]]; then
        printf "Are you sure you want to uninstall Mewser Gateway? [y/N]: "
        local ans
        read -r ans || true
        if [[ "$ans" != "y" && "$ans" != "Y" && "$ans" != "yes" ]]; then
            echo "Uninstall cancelled."
            return 0
        fi
    fi

    log_info "Stopping and disabling mewser-gateway service..."
    sysctl_cmd stop "${SYSTEMD_UNIT_PATH##*/}" 2>/dev/null || true
    sysctl_cmd disable "${SYSTEMD_UNIT_PATH##*/}" 2>/dev/null || true
    rm -f "${SYSTEMD_UNIT_PATH}"

    remove_topology_b_firewall

    if [[ -f "${INSTALL_BIN_PATH}" ]]; then
        rm -f "${INSTALL_BIN_PATH}"
        log_info "Removed binary ${INSTALL_BIN_PATH}."
    fi

    sysctl_cmd daemon-reload 2>/dev/null || true

    if [[ "$PARAM_PURGE_CONFIG" == "true" ]]; then
        rm -rf "${CONFIG_DIR}"
        log_info "Purged configuration directory ${CONFIG_DIR}."
        if [[ "${MEWSER_SKIP_ROOT_CHECK:-false}" != "true" ]]; then
            if id -u "${SERVICE_USER}" >/dev/null 2>&1; then
                userdel "${SERVICE_USER}" 2>/dev/null || true
                log_info "Removed system user ${SERVICE_USER}."
            fi
            if id -u "mewser-gw" >/dev/null 2>&1; then
                userdel "mewser-gw" 2>/dev/null || true
                log_info "Removed legacy system user mewser-gw."
            fi
        fi
    fi

    log_success "Mewser Gateway uninstalled cleanly."
}

# -----------------------------------------------------------------------------
# Argument Parsing
# -----------------------------------------------------------------------------
parse_args() {
    if [[ $# -eq 0 ]]; then
        show_help
        exit 0
    fi

    COMMAND="$1"
    shift

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--topology)
                PARAM_TOPOLOGY="$2"
                shift 2
                ;;
            -i|--public-ip)
                PARAM_PUBLIC_IP="$2"
                shift 2
                ;;
            -k|--token)
                PARAM_TOKEN="$2"
                shift 2
                ;;
            -p|--port)
                PARAM_PORT="$2"
                shift 2
                ;;
            --confirm-firewall)
                PARAM_CONFIRM_FIREWALL=true
                shift
                ;;
            -y|--non-interactive)
                PARAM_NON_INTERACTIVE=true
                shift
                ;;
            --package-dir)
                PARAM_PACKAGE_DIR="$2"
                shift 2
                ;;
            --purge-config)
                PARAM_PURGE_CONFIG=true
                shift
                ;;
            --confirm)
                PARAM_CONFIRM_SHOW=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                die "Unknown argument: $1. Run with --help for usage."
                ;;
        esac
    done
}

# -----------------------------------------------------------------------------
# Main Entry Point
# -----------------------------------------------------------------------------
main() {
    parse_args "$@"

    case "$COMMAND" in
        install)
            do_install
            ;;
        update)
            do_update
            ;;
        migrate)
            do_migrate
            ;;
        status)
            do_status
            ;;
        show-token)
            do_show_token
            ;;
        uninstall)
            do_uninstall
            ;;
        help|-h|--help)
            show_help
            ;;
        *)
            die "Unknown command '${COMMAND}'. Available commands: install, update, migrate, status, show-token, uninstall."
            ;;
    esac
}

main "$@"
