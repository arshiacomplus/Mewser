#!/usr/bin/env bash
#
# Mewser Gateway — Official Bootstrap & Installation Script
#
# Safely downloads, cryptographically verifies, and installs the standalone
# Mewser Gateway content extraction daemon on systemd-based Linux servers.
#
# Usage:
#   curl -fsSL -O https://raw.githubusercontent.com/arshiacomplus/Mewser/main/scripts/install-gateway.sh
#   chmod +x install-gateway.sh
#   sudo ./install-gateway.sh [options]
#
set -euo pipefail

# Invariant: Never allow execution tracing to leak credentials
set +x

INSTALLER_VERSION="0.1.1"
DEFAULT_RELEASE_TAG="v0.1.1"
DEFAULT_GITHUB_REPO="arshiacomplus/Mewser"
DEFAULT_PORT=4040

# Environment / mock overrides for automated testing
TEST_ROOT_DIR="${MEWSER_TEST_ROOT_DIR:-}"
SKIP_ROOT_CHECK="${MEWSER_SKIP_ROOT_CHECK:-false}"
MOCK_ARCH="${MEWSER_MOCK_ARCH:-}"
MOCK_OS="${MEWSER_MOCK_OS:-}"
MOCK_SYSTEMD="${MEWSER_MOCK_SYSTEMD:-false}"
MOCK_DOWNLOAD_FAIL="${MEWSER_MOCK_DOWNLOAD_FAIL:-false}"
MOCK_DOWNLOAD_DIR="${MEWSER_MOCK_DOWNLOAD_DIR:-}"
MOCK_DETECTED_IP="${MEWSER_MOCK_DETECTED_IP:-}"

CONFIG_DIR="${TEST_ROOT_DIR}/etc/mewser-gateway"
CONFIG_FILE="${CONFIG_DIR}/gateway.env"
LEGACY_CONFIG_FILE="${TEST_ROOT_DIR}/etc/mewser/gateway.env"
BIN_INSTALL_PATH="${TEST_ROOT_DIR}/usr/local/bin/mewser-gateway"
CTL_INSTALL_PATH="${TEST_ROOT_DIR}/usr/local/bin/deploy-gateway.sh"

PARAM_VERSION=""
PARAM_ARCHIVE=""
PARAM_CHECKSUM=""
PARAM_TOPOLOGY=""
PARAM_PUBLIC_IP=""
PARAM_PORT="${DEFAULT_PORT}"
PARAM_TOKEN=""
PARAM_CONFIRM_FIREWALL=false
PARAM_NON_INTERACTIVE=false
PARAM_UPDATE=false
PARAM_MIGRATE=false
PARAM_REPO="${DEFAULT_GITHUB_REPO}"

STAGING_DIR=""

cleanup() {
    if [[ -n "${STAGING_DIR:-}" && -d "${STAGING_DIR:-}" ]]; then
        rm -rf "${STAGING_DIR}"
    fi
}
trap cleanup EXIT

# -----------------------------------------------------------------------------
# Terminal Styling & Logging
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
# Help & Usage
# -----------------------------------------------------------------------------
show_help() {
    cat <<EOF
Mewser Gateway Official Installer (v${INSTALLER_VERSION})

Installs, configures, and verifies the Mewser Gateway on Linux servers.

Usage:
  sudo ./install-gateway.sh [options]

Installation Options:
  -v, --version <TAG>         Release version to download (default: ${DEFAULT_RELEASE_TAG}).
  -a, --archive <PATH>        Install from local archive (.tar.gz) instead of downloading.
  -c, --checksum <PATH>       Path to SHA-256 checksum file for local archive.
  -t, --topology <MODE>       Deployment topology:
                                fixed-tcp : Loopback binding (127.0.0.1:${DEFAULT_PORT}). Recommended for 1:1 NAT and direct-IP hosts.
                                socks5    : Public IP binding with firewall isolation. Requires directly assigned public IPv4.
  -i, --public-ip <IPv4>      Public IPv4 address (required for Topology B). Must be locally assigned.
  -p, --port <PORT>           Listening port (default: ${DEFAULT_PORT}).
  -k, --token <TOKEN>         Custom Bearer token (32+ chars; generated automatically if omitted).
  --confirm-firewall          Pre-authorize firewall rule insertion for Topology B.
  -y, --non-interactive       Run non-interactively without prompting.
  --update                    Update an existing Gateway installation (preserves configuration and token).
  --migrate                   Migrate an existing legacy installation (/etc/mewser).
  --repo <OWNER/REPO>         GitHub repository source (default: ${DEFAULT_GITHUB_REPO}).
  -h, --help                  Show this help message.

Examples:
  # Guided interactive installation (recommended):
  sudo ./install-gateway.sh

  # Automated non-interactive Fixed-TCP installation (Recommended for all cloud hosts):
  sudo ./install-gateway.sh -t fixed-tcp -y

  # Automated SOCKS5 installation on hosts with directly assigned public IP:
  sudo ./install-gateway.sh -t socks5 -i 198.51.100.25 --confirm-firewall -y

  # Offline installation from local archive:
  sudo ./install-gateway.sh --archive mewser-gateway-linux-x86_64.tar.gz --checksum mewser-gateway-linux-x86_64.tar.gz.sha256
EOF
}

# -----------------------------------------------------------------------------
# Argument Parsing
# -----------------------------------------------------------------------------
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v|--version)
                PARAM_VERSION="${2:-}"
                [[ -z "$PARAM_VERSION" ]] && die "Option --version requires an argument."
                shift 2
                ;;
            -a|--archive)
                PARAM_ARCHIVE="${2:-}"
                [[ -z "$PARAM_ARCHIVE" ]] && die "Option --archive requires an argument."
                shift 2
                ;;
            -c|--checksum)
                PARAM_CHECKSUM="${2:-}"
                [[ -z "$PARAM_CHECKSUM" ]] && die "Option --checksum requires an argument."
                shift 2
                ;;
            -t|--topology)
                PARAM_TOPOLOGY="${2:-}"
                [[ -z "$PARAM_TOPOLOGY" ]] && die "Option --topology requires an argument (fixed-tcp or socks5)."
                shift 2
                ;;
            -i|--public-ip)
                PARAM_PUBLIC_IP="${2:-}"
                [[ -z "$PARAM_PUBLIC_IP" ]] && die "Option --public-ip requires an IPv4 argument."
                shift 2
                ;;
            -p|--port)
                PARAM_PORT="${2:-}"
                [[ -z "$PARAM_PORT" ]] && die "Option --port requires a port argument."
                shift 2
                ;;
            -k|--token)
                PARAM_TOKEN="${2:-}"
                [[ -z "$PARAM_TOKEN" ]] && die "Option --token requires a token argument."
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
            --update)
                PARAM_UPDATE=true
                shift
                ;;
            --migrate)
                PARAM_MIGRATE=true
                shift
                ;;
            --repo)
                PARAM_REPO="${2:-}"
                [[ -z "$PARAM_REPO" ]] && die "Option --repo requires an argument."
                shift 2
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
# System & Preflight Checks
# -----------------------------------------------------------------------------
check_preflights() {
    if [[ "$SKIP_ROOT_CHECK" != "true" && "$(id -u)" -ne 0 ]]; then
        die "Root privileges are required. Please run with 'sudo ./install-gateway.sh'."
    fi

    local os_name="${MOCK_OS:-$(uname -s)}"
    if [[ "$os_name" != "Linux" ]]; then
        die "Unsupported operating system '${os_name}'. Mewser Gateway runs exclusively on Linux."
    fi

    local arch="${MOCK_ARCH:-$(uname -m)}"
    if [[ "$arch" != "x86_64" ]]; then
        die "Unsupported architecture '${arch}'. Mewser Gateway currently targets 'x86_64'."
    fi

    if [[ "$MOCK_SYSTEMD" != "true" && ! -d "${TEST_ROOT_DIR}/run/systemd/system" && ! -d /run/systemd/system ]]; then
        die "systemd is not running as the active init system. Mewser Gateway requires systemd."
    fi

    local missing=()
    for tool in curl tar sha256sum openssl; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing+=("$tool")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Missing required system utilities: ${missing[*]}. Please install them using your package manager (e.g. 'apt-get install curl tar coreutils openssl')."
    fi
}

# -----------------------------------------------------------------------------
# Existing Installation Detection
# -----------------------------------------------------------------------------
detect_existing_installation() {
    local has_canonical=false
    local has_legacy=false

    if [[ -f "${CONFIG_FILE}" || -f "${BIN_INSTALL_PATH}" ]]; then
        has_canonical=true
    fi

    if [[ -f "${LEGACY_CONFIG_FILE}" ]]; then
        has_legacy=true
    fi

    if [[ "$has_legacy" == "true" && "$has_canonical" == "false" ]]; then
        log_info "Detected legacy Gateway installation at ${LEGACY_CONFIG_FILE}."
        PARAM_MIGRATE=true
        return 0
    fi

    if [[ "$has_canonical" == "true" ]]; then
        if [[ "$PARAM_UPDATE" == "true" ]]; then
            log_info "Existing installation detected; proceeding with update mode."
            return 0
        fi

        if [[ "$PARAM_NON_INTERACTIVE" == "true" ]]; then
            die "Existing installation detected at ${CONFIG_FILE}. Run with --update to update the binary while preserving configuration and credentials."
        fi

        echo ""
        log_warn "An existing Mewser Gateway installation was detected at ${CONFIG_DIR}."
        echo "What would you like to do?"
        echo "  [1] Update Gateway binary (preserves credentials and configuration) [Recommended]"
        echo "  [2] Re-install / Re-configure service"
        echo "  [3] Cancel installation"
        printf "Please select an option [1-3] (default: 1): "
        local choice
        read -r choice || choice="1"
        case "${choice:-1}" in
            1)
                PARAM_UPDATE=true
                log_info "Selected update mode. Existing configuration and Bearer token will be preserved."
                ;;
            2)
                log_info "Selected re-install mode. Configuration will be refreshed."
                ;;
            *)
                echo "Installation cancelled."
                exit 0
                ;;
        esac
    fi
}

# -----------------------------------------------------------------------------
# Network Interface Public IP Discovery
# -----------------------------------------------------------------------------
detect_public_ip() {
    if [[ -n "$MOCK_DETECTED_IP" ]]; then
        echo "$MOCK_DETECTED_IP"
        return 0
    fi

    # Inspect locally assigned global IPv4 addresses (excluding RFC1918, loopback, link-local, and CGNAT)
    if command -v ip >/dev/null 2>&1; then
        local candidate
        while read -r candidate; do
            [[ -z "$candidate" ]] && continue
            if is_public_ipv4 "$candidate"; then
                echo "$candidate"
                return 0
            fi
        done < <(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1)
    fi

    return 1
}

is_public_ipv4() {
    local ip="$1"
    local o1 o2 o3 o4
    IFS=. read -r o1 o2 o3 o4 <<< "$ip"

    # Reject non-IPv4 or malformed
    if [[ -z "$o1" || -z "$o2" || -z "$o3" || -z "$o4" ]]; then
        return 1
    fi

    # 127.0.0.0/8 (Loopback)
    [[ "$o1" -eq 127 ]] && return 1

    # 10.0.0.0/8 (RFC 1918)
    [[ "$o1" -eq 10 ]] && return 1

    # 172.16.0.0/12 (RFC 1918)
    [[ "$o1" -eq 172 && "$o2" -ge 16 && "$o2" -le 31 ]] && return 1

    # 192.168.0.0/16 (RFC 1918)
    [[ "$o1" -eq 192 && "$o2" -eq 168 ]] && return 1

    # 169.254.0.0/16 (Link Local)
    [[ "$o1" -eq 169 && "$o2" -eq 254 ]] && return 1

    # 100.64.0.0/10 (CGNAT / Shared Address Space)
    [[ "$o1" -eq 100 && "$o2" -ge 64 && "$o2" -le 127 ]] && return 1

    # 0.0.0.0/8 or 224.0.0.0+
    [[ "$o1" -eq 0 || "$o1" -ge 224 ]] && return 1

    return 0
}

# -----------------------------------------------------------------------------
# Guided Topology Selection
# -----------------------------------------------------------------------------
select_topology() {
    if [[ -n "$PARAM_TOPOLOGY" ]]; then
        case "$PARAM_TOPOLOGY" in
            fixed-tcp|topology-a|a|A)
                PARAM_TOPOLOGY="fixed-tcp"
                ;;
            socks5|topology-b|b|B)
                PARAM_TOPOLOGY="socks5"
                ;;
            *)
                die "Invalid topology '${PARAM_TOPOLOGY}'. Choose 'fixed-tcp' or 'socks5'."
                ;;
        esac
        return 0
    fi

    local detected_ip
    detected_ip="$(detect_public_ip || true)"

    if [[ "$PARAM_NON_INTERACTIVE" == "true" ]]; then
        log_info "No topology specified in non-interactive mode; defaulting to Fixed TCP (Topology A)."
        PARAM_TOPOLOGY="fixed-tcp"
        return 0
    fi

    echo ""
    echo "======================================================================"
    echo "  Mewser Gateway — Deployment Topology Selection"
    echo "======================================================================"
    echo "Mewser Gateway supports two operational topologies:"
    echo ""
    echo "  [1] Topology A: Fixed TCP + Loopback (RECOMMENDED)"
    echo "      * Binds strictly to 127.0.0.1:${PARAM_PORT}."
    echo "      * Port ${PARAM_PORT} is NEVER exposed to the public internet."
    echo "      * MasterDNS forwards incoming DNS tunnel requests locally."
    echo "      * Ideal for ALL cloud environments (AWS, GCP, Azure, Hetzner, etc.)."
    echo "      * Universally supported on 1:1 NAT and direct-IP hosts alike."
    echo ""

    if [[ -n "$detected_ip" ]]; then
        echo "  [2] Topology B: SOCKS5 + Firewall Isolation (Advanced)"
        echo "      * Binds to server public IPv4 (${detected_ip}:${PARAM_PORT})."
        echo "      * Requires host firewall isolation (blocks all non-loopback inbound)."
        echo "      * Only supported on hosts with a directly assigned public IPv4."
        echo ""
    else
        echo "  [-] Topology B: SOCKS5 Mode (UNAVAILABLE on this server)"
        echo "      * No directly assigned public IPv4 detected on local interfaces."
        echo "      * Server appears to be behind 1:1 NAT (private interface IP)."
        echo "      * Topology A (Fixed TCP) must be used."
        echo ""
    fi

    printf "Select deployment topology [1]: "
    local choice
    read -r choice || choice="1"

    case "${choice:-1}" in
        1|"")
            PARAM_TOPOLOGY="fixed-tcp"
            log_info "Selected Topology A: Fixed TCP + Loopback."
            ;;
        2)
            if [[ -z "$detected_ip" ]]; then
                die "Topology B is not supported because no public IPv4 is directly assigned to local interfaces."
            fi
            PARAM_TOPOLOGY="socks5"
            PARAM_PUBLIC_IP="${PARAM_PUBLIC_IP:-$detected_ip}"
            log_info "Selected Topology B: SOCKS5 with public IP ${PARAM_PUBLIC_IP}."

            echo ""
            log_warn "Topology B requires binding to ${PARAM_PUBLIC_IP}:${PARAM_PORT}."
            log_warn "A protective firewall rule will be configured via iptables:"
            echo "  iptables -I INPUT 1 ! -i lo -p tcp --dport ${PARAM_PORT} -j REJECT --reject-with tcp-reset"
            echo ""
            if [[ "$PARAM_CONFIRM_FIREWALL" != "true" ]]; then
                printf "Authorize firewall rule configuration? [y/N]: "
                local fw_confirm
                read -r fw_confirm || fw_confirm="n"
                if [[ ! "$fw_confirm" =~ ^[Yy]$ ]]; then
                    die "Firewall configuration was not authorized. Topology B cannot proceed without firewall isolation. Aborting."
                fi
                PARAM_CONFIRM_FIREWALL=true
            fi
            ;;
        *)
            die "Invalid selection '${choice}'. Aborting."
            ;;
    esac
}

# -----------------------------------------------------------------------------
# Release Artifact Download and Verification
# -----------------------------------------------------------------------------
acquire_release_package() {
    local work_dir="$1"

    # Scenario A: Local Archive provided via --archive
    if [[ -n "$PARAM_ARCHIVE" ]]; then
        if [[ ! -f "$PARAM_ARCHIVE" ]]; then
            die "Specified local archive '${PARAM_ARCHIVE}' does not exist or is not a readable file."
        fi

        log_info "Verifying local release archive: ${PARAM_ARCHIVE}"
        local chk_file="$PARAM_CHECKSUM"
        if [[ -z "$chk_file" ]]; then
            if [[ -f "${PARAM_ARCHIVE}.sha256" ]]; then
                chk_file="${PARAM_ARCHIVE}.sha256"
            elif [[ -f "$(dirname "${PARAM_ARCHIVE}")/SHA256SUMS" ]]; then
                chk_file="$(dirname "${PARAM_ARCHIVE}")/SHA256SUMS"
            fi
        fi

        if [[ -z "$chk_file" || ! -f "$chk_file" ]]; then
            die "No SHA-256 checksum file found for '${PARAM_ARCHIVE}'. Provide --checksum <FILE> or place SHA256SUMS in the same directory. Checksum verification cannot be skipped."
        fi

        local archive_base
        archive_base="$(basename "${PARAM_ARCHIVE}")"
        local expected_hash
        expected_hash="$(grep "${archive_base}" "${chk_file}" 2>/dev/null | awk '{print $1}' || head -n 1 "${chk_file}" | awk '{print $1}')"

        if [[ -z "$expected_hash" || ${#expected_hash} -ne 64 ]]; then
            die "Failed to parse valid 64-character SHA-256 checksum from '${chk_file}'."
        fi

        local actual_hash
        actual_hash="$(sha256sum "${PARAM_ARCHIVE}" | awk '{print $1}')"

        if [[ "$expected_hash" != "$actual_hash" ]]; then
            die "Checksum verification failed for '${PARAM_ARCHIVE}'! Expected: ${expected_hash}, Actual: ${actual_hash}."
        fi

        log_success "Local archive checksum verified successfully (${expected_hash:0:16}...)."
        cp -f "${PARAM_ARCHIVE}" "${work_dir}/release.tar.gz"
        return 0
    fi

    # Scenario B: Automated GitHub Release Download
    if [[ "$MOCK_DOWNLOAD_FAIL" == "true" ]]; then
        die "Simulated download failure triggered by MEWSER_MOCK_DOWNLOAD_FAIL."
    fi

    local tag="${PARAM_VERSION:-$DEFAULT_RELEASE_TAG}"
    # Normalize tag format (ensure leading v)
    if [[ ! "$tag" =~ ^v ]]; then
        tag="v${tag}"
    fi

    if [[ -n "$MOCK_DOWNLOAD_DIR" && -d "$MOCK_DOWNLOAD_DIR" ]]; then
        log_info "Using mock release download directory: ${MOCK_DOWNLOAD_DIR}"
        if [[ ! -f "${MOCK_DOWNLOAD_DIR}/release.tar.gz" || ! -f "${MOCK_DOWNLOAD_DIR}/release.sha256" ]]; then
            die "Mock download directory is missing release.tar.gz or release.sha256."
        fi
        cp -f "${MOCK_DOWNLOAD_DIR}/release.tar.gz" "${work_dir}/release.tar.gz"
        cp -f "${MOCK_DOWNLOAD_DIR}/release.sha256" "${work_dir}/release.sha256"
    else
        local base_url="https://github.com/${PARAM_REPO}/releases/download/${tag}"
        local archive_url="${base_url}/mewser-gateway-linux-x86_64.tar.gz"
        local checksum_url="${base_url}/mewser-gateway-linux-x86_64.tar.gz.sha256"

        log_info "Downloading Mewser Gateway ${tag} from GitHub (${PARAM_REPO})..."
        if ! curl -fsSL --retry 2 --connect-timeout 15 -o "${work_dir}/release.tar.gz" "${archive_url}"; then
            die "Failed to download Gateway release archive from ${archive_url}. Verify your network connection and that release tag '${tag}' exists at https://github.com/${PARAM_REPO}/releases."
        fi

        log_info "Downloading SHA-256 checksum manifest..."
        if ! curl -fsSL --retry 2 --connect-timeout 15 -o "${work_dir}/release.sha256" "${checksum_url}"; then
            # Attempt fallback to aggregated SHA256SUMS
            local fallback_sums="${base_url}/SHA256SUMS"
            if ! curl -fsSL --retry 2 --connect-timeout 15 -o "${work_dir}/release.sha256" "${fallback_sums}"; then
                die "Failed to download release checksum manifest from ${checksum_url}. Checksum verification cannot be skipped. Aborting."
            fi
        fi
    fi

    log_info "Verifying cryptographic SHA-256 integrity of downloaded release..."
    local expected_hash
    expected_hash="$(grep "mewser-gateway-linux-x86_64.tar.gz" "${work_dir}/release.sha256" 2>/dev/null | awk '{print $1}' || head -n 1 "${work_dir}/release.sha256" | awk '{print $1}')"

    if [[ -z "$expected_hash" || ${#expected_hash} -ne 64 ]]; then
        die "Downloaded checksum file does not contain a valid 64-character SHA-256 hash."
    fi

    local actual_hash
    actual_hash="$(sha256sum "${work_dir}/release.tar.gz" | awk '{print $1}')"

    if [[ "$expected_hash" != "$actual_hash" ]]; then
        die "SECURITY ALERT: Checksum verification failed for downloaded archive! Expected: ${expected_hash}, Actual: ${actual_hash}. Extraction aborted."
    fi

    log_success "Downloaded release archive verified successfully (${expected_hash:0:16}...)."
}

# -----------------------------------------------------------------------------
# Extraction and Delegation
# -----------------------------------------------------------------------------
extract_and_delegate() {
    local work_dir="$1"
    local extract_dir="${work_dir}/pkg"
    mkdir -p "${extract_dir}"

    log_info "Extracting release package..."
    tar -xzf "${work_dir}/release.tar.gz" -C "${extract_dir}"

    if [[ ! -f "${extract_dir}/deploy-gateway.sh" || ! -f "${extract_dir}/mewser-gateway" || ! -f "${extract_dir}/SHA256SUMS" ]]; then
        die "Extracted package is corrupted or incomplete; missing deploy-gateway.sh, mewser-gateway, or SHA256SUMS."
    fi

    # Verify package internal checksum manifest
    log_info "Verifying package internal file checksums..."
    (
        cd "${extract_dir}"
        sha256sum -c SHA256SUMS >/dev/null
    )
    log_success "Package internal file integrity confirmed."

    chmod 0755 "${extract_dir}/deploy-gateway.sh" "${extract_dir}/mewser-gateway"

    # Assemble deployment command arguments
    local deploy_cmd
    if [[ "$PARAM_UPDATE" == "true" ]]; then
        deploy_cmd="update"
    elif [[ "$PARAM_MIGRATE" == "true" ]]; then
        deploy_cmd="migrate"
    else
        deploy_cmd="install"
    fi

    local deploy_args=(
        "$deploy_cmd"
        "--package-dir" "${extract_dir}"
        "-t" "${PARAM_TOPOLOGY}"
        "-p" "${PARAM_PORT}"
    )

    if [[ -n "$PARAM_PUBLIC_IP" ]]; then
        deploy_args+=("-i" "${PARAM_PUBLIC_IP}")
    fi

    if [[ -n "$PARAM_TOKEN" ]]; then
        deploy_args+=("-k" "${PARAM_TOKEN}")
    fi

    if [[ "$PARAM_CONFIRM_FIREWALL" == "true" ]]; then
        deploy_args+=("--confirm-firewall")
    fi

    if [[ "$PARAM_NON_INTERACTIVE" == "true" ]]; then
        deploy_args+=("-y")
    fi

    log_info "Executing deployment installation engine..."
    "${extract_dir}/deploy-gateway.sh" "${deploy_args[@]}"

    # Install management helper script into /usr/local/bin for operator convenience
    if [[ "${TEST_ROOT_DIR}" == "" && -d "/usr/local/bin" ]]; then
        cp -f "${extract_dir}/deploy-gateway.sh" "${CTL_INSTALL_PATH}"
        chmod 0755 "${CTL_INSTALL_PATH}"
    elif [[ -n "${TEST_ROOT_DIR}" && -d "${TEST_ROOT_DIR}/usr/local/bin" ]]; then
        cp -f "${extract_dir}/deploy-gateway.sh" "${CTL_INSTALL_PATH}"
        chmod 0755 "${CTL_INSTALL_PATH}"
    fi
}

# -----------------------------------------------------------------------------
# Post-Installation Summary & Client Guidance
# -----------------------------------------------------------------------------
show_post_install_summary() {
    local bind_addr="127.0.0.1:${PARAM_PORT}"
    if [[ "$PARAM_TOPOLOGY" == "socks5" && -n "$PARAM_PUBLIC_IP" ]]; then
        bind_addr="${PARAM_PUBLIC_IP}:${PARAM_PORT}"
    fi

    echo ""
    echo "======================================================================"
    printf "\033[1;32m  Mewser Gateway Installation Complete!\033[0m\n"
    echo "======================================================================"
    echo "  Service State : active (running)"
    echo "  Topology      : $( [[ "$PARAM_TOPOLOGY" == "fixed-tcp" ]] && echo "Topology A (Fixed TCP + Loopback)" || echo "Topology B (SOCKS5 + Firewall)" )"
    echo "  Bind Address  : ${bind_addr}"
    echo "  Configuration : /etc/mewser-gateway/gateway.env (mode 0600 root:root)"
    echo "  Control Tool  : /usr/local/bin/deploy-gateway.sh"
    echo "----------------------------------------------------------------------"
    echo "  Authentication Token:"
    echo "    Your 64-character Bearer token is safely stored in /etc/mewser-gateway/gateway.env."
    echo "    Retrieve it securely at any time by running:"
    echo "      sudo deploy-gateway.sh show-token"
    echo "----------------------------------------------------------------------"
    echo "  Next Step 1: Configure MasterDNS Server on this VPS"
    if [[ "$PARAM_TOPOLOGY" == "fixed-tcp" ]]; then
        echo "    Configure your MasterDNS server to forward TCP traffic to loopback:"
        echo "      PROTOCOL_TYPE = \"TCP\""
        echo "      FORWARD_IP    = \"127.0.0.1\""
        echo "      FORWARD_PORT  = ${PARAM_PORT}"
    else
        echo "    Configure your MasterDNS server to operate in SOCKS5 mode:"
        echo "      PROTOCOL_TYPE = \"SOCKS5\""
        echo "    The firewall has been configured to isolate port ${PARAM_PORT} from external internet."
    fi
    echo "----------------------------------------------------------------------"
    echo "  Next Step 2: Configure Mewser Desktop Client"
    echo "    1. Open Mewser Desktop -> Settings -> Resilient Gateway."
    if [[ "$PARAM_TOPOLOGY" == "fixed-tcp" ]]; then
        echo "    2. Set Transport Protocol to: Fixed TCP"
        echo "    3. Set Fixed TCP Listener to : 127.0.0.1:1080 (your local MasterDNS client listener)"
    else
        echo "    2. Set Transport Protocol to: SOCKS5"
        echo "    3. Set SOCKS5 Proxy to       : 127.0.0.1:1080"
        echo "    4. Set Remote Gateway to     : ${PARAM_PUBLIC_IP}:${PARAM_PORT}"
    fi
    echo "    5. Paste your Bearer token retrieved from 'sudo deploy-gateway.sh show-token'."
    echo "    6. In the Mewser address bar, switch to [Resilient] to browse via DNS tunnel."
    echo "======================================================================"
    echo ""
}

# -----------------------------------------------------------------------------
# Main Entry Point
# -----------------------------------------------------------------------------
main() {
    parse_args "$@"
    check_preflights
    detect_existing_installation
    select_topology

    STAGING_DIR="$(mktemp -d /tmp/mewser_gateway_bootstrap_XXXXXX)"
    chmod 0700 "${STAGING_DIR}"

    acquire_release_package "${STAGING_DIR}"
    extract_and_delegate "${STAGING_DIR}"

    if [[ "$PARAM_NON_INTERACTIVE" != "true" ]]; then
        show_post_install_summary
    else
        log_success "Mewser Gateway installed and verified successfully."
    fi
}

main "$@"
