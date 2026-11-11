# Mewser Gateway (Linux x86_64)

Standalone Content Extraction Gateway server for the Mewser Resilient Text pipeline.

## Overview

Mewser Gateway is a lightweight, low-overhead HTTP daemon designed to run on self-hosted Linux servers alongside MasterDNS. It receives extraction requests from Mewser clients over an encrypted DNS tunnel, safely fetches the target web page with strict SSRF defenses, strips scripts, tracking beacons, and ads, and returns structured text and hyperlinks.

## Platform Support Matrix

- **Supported Server Platforms**: Linux `x86_64` (`x86_64-unknown-linux-gnu`) with `systemd` (Ubuntu 20.04/22.04/24.04, Debian 11/12, CentOS/RHEL 8/9, Arch Linux).
- **Supported & Verified Clients**: Mewser Desktop on Linux (GTK 3).
- **Planned / Roadmap Clients**: Windows (WinUI 3), Android (Jetpack Compose).
- **Out of Scope**: Apple platforms (iOS, macOS).

## Requirements

- **Architecture**: Linux `x86_64` (`x86_64-unknown-linux-gnu`)
- **Kernel**: Linux 3.2+
- **C Library**: `glibc >= 2.17`
- **External Libraries**: None (uses pure Rust TLS via rustls; no OpenSSL runtime or GUI libraries required)
- **Firewall Support**: Linux `iptables` (with optional `netfilter-persistent` / `iptables-persistent`). If using standalone `nftables`, `ufw`, or `firewalld`, ensure equivalent isolation rules are installed.

---

## Installation

### Option 1: Official Guided Bootstrap Installer (Recommended)

From your server terminal, download, verify, inspect, and run the official bootstrap installer (never pipe download commands to bash):

```bash
# 1. Download official bootstrap installer and integrity manifest
curl -fsSL -O https://github.com/arshiacomplus/Mewser/releases/download/v0.1.1/install-gateway.sh
curl -fsSL -O https://github.com/arshiacomplus/Mewser/releases/download/v0.1.1/SHA256SUMS

# Verify SHA-256 checksum of the installer script
sha256sum --ignore-missing -c SHA256SUMS

# Alternatively, obtain the installer directly from the repository main branch:
# curl -fsSL -O https://raw.githubusercontent.com/arshiacomplus/Mewser/main/scripts/install-gateway.sh

# 2. Inspect script content before execution (security best practice)
less install-gateway.sh

# 3. Make executable and run with root privileges
chmod +x install-gateway.sh
sudo ./install-gateway.sh
```

The installer verifies SHA-256 release checksums, checks system dependencies, detects local network interfaces, guides you through topology selection, installs systemd service units, and generates a secure 64-character Bearer token.

For automated provisioning:
```bash
# Topology A: Fixed TCP + Loopback (Recommended for all environments, including 1:1 NAT cloud hosts):
sudo ./install-gateway.sh -t fixed-tcp -y

# Topology B: SOCKS5 with Firewall Isolation (Supported ONLY when public IPv4 is directly on local interface):
sudo ./install-gateway.sh -t socks5 -i <SERVER_PUBLIC_IP> --confirm-firewall -y
```

### Option 2: Standalone Release Package Deployment (`deploy-gateway.sh`)

If you have extracted this standalone archive (`mewser-gateway-linux-x86_64.tar.gz`), run the included deployment script directly:

```bash
# Topology A (Fixed TCP - Recommended):
sudo ./deploy-gateway.sh install -t fixed-tcp

# Topology B (SOCKS5 with Firewall Isolation):
sudo ./deploy-gateway.sh install -t socks5 -i <SERVER_PUBLIC_IP> --confirm-firewall
```

### Option 3: Manual Step-by-Step Installation

1. Copy `mewser-gateway` to `/usr/local/bin/`:
   ```bash
   sudo cp mewser-gateway /usr/local/bin/
   sudo chmod 755 /usr/local/bin/mewser-gateway
   ```

2. Create the unprivileged system user (`mewser-gateway`):
   ```bash
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin mewser-gateway
   ```

3. Configure environment file at `/etc/mewser-gateway/gateway.env`:
   ```bash
   sudo mkdir -p /etc/mewser-gateway
   sudo cp gateway.env.example /etc/mewser-gateway/gateway.env
   sudo chown -R root:root /etc/mewser-gateway
   sudo chmod 700 /etc/mewser-gateway
   sudo chmod 600 /etc/mewser-gateway/gateway.env
   ```

4. Install and start the systemd service:
   ```bash
   sudo cp mewser-gateway.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now mewser-gateway
   ```

5. Verify health:
   ```bash
   # Query health on the actual configured bind address:
   BIND_ADDR="$(grep -E "^MEWSER_GATEWAY_BIND=" /etc/mewser-gateway/gateway.env | cut -d= -f2- | tr -d '[:space:]')"
   curl -s "http://${BIND_ADDR}/health"
   # Expected response: {"status":"ok"}
   ```

---

## Service Management

After installation, use `deploy-gateway.sh` to manage the daemon:

```bash
# Check service state and local health
sudo deploy-gateway.sh status

# Retrieve your 64-character Bearer token
sudo deploy-gateway.sh show-token

# Update binary to latest release (preserves token and configuration)
sudo deploy-gateway.sh update

# Safely uninstall service and remove binaries
sudo deploy-gateway.sh uninstall
```

See `docs/deployment/self-hosted-gateway.md` for complete architecture diagrams, firewall isolation recipes, and troubleshooting guides.
