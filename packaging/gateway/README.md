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

- **Architecture**: Linux x86_64 (`x86_64-unknown-linux-gnu`)
- **Kernel**: Linux 3.2+
- **C Library**: glibc 2.17+
- **External Libraries**: None (uses pure Rust TLS via rustls; no OpenSSL or GUI libraries required)
- **Firewall Support**: Linux `iptables` (with optional `netfilter-persistent` / `iptables-persistent`). If using standalone `nftables`, `ufw`, or `firewalld`, ensure equivalent isolation rules are installed.

## Automated Installation (Recommended)

Run the included idempotent deployment script:

```bash
# Topology A (Fixed TCP - Recommended):
# Architecturally designed for 1:1 NAT cloud hosts (AWS, GCP, Azure) and direct-public-IP hosts:
sudo ./deploy-gateway.sh install -t fixed-tcp

# Topology B (SOCKS5 with Firewall Isolation):
# Supported ONLY when public IPv4 is directly assigned to the local interface (Hetzner, OVH, Linode, DigitalOcean).
# UNSUPPORTED on 1:1 NAT cloud providers (AWS, GCP, Azure - use Topology A instead):
sudo ./deploy-gateway.sh install -t socks5 -i <SERVER_PUBLIC_IP> --confirm-firewall
```

## Manual Installation

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
   # Use configured bind address (127.0.0.1:4040 for Topology A, <SERVER_PUBLIC_IP>:4040 for Topology B)
   curl -s http://127.0.0.1:4040/health
   # Expected response: {"status":"ok"}
   ```

See `docs/deployment/self-hosted-gateway.md` for full manual deployment instructions, firewall isolation recipes, and topology guides.
