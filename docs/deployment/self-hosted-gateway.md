# Self-Hosted Mewser Gateway Deployment Guide

This guide documents the manual deployment of the **Mewser Gateway** on user-controlled Linux VPS infrastructure.

Mewser Resilient Text mode requires a Gateway deployed on infrastructure controlled by the individual user. The developer's VPS is development/staging infrastructure only and is never a mandatory or default destination.

---

## 1. Supported Architecture & Platform Matrix

### Platform Support Status
- **Supported Gateway Server Platforms**: Linux `x86_64` with `systemd` (Ubuntu 20.04/22.04/24.04, Debian 11/12, RHEL/CentOS 8/9, Arch Linux).
- **Supported & Verified Mewser Clients**: Mewser Desktop on Linux (GTK 3).
- **Planned / Roadmap Mewser Clients**: Windows (WinUI 3), Android (Jetpack Compose).
- **Out of Scope**: Apple platforms (iOS, macOS).

### Server Requirements
- **Operating System**: Modern systemd-based Linux distribution on `x86_64`.
- **CPU & RAM**: Minimum 1 vCPU, 512 MB RAM (lightweight, typically consumes < 25 MB RSS).
- **Network Interfaces**:
  - Inbound UDP port 53 (open for MasterDNS tunnel traffic).
  - Outbound TCP ports 80/443 (open for Gateway to fetch external web content).
- **Init System**: `systemd`.
- **Runtime Dependencies**: `glibc >= 2.17`. No OpenSSL runtime, GUI, WebKit, or graphics packages required.

---

## 2. Gateway Deployment Topologies & Transport Security

Before installing, select one of the following topologies based on your MasterDNS server configuration:

```
┌────────────────────────────────────────────────────────────────────────┐
│ TOPOLOGY 1: Co-located MasterDNS Fixed-TCP Mode (Recommended)          │
│                                                                        │
│ [Client Device]                               [Server VPS]             │
│   Mewser Desktop Client                       MasterDNS Server         │
│     │ (Connects to 127.0.0.1:1080)              │                      │
│     ▼                                           │                      │
│   Local MasterDNS Client Runtime                │                      │
│     │ (Encrypted DNS Tunnel)                    │                      │
│     └───────────────────────────────────────────┤ (Local TCP Loopback) │
│                                                 ▼                      │
│                                           Mewser Gateway               │
│                                           (127.0.0.1:4040)             │
│                                           Strictly Loopback            │
└────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────┐
│ TOPOLOGY 2: Co-located MasterDNS SOCKS5 Mode + Firewall Isolation      │
│                                                                        │
│ [Client Device]                               [Server VPS]             │
│   Mewser Desktop Client                       MasterDNS Server         │
│     │ (SOCKS5 CONNECT via 127.0.0.1:1080)       │                      │
│     └───────────────────────────────────────────┤ (Kernel lo routing)  │
│                                                 ▼                      │
│  [Internet Attacker] ──X (Blocked by Firewall)─► Mewser Gateway        │
│                                                  (Public_IP:4040)      │
└────────────────────────────────────────────────────────────────────────┘
```

### Topology 1: Co-located with MasterDNS in Fixed-TCP Mode (Recommended)
- **Mechanics**: The MasterDNS server is configured with `PROTOCOL_TYPE = "TCP"`, `FORWARD_IP = "127.0.0.1"`, and `FORWARD_PORT = 4040`. The client connects using `--transport fixed-tcp` (or selects Fixed TCP in Mewser Desktop Settings).
- **Security Boundary**: The Gateway binds strictly to `127.0.0.1:4040` (`MEWSER_GATEWAY_BIND=127.0.0.1:4040`, `MEWSER_GATEWAY_ALLOW_NON_LOOPBACK=false`). Port 4040 is not accessible from the external internet under any circumstances.
- **Provider Compatibility**: **Architecturally designed for 1:1 NAT environments**.
  - Recommended deployment path for 1:1 NAT cloud hosts (e.g. AWS EC2, Google Cloud Platform, Microsoft Azure, Oracle Cloud Infrastructure) as well as traditional VPS and bare-metal hosts with directly assigned public IPv4 addresses (Hetzner, OVH, Linode, DigitalOcean).
  - Handles traffic entirely via internal loopback forwarding (`127.0.0.1`), eliminating public-IP socket binding requirements.
  - *Verification Boundary*: Expected to work when MasterDNS TCP forwarding, UDP/53 DNS reachability, and provider ingress rules are correctly configured. Provider-specific end-to-end operation remains subject to real VPS verification; universal production compatibility is not claimed.
- **Endpoint Semantics**:
  1. *Gateway Bind Address (VPS)*: `127.0.0.1:4040`
  2. *MasterDNS Server Forwarding (VPS)*: `FORWARD_IP = "127.0.0.1"`, `FORWARD_PORT = 4040`
  3. *Local Client Transport Endpoint (Desktop)*: `127.0.0.1:1080` (the local MasterDNS runtime listener)
  4. *Client Configuration*: In Mewser Desktop Settings -> Resilient Gateway, set **Transport Protocol** to `Fixed TCP` and **Fixed TCP Listener** to `127.0.0.1:1080`.
     *Note*: The client does NOT connect to `127.0.0.1:4040` directly, as port 4040 exists on the VPS loopback, not the local client machine.
  5. *Gateway Request Semantics*: Requests are transmitted as `POST /extract` with `Host: gateway.local`.

### Topology 2: Co-located with MasterDNS in SOCKS5 Mode + Firewall Isolation
- **Mechanics**: The MasterDNS server runs with `PROTOCOL_TYPE = "SOCKS5"`. MasterDNS operates as a general-purpose tunnel proxy that permits outbound SOCKS5 connections to any globally routable unicast IP address, while rejecting connections to local loopback and RFC 1918 private subnets. MasterDNS does **not** restrict destinations exclusively to the server's own IP. Rather, when Mewser Gateway binds to `<SERVER_PUBLIC_IP>:4040`, MasterDNS can connect to it because `<SERVER_PUBLIC_IP>` is a globally routable unicast IPv4 address that satisfies MasterDNS's destination validation filters, and the Linux kernel routes outbound traffic destined to its own public IP locally over the loopback (`lo`) interface.
- **MasterDNS Audit Traceability**:
  - *Upstream Repository*: `https://github.com/masterking32/MasterDnsVPN`
  - *Pinned Upstream Commit*: `7de2476f1c33e69eec35360c52810dab43c5c986` (v2026.06.13.234407-7de2476, built with Go 1.25.0)
  - *Audited Source Symbol*: `masterdnsvpn-go/internal/udpserver.validateSOCKSTargetHost` (in `internal/udpserver/socks5.go`)
  - *Audited Binaries*: `MasterDnsVPN_Client_Linux_AMD64_v2026.06.13.234407-7de2476` (SHA-256: `dbe8b7c8de12e76ac3fd8d6eca4a98d43e358173193be24a886f290220512d67`) and `MasterDnsVPN_Server_Linux_AMD64_v2026.06.13.234407-7de2476`
  - *Disassembly & Predicate Call Graph*: Machine disassembly of `validateSOCKSTargetHost` (entry point `0x5d9d40`) reveals the following sequential logic:
    1. Whitespace normalization via `strings.TrimSpace(host)`: empty string returns `blockedSOCKSTargetError`.
    2. Lowercase transformation via `strings.ToLower(host)`: exact match for `"localhost"` or domain suffix match for `".localhost"` returns `blockedSOCKSTargetError`.
    3. Target parsing via `net.ParseIP(host)`:
       - *If host is a literal IP address*:
         - `!net.IP.IsGlobalUnicast()` -> Rejects `0.0.0.0/8`, `::`, broadcast `255.255.255.255`, loopback `127.0.0.0/8`, `::1`, link-local `169.254.0.0/16`, `fe80::/10`, and multicast `224.0.0.0/4`, `ff00::/8`.
         - `net.IP.IsLoopback()` -> Explicitly rejects `127.0.0.0/8` and `::1`.
         - `net.IP.IsPrivate()` -> Rejects RFC 1918 IPv4 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and RFC 4193 IPv6 ULA (`fc00::/7`).
         - `net.IP.IsMulticast()` -> Explicitly rejects `224.0.0.0/4` and `ff00::/8`.
         - `net.IP.IsLinkLocalUnicast()` -> Explicitly rejects `169.254.0.0/16` and `fe80::/10`.
       - *If host is a domain name*: Evaluates the domain name against the system resolver and subjects each resolved IP address to the identical set of predicates above.
  - *Policy Gap Analysis*: MasterDNS's reliance on the Go standard library's `net.IP.IsPrivate()` means that special-purpose IPv4 ranges not defined in RFC 1918—specifically Carrier-Grade NAT (RFC 6598 `100.64.0.0/10`), documentation ranges (RFC 5737 `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), benchmarking ranges (RFC 2544 `198.18.0.0/15`), and reserved Class E (`240.0.0.0/4`)—are **permitted** by MasterDNS SOCKS5 because `IsGlobalUnicast()` returns `true` and `IsPrivate()` returns `false` for them.
  - *Mewser Gateway SSRF Defense-in-Depth*: In Mewser's deployment model, this MasterDNS policy gap does not introduce vulnerability because Mewser Gateway implements independent, defense-in-depth destination validation (`crates/mewser-gateway/src/ssrf.rs` and `crates/mewser-core/src/policy.rs`). Before fetching any target content, Mewser Gateway validates and strictly rejects Carrier-Grade NAT (`100.64.0.0/10`), documentation networks, benchmarking ranges, reserved Class E addresses, loopback, private RFC 1918 networks, and cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`, `instance-data`).
- **Supported Boundary**:
  - **Supported**: Environments where the server's public IPv4 address is **directly assigned to a local network interface** (e.g., Hetzner, OVH, Linode, DigitalOcean, and dedicated bare-metal servers).
  - **UNSUPPORTED on 1:1 NAT Cloud Providers** (AWS EC2, Google Cloud Platform, Microsoft Azure, Oracle Cloud):
    1. *No Local Public IP*: On 1:1 NAT providers, the VM interface (`eth0`) is assigned an RFC 1918 private IPv4 address (e.g., `10.0.0.0/8`, `172.16.0.0/12`, or `192.168.0.0/16`). The public IPv4 exists only at the cloud border gateway.
    2. *Bind Failure*: Binding the Gateway listener directly to the cloud public IP fails with `EADDRNOTAVAIL` because the address does not exist on the local kernel interface.
    3. *Private IP Rejected*: Upstream MasterDNS SOCKS5 rejects private IP targets; operators cannot substitute their private interface IP.
    4. *Security Invariant*: MasterDNS SOCKS5 target restrictions prevent internal network probing and SSRF; they must never be bypassed or weakened.
    5. *Required Resolution*: For 1:1 NAT cloud environments, operators **must deploy using Topology 1 (Fixed TCP)** (subject to real-VPS verification of provider networking and MasterDNS TCP forwarding).
- **Security Boundary & systemd Privilege Model**:
  The Gateway binds to the server's public IP (`MEWSER_GATEWAY_BIND=<SERVER_PUBLIC_IP>:4040`, `MEWSER_GATEWAY_ALLOW_NON_LOOPBACK=true`). To prevent external internet scanners from accessing the Gateway, **the host firewall rejects all non-loopback traffic to port 4040**:
  ```bash
  sudo iptables -I INPUT 1 ! -i lo -p tcp --dport 4040 -m comment --comment "mewser-gateway-isolation" -j REJECT --reject-with tcp-reset
  ```
  Local kernel routing delivers the MasterDNS connection internally over the `lo` interface, while external connection attempts fail with connection reset.
  *Pre-Start Verification & Privilege Boundary*:
  - The drop-in `/etc/systemd/system/mewser-gateway.service.d/firewall.conf` invokes:
    ```ini
    ExecStartPre=+${FIREWALL_HELPER_PATH} check ${PARAM_PORT}
    ```
  - The `+` prefix causes systemd to execute the helper with full privileges (as root), bypassing `User=`, `Group=`, and filesystem namespacing restrictions described by systemd for this single pre-start check.
  - *Privilege Boundaries*:
    1. Only the read-only firewall check receives the `+` prefix.
    2. The main Gateway daemon (`ExecStart=/usr/local/bin/mewser-gateway`) runs with zero `+` prefix under unprivileged `User=mewser-gateway` with zero capabilities (`CapabilityBoundingSet=`, `AmbientCapabilities=`) and strict sandboxing (`ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`).
    3. The helper script `/usr/local/bin/mewser-gateway-firewall` is owned by `root:root` with mode `0700`.
    4. Helper arguments are strictly validated to `{check|apply|remove}`, positive integer port `1..65535`, and at most 2 arguments, preventing arbitrary command execution.
  *Firewall Manager Support*: The installer manages Linux `iptables` rules directly and saves persistence via `netfilter-persistent` / `iptables-persistent`. If using standalone `nftables`, `ufw`, or `firewalld`, ensure an equivalent reject rule is placed before any permissive input rules.
- **Endpoint Semantics**:
  1. *Gateway Bind Address (VPS)*: `<SERVER_PUBLIC_IP>:4040`
  2. *Local Client Proxy Endpoint (Desktop)*: `127.0.0.1:1080` (the local MasterDNS runtime listener)
  3. *Client Configuration*: In Mewser Desktop Settings -> Resilient Gateway, set **Transport Protocol** to `SOCKS5`, **SOCKS5 Proxy Address** to `127.0.0.1:1080`, and **Gateway Endpoint** to `<SERVER_PUBLIC_IP>:4040`.

### Topology 3: Separate Server / Remote Standalone Host (NOT SUPPORTED)
- **Limitation**: The current Mewser `ClientEngine` communicates with the Gateway using HTTP/1.1 over the tunnel adapter. `ClientEngine` does **not** negotiate TLS or validate TLS certificates for the Gateway connection.
- **Risk**: Deploying the Gateway on a separate public server over plain HTTP exposes the Bearer authentication token and extracted cleartext content to external network eavesdropping and tampering.
- **Recommendation**: Do not expose a plain-HTTP Gateway across public networks. Separate-host Gateway deployment is unverified and blocked until client-side TLS termination is implemented in `ClientEngine`.

---

## 3. Obtaining and Verifying the Release Package

Download or copy the release directory to the server:

```bash
cd /tmp
tar -xzf mewser-gateway-linux-x86_64.tar.gz
cd dist/gateway/linux-x86_64
```

Verify package integrity using the provided SHA256 checksums:

```bash
sha256sum -c SHA256SUMS
```

Ensure all files report `OK`.

---

## 4. Creating the Unprivileged Service Account

Create a dedicated system account with no interactive login shell and no home directory:

```bash
sudo useradd --system \
  --no-create-home \
  --shell /usr/sbin/nologin \
  --comment "Mewser Gateway Service Account" \
  mewser-gateway
```

---

## 5. Installing the Gateway Binary

Copy the binary to `/usr/local/bin/` and restrict permissions:

```bash
sudo cp mewser-gateway /usr/local/bin/mewser-gateway
sudo chown root:root /usr/local/bin/mewser-gateway
sudo chmod 755 /usr/local/bin/mewser-gateway
```

Verify binary execution:

```bash
/usr/local/bin/mewser-gateway --help 2>&1 | head -n 5 || true
```

---

## 6. Generating Authentication Credentials

Generate a cryptographically secure 64-character hexadecimal Bearer token:

```bash
GW_TOKEN=$(openssl rand -hex 32)
echo "Generated Token: ${GW_TOKEN}"
```

> [!IMPORTANT]
> Save this token securely. You will need it to configure your Mewser Desktop client (and future mobile clients once released). Never share or commit this token.

---

## 7. Creating the Protected Environment File

Create the configuration directory:

```bash
sudo mkdir -p /etc/mewser-gateway
```

Create `/etc/mewser-gateway/gateway.env`:

```bash
sudo bash -c "cat > /etc/mewser-gateway/gateway.env" <<EOF
# Mewser Gateway Environment Configuration
MEWSER_GATEWAY_AUTH_TOKEN=${GW_TOKEN}
MEWSER_GATEWAY_REQUIRE_AUTH=true
MEWSER_GATEWAY_BIND=127.0.0.1:4040
MEWSER_GATEWAY_ALLOW_NON_LOOPBACK=false
EOF
```

> [!NOTE]
> If deploying under Topology 2 (SOCKS5 mode), replace `127.0.0.1:4040` with `<SERVER_PUBLIC_IP>:4040` and set `MEWSER_GATEWAY_ALLOW_NON_LOOPBACK=true`. Then apply the firewall rule in Section 2.
>
> **Important**: Topology 2 requires a public IPv4 address directly assigned to the server's network interface (e.g. Hetzner, OVH, Linode, DigitalOcean). For 1:1 NAT cloud providers (AWS EC2, GCP, Azure), operators should use Topology 1 (Fixed TCP) because public IPs are not assigned to local interfaces and MasterDNS SOCKS5 rejects private IP targets.

Secure the configuration directory and environment file with strict root-only permissions:

```bash
sudo chown -R root:root /etc/mewser-gateway
sudo chmod 700 /etc/mewser-gateway
sudo chmod 600 /etc/mewser-gateway/gateway.env
```

---

## 8. Installing and Enabling the systemd Service

Copy the hardened systemd unit file to `/etc/systemd/system/`:

```bash
sudo cp packaging/gateway/systemd/mewser-gateway.service /etc/systemd/system/
sudo chown root:root /etc/systemd/system/mewser-gateway.service
sudo chmod 644 /etc/systemd/system/mewser-gateway.service
```

Reload systemd daemon, enable the service to start at boot, and launch it immediately:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now mewser-gateway.service
```

---

## 9. Checking Service Status and Logs

Verify that the service is active and running:

```bash
sudo systemctl status mewser-gateway.service
```

Expected status output:
```text
● mewser-gateway.service - Mewser Gateway Content Extraction Service
     Loaded: loaded (/etc/systemd/system/mewser-gateway.service; enabled; ...)
     Active: active (running) since ...
   Main PID: 12345 (mewser-gateway)
      Tasks: 2 (limit: ...)
     Memory: 4.2M
        CPU: 12ms
     CGroup: /system.slice/mewser-gateway.service
             └─12345 /usr/local/bin/mewser-gateway
```

View live service logs:

```bash
sudo journalctl -u mewser-gateway.service -f
```

---

## 10. Testing Local Service Health

From the server shell, test the unauthenticated `/health` endpoint:

```bash
curl -i http://127.0.0.1:4040/health
```

Expected response:
```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 15

{"status":"ok"}
```

Test extraction endpoint without authentication (must return HTTP 401 Unauthorized):

```bash
curl -i -X POST http://127.0.0.1:4040/extract \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com/"}'
```

Expected response:
```http
HTTP/1.1 401 Unauthorized
```

Test extraction endpoint with the valid Bearer token:

```bash
curl -i -X POST http://127.0.0.1:4040/extract \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${GW_TOKEN}" \
  -d '{"url":"https://example.com/"}'
```

Expected response:
```http
HTTP/1.1 200 OK
Content-Type: application/json
...
```

---

## 11. Configuring the Mewser Client

In your local Mewser client:

1. Open **Settings** -> **Resilient Gateway**.
2. Set **Gateway Endpoint**:
   - For Topology 1: `127.0.0.1:4040` (with Transport set to Fixed TCP).
   - For Topology 2: `<SERVER_PUBLIC_IP>:4040` (with Transport set to SOCKS5).
3. In **Gateway Authentication**:
   - Paste the generated token into the token field.
   - Click **Save Settings**. The status badge updates to `● Configured (Vault)`.
4. Click **Test Health**: Mewser queries `/health` across the active tunnel. A green checkmark confirms end-to-end connectivity.

---

## 12. Updating the Gateway

To update the Gateway to a newer release:

1. Download the new release package and verify checksums.
2. Stop the service:
   ```bash
   sudo systemctl stop mewser-gateway.service
   ```
3. Overwrite the binary:
   ```bash
   sudo cp mewser-gateway /usr/local/bin/mewser-gateway
   sudo chmod 755 /usr/local/bin/mewser-gateway
   ```
4. Start the service:
   ```bash
   sudo systemctl start mewser-gateway.service
   ```
5. Verify health:
   ```bash
   curl -s http://127.0.0.1:4040/health
   ```

---

## 13. Safely Removing the Service

To completely uninstall the service:

```bash
sudo systemctl stop mewser-gateway.service
sudo systemctl disable mewser-gateway.service
sudo rm -f /etc/systemd/system/mewser-gateway.service
sudo systemctl daemon-reload
sudo rm -f /usr/local/bin/mewser-gateway
sudo rm -rf /etc/mewser-gateway
sudo userdel mewser-gateway
```
