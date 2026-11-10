# Mewser Gateway — Operator Guide: Legacy VPS Migration

This procedure guides an operator in safely updating an existing staging/developer VPS running the legacy Mewser Gateway layout to the canonical Pass 8.3.6+ deployment layout.

---

## 1. Context & Legacy Architecture

The staging VPS currently hosts:
* **MasterDNS Server Daemon**: Running independently (`masterdnsvpn.service`). **Do NOT touch or reinstall MasterDNS.**
* **Legacy Gateway Service**: `mewser-gateway.service` running as service identity `mewser:mewser` with non-empty `CapabilityBoundingSet`.
* **Legacy Configuration**: `/etc/mewser/gateway.env` (permissions `0600`, directory `0700` owned by `root:root`).
* **Legacy Firewall Helper & Service**: `/usr/local/sbin/mewser-firewall-ensure` and `/etc/systemd/system/mewser-firewall.service`.
* **Legacy Binary**: `/usr/local/bin/mewser-gateway` (older pre-Pass 8.3.6 build).

### Canonical Target Architecture:
* **Service Identity**: Unprivileged system account `mewser-gateway:mewser-gateway`.
* **Configuration**: `/etc/mewser-gateway/gateway.env` (permissions `0600`, directory `0700` owned by `root:root`).
* **Systemd Hardening**: Empty `CapabilityBoundingSet=` and `AmbientCapabilities=`, `NoNewPrivileges=true`, `ProtectSystem=strict`.
* **Firewall Isolation**: Canonical helper `/usr/local/bin/mewser-gateway-firewall` managed by systemd drop-in `ExecStartPre=+... check` and persistent lifecycle unit `mewser-gateway-firewall.service`.

---

## 2. Invariants & Safety Guarantees

1. **Token Preservation**: The existing 32-byte Bearer token (`MEWSER_GATEWAY_AUTH_TOKEN`) is automatically preserved. Clients connected to this server do NOT need to update their credentials.
2. **Bind Address Preservation**: The existing bind address and non-loopback permissions are preserved.
3. **MasterDNS Isolation**: Zero files or systemd units associated with MasterDNS are modified.
4. **Root-Only Backups**: All legacy configuration and service unit files are backed up atomically with `0600`/`0700` root-only permissions prior to candidate execution.
5. **Atomic Rollback**: If the candidate binary fails health verification, the installer restores the legacy binary, units, and configuration automatically.

---

## 3. Step-by-Step Operator Migration Procedure

Execute these steps on the staging VPS:

### Step 1: Download the Published Release Package

From the latest GitHub Release:

```bash
mkdir -p /tmp/mewser-upgrade
cd /tmp/mewser-upgrade

# Download release archive and checksum
curl -sSL -O https://github.com/arshiacomplus/Mewser/releases/latest/download/mewser-gateway-linux-x86_64.tar.gz
curl -sSL -O https://github.com/arshiacomplus/Mewser/releases/latest/download/mewser-gateway-linux-x86_64.tar.gz.sha256
```

### Step 2: Verify Checksum

```bash
sha256sum -c mewser-gateway-linux-x86_64.tar.gz.sha256
# Expected output: mewser-gateway-linux-x86_64.tar.gz: OK
```

### Step 3: Unpack Release Package

```bash
tar -xzf mewser-gateway-linux-x86_64.tar.gz
# Release contents are extracted directly into the current directory
```

### Step 4: Verify Current Legacy Status

```bash
sudo ./deploy-gateway.sh status
```

Expected diagnostic output:
```text
Binary Installed : /usr/local/bin/mewser-gateway
Configuration    : Legacy layout detected (/etc/mewser/gateway.env)
Bind Address     : <CURRENT_BIND_ADDRESS>
Auth Token       : [Configured] (in legacy config)
Migration Status : Action required - Legacy installation detected. Run 'deploy-gateway.sh update' or 'deploy-gateway.sh migrate'.
```

### Step 5: Execute Migration

Run either `update` or `migrate` with sudo:

```bash
sudo ./deploy-gateway.sh update
```

The script will:
1. Detect the legacy layout.
2. Extract the existing Bearer token and bind address.
3. Create root-only backups:
   * `/etc/mewser/gateway.env.legacy.bak` (mode 0600)
   * `/etc/systemd/system/mewser-gateway.service.legacy.bak`
4. Ensure the canonical unprivileged service user `mewser-gateway` exists.
5. Create `/etc/mewser-gateway/gateway.env` (mode 0600 root:root).
6. Atomically install the updated `mewser-gateway` binary to `/usr/local/bin/mewser-gateway`.
7. Install the canonical systemd unit with empty capabilities.
8. Migrate firewall helpers to `/usr/local/bin/mewser-gateway-firewall` and remove legacy `mewser-firewall.service` without dropping active firewall rules.
9. Restart `mewser-gateway.service`.
10. Query `/health` to verify that the updated service is active and responsive.

### Step 6: Post-Migration Verification

1. Verify status:
   ```bash
   sudo ./deploy-gateway.sh status
   ```
   Confirm `Configuration: /etc/mewser-gateway/gateway.env (mode 600)` and `Service State: active (running)`.

2. Query local health (using the actual configured bind address):
   ```bash
   BIND_ADDR="$(grep -E "^MEWSER_GATEWAY_BIND=" /etc/mewser-gateway/gateway.env | cut -d= -f2- | tr -d '[:space:]')"
   curl -s "http://${BIND_ADDR}/health"
   # Expected response: {"status":"ok"}
   ```
   *Note*: Never assume `127.0.0.1:4040`. On Topology B hosts, the Gateway binds to the server's public IPv4 interface (routed internally via `lo`), so querying `127.0.0.1:4040` directly would fail with connection refused.

3. Confirm MasterDNS remains active:
   ```bash
   systemctl is-active masterdnsvpn.service
   # Expected response: active
   ```

---

## 4. Manual Rollback (Contingency Only)

If automated rollback fails or manual recovery is required:

```bash
# 1. Stop candidate service
sudo systemctl stop mewser-gateway.service

# 2. Restore legacy systemd unit
sudo cp -p /etc/systemd/system/mewser-gateway.service.legacy.bak /etc/systemd/system/mewser-gateway.service

# 3. Reload and restart legacy service
sudo systemctl daemon-reload
sudo systemctl restart mewser-gateway.service

# 4. Verify legacy health (using configured bind address)
LEGACY_BIND="$(grep -E "^MEWSER_GATEWAY_BIND=" /etc/mewser-gateway/gateway.env 2>/dev/null | cut -d= -f2- | tr -d '[:space:]')"
[ -z "$LEGACY_BIND" ] && LEGACY_BIND="$(grep -oP 'MEWSER_GATEWAY_BIND=\K[^\s"]+' /etc/systemd/system/mewser-gateway.service 2>/dev/null || echo "127.0.0.1:4040")"
curl -s "http://${LEGACY_BIND}/health"
```
