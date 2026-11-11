# Mewser Desktop for Linux (x86_64)

Dual-mode web browser with direct standard rendering and resilient text mode over DNS tunnels.

## Overview

Mewser Desktop provides:
1. **Standard Web Mode**: Full web browsing engine powered by GTK 3 and WebKitGTK with support for modern web standards, CSS, and media.
2. **Resilient Text Mode**: Server-assisted article and text extraction routed over encrypted DNS tunnels (via MasterDNS) to your self-hosted Mewser Gateway. Bypasses restrictive censorship and network throttling with zero auto-fetched media and minimal payload sizes.

## Runtime Requirements

* **Architecture**: Linux `x86_64` (`x86_64-unknown-linux-gnu`)
* **Desktop Toolkit**: GTK 3 (`libgtk-3-0` >= 3.24.0 or `libgtk-3-0t64` >= 3.24.0)
* **Web Engine**: WebKitGTK 4.1 (`libwebkit2gtk-4.1-0` >= 2.40.0)
* **HTTP Library**: libsoup 3 (`libsoup-3.0-0` >= 3.0.0)
* **C Library**: glibc >= 2.34 (`libc6` >= 2.34)

### Installing Runtime Dependencies on Debian/Ubuntu:
```bash
sudo apt update
sudo apt install -y libgtk-3-0 libwebkit2gtk-4.1-0 libsoup-3.0-0
```

### Installing Runtime Dependencies on Fedora/RHEL:
```bash
sudo dnf install -y gtk3 webkit2gtk4.1 libsoup3
```

### Installing Runtime Dependencies on Arch Linux:
```bash
sudo pacman -S gtk3 webkit2gtk-4.1 libsoup3
```

---

## Installation

### Option 1: Debian/Ubuntu Native Package (`.deb`)

```bash
sudo dpkg -i mewser-desktop_0.1.1_amd64.deb
# Or via apt to automatically install any missing dependencies:
sudo apt install ./mewser-desktop_0.1.1_amd64.deb
```

### Option 2: Generic Linux Archive (`.tar.gz`)

```bash
tar -xzf mewser-desktop-linux-x86_64.tar.gz
cd mewser-desktop-linux-x86_64

# System-wide installation (requires sudo):
sudo ./install.sh

# Or user-local installation (no root required):
./install.sh --user
```

---

## Uninstallation

* **Debian/Ubuntu (`.deb`)**:
  ```bash
  sudo apt remove mewser-desktop
  ```
* **System-wide tarball**:
  ```bash
  sudo /usr/local/bin/mewser-desktop-uninstall
  ```
* **User-local tarball**:
  ```bash
  ~/.local/bin/mewser-desktop-uninstall
  ```

---

## Configuration & Resilient Mode Setup

1. Launch **Mewser** from your application menu or terminal (`mewser-desktop`).
2. Open **Settings -> Resilient Gateway**.
3. Select your deployment transport:
   * **Fixed TCP**: Transport set to `Fixed TCP`, listener set to `127.0.0.1:1080` (your local MasterDNS client listener).
   * **SOCKS5**: Transport set to `SOCKS5`, proxy set to `127.0.0.1:1080`, gateway endpoint set to `<YOUR_VPS_PUBLIC_IP>:4040`.
4. Enter your Gateway Bearer Authentication Token (generated when deploying `deploy-gateway.sh` on your VPS).
5. Switch the address bar mode badge from `[Standard]` to `[Resilient]` to browse in text mode over your DNS tunnel.
