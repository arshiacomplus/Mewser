use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const OFFICIAL_UPSTREAM_REPO: &str = "https://github.com/masterking32/MasterDnsVPN";
pub const PINNED_RELEASE_VERSION: &str = "v2026.06.13.234407-7de2476";

pub const LINUX_AMD64_BINARY_NAME: &str =
    "MasterDnsVPN_Client_Linux_AMD64_v2026.06.13.234407-7de2476";
pub const LINUX_AMD64_BINARY_SHA256: &str =
    "dbe8b7c8de12e76ac3fd8d6eca4a98d43e358173193be24a886f290220512d67";

pub const LINUX_AMD64_TARBALL_NAME: &str = "MasterDnsVPN_Client_Linux_AMD64.tar.gz";
pub const LINUX_AMD64_TARBALL_SHA256: &str =
    "f28d760402fd3b1a7bb9b7f74168ddb11c41467e44b987d4f4c89016cb7fcdac";

/// Pure-Rust streaming SHA-256 implementation (FIPS 180-4) with zero external crate dependencies.
pub fn compute_sha256(data: &[u8]) -> [u8; 32] {
    let k: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, part) in chunk.chunks_exact(4).enumerate() {
            w[i] = u32::from_be_bytes(part.try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, val) in h.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&val.to_be_bytes());
    }
    out
}

pub fn compute_file_sha256(path: &Path) -> Result<String, std::io::Error> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let hash = compute_sha256(&buffer);
    Ok(hash.iter().map(|b| format!("{b:02x}")).collect())
}

/// Discovers the official MasterDNS client binary across predictable standard locations.
pub fn locate_masterdns_binary() -> Result<PathBuf, String> {
    // 1. Explicit override via environment variable
    if let Ok(env_path) = std::env::var("MEWSER_MASTERDNS_BIN") {
        let p = PathBuf::from(env_path);
        if p.is_file() {
            validate_masterdns_binary(&p)?;
            return Ok(p);
        }
    }

    let binary_names = [LINUX_AMD64_BINARY_NAME, "mdns", "masterdns"];

    // 2. User local share (~/.local/share/mewser/bin/ or $XDG_DATA_HOME/mewser/bin/)
    let user_bin_dir = if let Ok(data_home) = std::env::var("XDG_DATA_HOME") {
        PathBuf::from(data_home).join("mewser/bin")
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".local/share/mewser/bin")
    } else {
        PathBuf::from(".local/share/mewser/bin")
    };

    for name in &binary_names {
        let candidate = user_bin_dir.join(name);
        if candidate.is_file() && validate_masterdns_binary(&candidate).is_ok() {
            return Ok(candidate);
        }
    }

    // 3. Executable adjacent directory or adjacent bin/
    if let Ok(curr_exe) = std::env::current_exe() {
        if let Some(parent) = curr_exe.parent() {
            for name in &binary_names {
                let adj = parent.join(name);
                if adj.is_file() && validate_masterdns_binary(&adj).is_ok() {
                    return Ok(adj);
                }
                let adj_bin = parent.join("bin").join(name);
                if adj_bin.is_file() && validate_masterdns_binary(&adj_bin).is_ok() {
                    return Ok(adj_bin);
                }
            }
        }
    }

    // 4. Standard system PATH lookup
    // Never execute arbitrary binaries from an untrusted relative or current working directory.
    if let Some(paths) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&paths) {
            // Reject relative directories, empty paths, or current working directory
            if !dir.is_absolute() {
                continue;
            }
            for name in &binary_names {
                let candidate = dir.join(name);
                if candidate.is_file() && validate_masterdns_binary(&candidate).is_ok() {
                    return Ok(candidate);
                }
            }
        }
    }

    Err(format!(
        "MasterDNS client executable not found. Looked in standard locations: \
        ~/.local/share/mewser/bin/, application-adjacent directories, and system PATH. \
        Please place the official '{LINUX_AMD64_BINARY_NAME}' binary in ~/.local/share/mewser/bin/ (with executable permissions) or set MEWSER_MASTERDNS_BIN."
    ))
}

/// Validates that a binary exists, is executable, and optionally verifies SHA-256 against pinned release.
pub fn validate_masterdns_binary(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err(format!(
            "MasterDNS binary does not exist at {}",
            path.display()
        ));
    }
    if !path.is_file() {
        return Err(format!("MasterDNS path is not a file: {}", path.display()));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path)
            .map_err(|e| format!("Failed to read metadata for {}: {e}", path.display()))?;
        if (metadata.permissions().mode() & 0o111) == 0 {
            return Err(format!(
                "MasterDNS binary at {} is not executable (missing chmod +x)",
                path.display()
            ));
        }
    }

    // Check if filename matches pinned release; if so, verify SHA-256
    let filename = path.file_name().and_then(|f| f.to_str()).unwrap_or("");
    if filename == LINUX_AMD64_BINARY_NAME {
        let hash = compute_file_sha256(path)
            .map_err(|e| format!("Failed to compute SHA256 of {}: {e}", path.display()))?;
        if hash != LINUX_AMD64_BINARY_SHA256 {
            return Err(format!(
                "MasterDNS binary checksum mismatch! Expected: {LINUX_AMD64_BINARY_SHA256}, Got: {hash}"
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_known_vector() {
        let hash = compute_sha256(b"hello world");
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_binary_discovery_error_message_has_no_developer_paths() {
        let prev = std::env::var("MEWSER_MASTERDNS_BIN").ok();
        std::env::remove_var("MEWSER_MASTERDNS_BIN");

        let err = locate_masterdns_binary();
        if let Err(msg) = err {
            assert!(!msg.contains("/mnt/D84AE43F4AE41C4E"));
            assert!(!msg.contains("Mylinxfiles"));
            assert!(msg.contains("~/.local/share/mewser/bin/"));
            assert!(msg.contains(LINUX_AMD64_BINARY_NAME));
        }

        if let Some(v) = prev {
            std::env::set_var("MEWSER_MASTERDNS_BIN", v);
        }
    }
}
