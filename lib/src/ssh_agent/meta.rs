//! Live device metadata collected fresh on every sign request.
//!
//! The snapshot is a flat `HashMap<String, String>` — no fixed schema.
//! Standard keys:
//!   `hostname`           — system hostname
//!   `net.<iface>.ip`     — IPv4/IPv6 address for each interface
//!   `net.<iface>.mac`    — MAC address for each interface
//!   `disk.total_gb`      — total disk size of the root filesystem
//!   `disk.free_gb`       — available disk space on the root filesystem
//!
//! Unknown keys in received messages must be silently ignored.

use std::collections::HashMap;

/// Collect a live device snapshot.  Called fresh on every sign request.
pub fn collect() -> HashMap<String, String> {
    let mut m = HashMap::new();

    // ── Hostname ──────────────────────────────────────────────────────────────
    if let Ok(h) = hostname::get() {
        if let Ok(s) = h.into_string() {
            m.insert("hostname".into(), s);
        }
    }

    // ── Network interfaces ────────────────────────────────────────────────────
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    collect_interfaces(&mut m);

    // ── Disk space (root filesystem) ──────────────────────────────────────────
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    collect_disk(&mut m);

    m
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn collect_interfaces(m: &mut HashMap<String, String>) {
    use std::process::Command;

    // Use `ifconfig` on macOS, `ip addr` on Linux.
    #[cfg(target_os = "macos")]
    let output = Command::new("ifconfig").output();
    #[cfg(target_os = "linux")]
    let output = Command::new("ip").args(["addr", "show"]).output();

    if let Ok(out) = output {
        parse_ifconfig(&String::from_utf8_lossy(&out.stdout), m);
    }
}

/// Minimal line-by-line parser — extracts interface names, IPs, and MACs
/// from `ifconfig` (macOS) / `ip addr` (Linux) output without extra deps.
fn parse_ifconfig(text: &str, m: &mut HashMap<String, String>) {
    let mut current: Option<String> = None;

    // First pass: collect all data.
    for line in text.lines() {
        // Interface header: "en0: flags=…" or "2: en0: <…>"
        if !line.starts_with(' ') && !line.starts_with('\t') {
            // Strip leading number (Linux ip addr format).
            let part = line.split_once(':').map(|x| x.1).unwrap_or(line).trim();
            let iface = part.split(':').next().unwrap_or("").trim().to_string();
            if !iface.is_empty() && iface != "flags" {
                current = Some(iface);
            }
        }

        let Some(ref iface) = current else { continue };
        let trimmed = line.trim();

        // inet / inet6 — skip loopback and link-local addresses.
        if let Some(rest) = trimmed.strip_prefix("inet6 ") {
            let ip = rest
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_end_matches('%');
            // Skip loopback (::1) and link-local (fe80::).
            let is_loopback = ip == "::1";
            let is_link_local = ip.starts_with("fe80");
            if !ip.is_empty() && !is_loopback && !is_link_local {
                m.entry(format!("net.{iface}.ip"))
                    .or_insert_with(|| ip.to_string());
            }
        } else if let Some(rest) = trimmed.strip_prefix("inet ") {
            let ip = rest.split_whitespace().next().unwrap_or("");
            // Skip loopback (127.x.x.x).
            if !ip.is_empty() && !ip.starts_with("127.") {
                m.entry(format!("net.{iface}.ip"))
                    .or_insert_with(|| ip.to_string());
            }
        }

        // ether (macOS) / link/ether (Linux)
        for prefix in &["ether ", "link/ether "] {
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                let mac = rest.split_whitespace().next().unwrap_or("");
                if !mac.is_empty() {
                    m.insert(format!("net.{iface}.mac"), mac.to_string());
                }
            }
        }
    }

    // Second pass: remove MAC entries for interfaces that have no routable IP
    // (e.g. loopback lo0 ends up with no .ip entry after filtering).
    let orphan_macs: Vec<String> = m
        .keys()
        .filter(|k| k.ends_with(".mac"))
        .map(|k| k.trim_end_matches(".mac").to_string())
        .filter(|iface| !m.contains_key(&format!("{iface}.ip")))
        .map(|iface| format!("{iface}.mac"))
        .collect();
    for key in orphan_macs {
        m.remove(&key);
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn collect_disk(m: &mut HashMap<String, String>) {
    use std::process::Command;

    // `df -k /` gives 1 KiB blocks.
    if let Ok(out) = Command::new("df").args(["-k", "/"]).output() {
        let text = String::from_utf8_lossy(&out.stdout);
        // Second line: filesystem  1K-blocks  used  available  ...
        if let Some(line) = text.lines().nth(1) {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.len() >= 4 {
                if let (Ok(total), Ok(avail)) = (cols[1].parse::<u64>(), cols[3].parse::<u64>()) {
                    m.insert("disk.total_gb".into(), format!("{}", total / 1_048_576));
                    m.insert("disk.free_gb".into(), format!("{}", avail / 1_048_576));
                }
            }
        }
    }
}
