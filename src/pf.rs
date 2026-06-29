//! Packet Filter (PF) block list persistence and reload.
//!
//! arpmac blocks clients by loading rules into a dynamic PF **anchor** named
//! `arpmac/block`. This avoids editing system `/etc/pf.conf`.
//!
//! ## Rule file format (`~/.config/arpmac/blocks.pf`)
//!
//! ```text
//! block drop quick from 192.168.2.5 to any
//! block drop quick from any to 192.168.2.5
//! ```
//!
//! Each blocked IP gets two rules (egress + ingress).
//!
//! ## Reload command
//!
//! ```text
//! sudo -S pfctl -a arpmac/block -f ~/.config/arpmac/blocks.pf
//! ```
//!
//! When the block list is empty, the anchor is flushed instead:
//!
//! ```text
//! sudo -S pfctl -a arpmac/block -F all
//! ```

use std::fs;
use std::io;
use std::path::PathBuf;

mod dirs {
    use std::path::PathBuf;

    /// Return `~/.config/arpmac`, falling back to `/tmp/arpmac`.
    pub fn config_dir() -> PathBuf {
        std::env::var_os("HOME")
            .map(|h| PathBuf::from(h).join(".config").join("arpmac"))
            .unwrap_or_else(|| PathBuf::from("/tmp/arpmac"))
    }
}

/// Absolute path to the generated PF rules file.
pub fn blocks_path() -> PathBuf {
    dirs::config_dir().join("blocks.pf")
}

/// Read blocked IPv4 addresses from the on-disk rules file.
///
/// Parses only outbound rules (`block drop quick from <ip> to any`),
/// ignoring reverse rules that start with `any`.
pub fn load_blocked() -> io::Result<Vec<String>> {
    let path = blocks_path();
    if !path.exists() {
        return Ok(vec![]);
    }
    let text = fs::read_to_string(path)?;
    Ok(text
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("block drop quick from ")?;
            let ip = rest.split_whitespace().next()?;
            if ip == "any" {
                return None;
            }
            Some(ip.to_string())
        })
        .collect())
}

/// Rewrite `blocks.pf` with rules for every IP in `ips`.
fn write_rules(ips: &[&str]) -> io::Result<()> {
    let dir = dirs::config_dir();
    fs::create_dir_all(&dir)?;
    let mut rules = String::new();
    for ip in ips {
        rules.push_str(&format!("block drop quick from {ip} to any\n"));
        rules.push_str(&format!("block drop quick from any to {ip}\n"));
    }
    fs::write(blocks_path(), rules)
}

/// Add `ip` to the block list and reload the PF anchor.
///
/// Requires a valid administrator password for [`crate::sudo::run`].
pub fn block(ip: &str, password: &str) -> Result<(), String> {
    let mut ips = load_blocked().map_err(|e| e.to_string())?;
    if ips.iter().any(|x| x == ip) {
        return reload(password).map_err(|e| e.to_string());
    }
    ips.push(ip.to_string());
    let refs: Vec<&str> = ips.iter().map(String::as_str).collect();
    write_rules(&refs).map_err(|e| e.to_string())?;
    reload(password).map_err(|e| e.to_string())
}

/// Remove `ip` from the block list and reload the PF anchor.
pub fn unblock(ip: &str, password: &str) -> Result<(), String> {
    let ips = load_blocked().map_err(|e| e.to_string())?;
    let refs: Vec<&str> = ips
        .iter()
        .filter(|x| *x != ip)
        .map(String::as_str)
        .collect();
    write_rules(&refs).map_err(|e| e.to_string())?;
    reload(password).map_err(|e| e.to_string())
}

/// Apply the current `blocks.pf` to the running PF anchor via `pfctl`.
fn reload(password: &str) -> io::Result<()> {
    let ips = load_blocked()?;
    if ips.is_empty() {
        let out = crate::sudo::run(password, &["pfctl", "-a", "arpmac/block", "-F", "all"])?;
        if out.status.success() {
            return Ok(());
        }
        return Ok(());
    }
    let path = blocks_path().to_string_lossy().to_string();
    let out = crate::sudo::run(password, &["pfctl", "-a", "arpmac/block", "-f", &path])?;
    if out.status.success() {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "{}",
        String::from_utf8_lossy(&out.stderr)
    )))
}
