//! Privileged command execution via `sudo -S`.
//!
//! arpmac collects the administrator password in a **TUI modal** (not a macOS
//! dialog) and pipes it to `sudo` on stdin.
//!
//! ```text
//!   TUI password modal
//!         │ Enter
//!         ▼
//!   sudo -S pfctl …     ← password written to child stdin
//!         │
//!         ▼
//!   pfctl loads anchor rules
//! ```
//!
//! The password is cached in [`crate::app::App`] for the session after first
//! successful use.

use std::io::Write;
use std::process::{Command, Output, Stdio};

/// Run `sudo -S <args…>` with `password` supplied on stdin.
///
/// `-S` tells sudo to read the password from standard input instead of the
/// terminal — required because the TUI owns the terminal in raw mode.
///
/// # Errors
///
/// Returns [`std::io::Error`] if the process cannot be spawned or waited on.
/// A non-zero sudo exit status is **not** an `Err`; check [`Output::status`].
pub fn run(password: &str, args: &[&str]) -> std::io::Result<Output> {
    let mut child = Command::new("sudo")
        .arg("-S")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(format!("{password}\n").as_bytes())?;
    }
    child.wait_with_output()
}
