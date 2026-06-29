//! Binary entry point for **monit**.
//!
//! On macOS, delegates to [`monit::run`]. On other platforms, prints an error and exits.
//!
//! ```text
//! cargo run          # run the TUI
//! cargo doc --open   # read the full developer guide
//! ```

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("monit requires macOS");
    std::process::exit(1);
}

#[cfg(target_os = "macos")]
fn main() -> std::io::Result<()> {
    monit::run()
}
