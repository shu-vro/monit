//! Binary entry point for **arpmac**.
//!
//! On macOS, delegates to [`arpmac::run`]. On other platforms, prints an error and exits.
//!
//! ```text
//! cargo run          # run the TUI
//! cargo doc --open   # read the full developer guide
//! ```

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("arpmac requires macOS");
    std::process::exit(1);
}

#[cfg(target_os = "macos")]
fn main() -> std::io::Result<()> {
    arpmac::run()
}
