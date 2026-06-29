//! # monit — macOS Internet Sharing manager
//!
//! **monit** is a terminal UI (TUI) that gives you router-like visibility and control
//! over devices connected through **macOS Internet Sharing** (Ethernet → Wi‑Fi).
//! Apple's built-in sharing has no client list, no blocking, and no bandwidth view —
//! this project fills that gap using only native macOS tools and two Rust crates.
//!
//! ## Quick start
//!
//! ```text
//! # Prerequisites: macOS, Rust (rustup), Internet Sharing enabled
//! cargo build --release
//! cargo run --release
//! cargo doc --no-deps --open   # opens this documentation
//! ```
//!
//! ## The problem
//!
//! When you enable **Internet Sharing**, your Mac becomes a small Wi‑Fi router.
//! Unlike a real router, macOS does not expose:
//!
//! - A live client list in System Settings
//! - MAC filtering or per-device blocking
//! - Per-client bandwidth usage
//!
//! Power users resort to manual Terminal commands (`arp -a`, `nmap`, `pfctl`, `iftop`).
//! **monit** wraps those primitives into one keyboard-driven interface.
//!
//! ## How Internet Sharing works (macOS)
//!
//! ```text
//!   [ Ethernet / upstream ]          [ Your Mac ]              [ Wi‑Fi clients ]
//!          en0  ─────────────────►  NAT + DHCP               phones, laptops
//!                                   bridge100  ◄────────────►  192.168.2.x
//!                                   192.168.2.1
//!                                        │
//!                                   pfctl (Packet Filter)
//!                                   bootpd (DHCP server)
//! ```
//!
//! When sharing is **on**, macOS creates a hidden bridge interface (usually
//! [`bridge100`](https://apple.stackexchange.com/questions/173563/how-is-the-hidden-interface-bridge100-working))
//! with gateway `192.168.2.1/24`. The DHCP daemon [`bootpd`](x-man-page://8/bootpd)
//! assigns leases and writes them to [`/var/db/dhcpd_leases`](file:///var/db/dhcpd_leases).
//!
//! When sharing is **off**, `bridge100` does not exist and monit shows `INACTIVE`.
//!
//! ## Terminology
//!
//! | Term | Meaning |
//! |------|---------|
//! | **Internet Sharing** | macOS feature: share one interface's internet to another (e.g. Ethernet → Wi‑Fi). |
//! | **bridge100** | Virtual bridge interface created when sharing is active; clients connect here. |
//! | **DHCP lease** | Record that a device was assigned an IP. Stored in `/var/db/dhcpd_leases` — includes *past* guests. |
//! | **ARP** | Address Resolution Protocol. Maps IP → MAC on the local network. `arp -a` shows who the Mac has talked to recently. |
//! | **MAC address** | Hardware ID of a network adapter (e.g. `aa:bb:cc:dd:ee:ff`). First 3 bytes = OUI (vendor). |
//! | **PF / pfctl** | macOS **Packet Filter** firewall. `pfctl` loads rules; we use a dynamic **anchor** `monit/block`. |
//! | **Anchor** | Named sub-ruleset in PF, loaded at runtime without editing `/etc/pf.conf`. |
//! | **nettop** | Built-in macOS tool for per-connection byte counters (like `iftop`, but native). |
//! | **TUI** | Text User Interface — full-screen terminal UI (as opposed to GUI or plain CLI). |
//! | **Ratatui** | Rust library for building TUIs (successor to tui-rs). |
//! | **crossterm** | Cross-platform terminal manipulation (raw mode, keyboard events). |
//! | **● now / past** | monit labels: *now* = on bridge ARP right now; *past* = only in DHCP history. |
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │  main.rs          entry point, terminal setup/teardown        │
//! │       │                                                     │
//! │       ▼                                                     │
//! │  lib::run()       event loop (250 ms tick, 10 s auto-refresh)│
//! │       │                                                     │
//! │       ├── app.rs  App state, keys, background threads       │
//! │       │      │                                              │
//! │       │      ├── net.rs   discovery (leases, ARP, nettop)   │
//! │       │      ├── pf.rs    block list + pfctl reload         │
//! │       │      └── sudo.rs  pipe password to sudo -S          │
//! │       │                                                     │
//! │       └── ui.rs   ratatui draw (table, modals, status)      │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! ### Refresh data flow
//!
//! ```text
//!  User presses 'r' (or 10 s timer)
//!         │
//!         ▼
//!  app::App::refresh() ── spawns thread ─────────────────────────┐
//!         │                                                       │
//!         │  (UI stays responsive, shows "Refreshing…")           │
//!         │                                                       ▼
//!         │                              pf::load_blocked()  ← ~/.config/monit/blocks.pf
//!         │                              net::detect_sharing() ← ifconfig bridge100
//!         │                              net::discover_clients()
//!         │                                   ├─ connected_on_bridge() ← arp -a
//!         │                                   ├─ parse_leases()      ← /var/db/dhcpd_leases
//!         │                                   ├─ ping()              ← ping -c 1
//!         │                                   └─ nettop_bandwidth()  ← nettop -L 1 …
//!         │                                                       │
//!         ◄──────── RefreshMsg::Done { sharing, clients } ────────┘
//!         │
//!         ▼
//!  ui::draw() renders updated table
//! ```
//!
//! ### Block data flow
//!
//! ```text
//!  User presses 'b' on selected client
//!         │
//!         ▼
//!  Modal::Password (TUI, masked input)
//!         │ Enter
//!         ▼
//!  pf::block(ip, password)
//!         ├─ append IP to ~/.config/monit/blocks.pf
//!         └─ sudo::run(password, ["pfctl", "-a", "monit/block", "-f", …])
//!                   └─ sudo -S  (password on stdin)
//!         │
//!         ▼
//!  Client loses internet; row shows BLOCKED
//! ```
//!
//! ## What you need to learn (build-from-scratch curriculum)
//!
//! ### 1. Rust basics
//! - Ownership, `Result`/`Option`, modules, `std::process::Command`
//! - [The Rust Book](https://doc.rust-lang.org/book/)
//!
//! ### 2. Terminal / TUI
//! - **Raw mode**: keyboard input byte-by-byte without line buffering
//! - **Alternate screen**: full-screen app that restores on exit
//! - Event loop: poll keyboard → update state → draw → repeat
//! - [Ratatui tutorial](https://ratatui.rs/)
//!
//! ### 3. Networking (macOS-specific)
//! - IPv4 subnets and CIDR (`192.168.2.0/24`)
//! - DHCP vs ARP vs ping as liveness signals
//! - Read: `man ifconfig`, `man arp`, `man pfctl`, `man nettop`
//!
//! ### 4. Process design choices (this project)
//! - **YAGNI**: no nmap/iftop dependencies — shell out to what's already on macOS
//! - **Background threads + channels**: slow `ping`/`nettop` must not freeze the TUI
//! - **Session password cache**: ask once per run, reuse for subsequent `pfctl` calls
//! - **Online vs past**: DHCP file is historical; bridge ARP is the live signal
//!
//! ## Reproduce from scratch
//!
//! ### Step 1 — Project skeleton
//!
//! ```text
//! cargo new monit
//! ```
//!
//! Add to `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! ratatui = "0.29"
//! crossterm = "0.28"
//! ```
//!
//! ### Step 2 — Module layout
//!
//! ```text
//! src/
//!   lib.rs    crate docs + run() event loop
//!   main.rs   calls monit::run()
//!   app.rs    state machine
//!   net.rs    shell commands for discovery
//!   pf.rs     PF rule file + pfctl
//!   sudo.rs   sudo -S wrapper
//!   ui.rs     ratatui widgets
//! ```
//!
//! ### Step 3 — Implement in order
//!
//! 1. **`net::detect_sharing`** — parse `ifconfig bridge100` for inet + netmask
//! 2. **`net::discover_clients`** — leases + bridge ARP + ping + nettop
//! 3. **`ui::draw`** — table with columns IP, MAC, Name, Online, bandwidth
//! 4. **`app::App`** — key handling, refresh thread
//! 5. **`pf::block` / `pf::unblock`** — persist rules, `pfctl -a monit/block`
//! 6. **`sudo::run`** — TUI password → `sudo -S`
//! 7. Modals — help, vendor lookup (`curl` + api.macvendors.com)
//!
//! ### Step 4 — Test manually
//!
//! 1. Enable Internet Sharing (System Settings → General → Sharing)
//! 2. Connect a phone to your Mac's shared Wi‑Fi
//! 3. `cargo run` — client appears as `● now`
//! 4. Press `b`, enter password — client blocked
//! 5. Press `a` — toggle online-only vs full DHCP history
//!
//! ## On-disk files
//!
//! | Path | Purpose |
//! |------|---------|
//! | `/var/db/dhcpd_leases` | DHCP lease database (read-only for users) |
//! | `~/.config/monit/blocks.pf` | PF rules generated by monit |
//! | `bridge100` | Virtual interface (exists only when sharing is on) |
//!
//! ## Keyboard reference
//!
//! | Key | Action |
//! |-----|--------|
//! | `↑/↓` `j/k` | Select row |
//! | `r` | Refresh client list |
//! | `a` | Toggle online-only / show all history |
//! | `b` / `u` | Block / unblock selected client |
//! | `v` | MAC vendor lookup |
//! | `?` | Help modal |
//! | `q` / Esc | Quit (or cancel modal) |
//!
//! ## Module index
//!
//! - [`app`](app/index.html) — application state, event handling, background workers
//! - [`net`](net/index.html) — Internet Sharing detection and client discovery
//! - [`pf`](pf/index.html) — Packet Filter block list persistence
//! - [`sudo`](sudo/index.html) — privileged command execution
//! - [`ui`](ui/index.html) — Ratatui rendering
//!
//! ## Dependencies (why only two crates)
//!
//! | Crate | Role |
//! |-------|------|
//! | **ratatui** | Layout, tables, styled text, widgets |
//! | **crossterm** | Raw mode, alternate screen, keyboard events |
//!
//! Everything else uses **`std::process::Command`** to call macOS binaries already on the system.

#![cfg(target_os = "macos")]

pub mod app;
pub mod net;
pub mod pf;
pub mod sudo;
pub mod ui;

use std::io;
use std::time::Duration;

use crossterm::ExecutableCommand;
use crossterm::event::{self, Event, KeyEventKind};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

/// Run the monit TUI event loop until the user quits.
///
/// Sets up the terminal (raw mode + alternate screen), constructs [`app::App`],
/// then loops: poll background workers → auto-refresh every 10 s → draw → handle keys.
///
/// # Errors
///
/// Returns [`io::Error`] if terminal setup, drawing, or event polling fails.
///
/// # Example
///
/// Called from the binary entry point:
///
/// ```no_run
/// monit::run().expect("monit exited with an error");
/// ```
pub fn run() -> io::Result<()> {
    let mut stdout = io::stdout();
    enable_raw_mode()?;
    stdout.execute(EnterAlternateScreen)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;

    let mut app = app::App::new();
    let tick = Duration::from_millis(250);
    let auto_refresh = Duration::from_secs(3);
    let mut last_refresh = std::time::Instant::now();

    loop {
        app.poll_background();
        if last_refresh.elapsed() >= auto_refresh {
            app.refresh();
            last_refresh = std::time::Instant::now();
        }

        terminal.draw(|f| ui::draw(f, &app))?;

        if app.needs_cursor() {
            terminal.show_cursor()?;
        } else {
            terminal.hide_cursor()?;
        }

        if event::poll(tick)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press && app.handle_key(key) {
                    break;
                }
            }
        }
    }

    disable_raw_mode()?;
    terminal.backend_mut().execute(LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    Ok(())
}
