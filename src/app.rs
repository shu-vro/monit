//! Application state, keyboard handling, and background workers.
//!
//! [`App`] is the central state machine. It owns the client list, UI modals,
//! and two background channels:
//!
//! ```text
//!   refresh thread ──► RefreshMsg ──► updated Sharing + Vec<Client>
//!   vendor thread  ──► VendorMsg  ──► MAC vendor lookup result
//! ```
//!
//! The main thread never blocks on slow shell commands (`ping`, `nettop`, `curl`).

use std::collections::HashMap;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::net::{self, Client, Sharing};

/// Result of a background client-discovery pass.
pub enum RefreshMsg {
    /// Discovery finished successfully.
    Done {
        /// Current Internet Sharing status and subnet.
        sharing: Sharing,
        /// All known clients (online + historical), sorted with online first.
        clients: Vec<Client>,
    },
}

/// Result of a background MAC vendor lookup.
pub enum VendorMsg {
    /// Lookup finished (success or failure).
    Done {
        /// MAC address that was queried.
        mac: String,
        /// Vendor name, or error string.
        result: Result<String, String>,
    },
}

/// Privileged action waiting for the TUI password modal.
#[derive(Clone, PartialEq)]
pub enum PendingAction {
    /// Add PF block rules for this IP.
    Block(String),
    /// Remove PF block rules for this IP.
    Unblock(String),
}

/// Overlay dialog shown on top of the main table.
#[derive(PartialEq)]
pub enum Modal {
    /// No modal — main view receives keys.
    None,
    /// Wi‑Fi password / kick-all instructions.
    Help,
    /// MAC vendor lookup result.
    Vendor {
        /// Queried MAC address.
        mac: String,
        /// Vendor name or error message.
        text: String,
    },
    /// Administrator password prompt for `sudo` / `pfctl`.
    Password {
        /// Characters typed so far (masked in UI).
        input: String,
        /// Block or unblock to perform after Enter.
        action: PendingAction,
    },
}

/// Full application state for one arpmac session.
pub struct App {
    /// Internet Sharing detection result (updated each refresh).
    pub sharing: Sharing,
    /// Complete client list including historical DHCP entries.
    pub clients: Vec<Client>,
    /// Index into [`Self::visible_clients`], not raw `clients`.
    pub selected: usize,
    /// Short status line shown in the header (errors, confirmations).
    pub status: String,
    /// Active modal overlay, if any.
    pub modal: Modal,
    /// `true` while a refresh thread is in flight.
    pub refreshing: bool,
    /// When `true`, hide past DHCP guests that aren't connected now.
    pub online_only: bool,
    /// Reused for subsequent `pfctl` calls after first successful auth.
    cached_password: Option<String>,
    refresh_rx: Receiver<RefreshMsg>,
    refresh_tx: Sender<RefreshMsg>,
    vendor_rx: Receiver<VendorMsg>,
    vendor_tx: Sender<VendorMsg>,
    vendor_cache: HashMap<String, String>,
}

impl App {
    /// Create a new app and trigger the first client refresh.
    pub fn new() -> Self {
        let (refresh_tx, refresh_rx) = mpsc::channel();
        let (vendor_tx, vendor_rx) = mpsc::channel();
        let mut app = Self {
            sharing: Sharing::default(),
            clients: vec![],
            selected: 0,
            status: String::new(),
            modal: Modal::None,
            refreshing: false,
            online_only: true,
            cached_password: None,
            refresh_rx,
            refresh_tx,
            vendor_rx,
            vendor_tx,
            vendor_cache: HashMap::new(),
        };
        app.refresh();
        app
    }

    /// Whether the terminal cursor should be visible (password modal open).
    pub fn needs_cursor(&self) -> bool {
        matches!(self.modal, Modal::Password { .. })
    }

    /// Drain completed background work without blocking.
    ///
    /// Call once per event-loop iteration to apply refresh and vendor results.
    pub fn poll_background(&mut self) {
        while let Ok(msg) = self.refresh_rx.try_recv() {
            match msg {
                RefreshMsg::Done { sharing, clients } => {
                    self.sharing = sharing;
                    self.clients = clients;
                    self.refreshing = false;
                    if self.selected >= self.visible_clients().len() {
                        self.selected = self.visible_clients().len().saturating_sub(1);
                    }
                    if self.status.is_empty() || self.status.starts_with("Refreshing") {
                        self.status.clear();
                    }
                }
            }
        }
        while let Ok(msg) = self.vendor_rx.try_recv() {
            match msg {
                VendorMsg::Done { mac, result } => {
                    let text = match result {
                        Ok(v) => {
                            self.vendor_cache.insert(mac.clone(), v.clone());
                            v
                        }
                        Err(e) => e,
                    };
                    self.modal = Modal::Vendor { mac, text };
                }
            }
        }
    }

    /// Spawn a background thread to re-run client discovery.
    ///
    /// No-op if a refresh is already in progress.
    pub fn refresh(&mut self) {
        if self.refreshing {
            return;
        }
        self.refreshing = true;
        self.status = "Refreshing…".into();
        let tx = self.refresh_tx.clone();
        thread::spawn(move || {
            let blocked = crate::pf::load_blocked().unwrap_or_default();
            let sharing = net::detect_sharing();
            let clients = net::discover_clients(&sharing, &blocked);
            let _ = tx.send(RefreshMsg::Done { sharing, clients });
        });
    }

    /// Clients visible in the table after applying [`Self::online_only`] filter.
    pub fn visible_clients(&self) -> Vec<&Client> {
        self.clients
            .iter()
            .filter(|c| !self.online_only || c.connected)
            .collect()
    }

    /// Count of clients marked [`Client::connected`].
    pub fn online_count(&self) -> usize {
        self.clients.iter().filter(|c| c.connected).count()
    }

    /// Handle a keyboard event.
    ///
    /// Returns `true` if the app should exit (user pressed `q` or Esc on main view).
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        if matches!(self.modal, Modal::Password { .. }) {
            let action = match &self.modal {
                Modal::Password { action, .. } => action.clone(),
                _ => unreachable!(),
            };
            match key.code {
                KeyCode::Esc | KeyCode::Char('c') => {
                    self.modal = Modal::None;
                    self.status = "Cancelled".into();
                }
                KeyCode::Enter => {
                    let Modal::Password { input, .. } = &self.modal else {
                        return false;
                    };
                    let password = input.clone();
                    if password.is_empty() {
                        self.status = "Password required".into();
                        return false;
                    }
                    let result = match &action {
                        PendingAction::Block(ip) => crate::pf::block(ip, &password),
                        PendingAction::Unblock(ip) => crate::pf::unblock(ip, &password),
                    };
                    match result {
                        Ok(()) => {
                            self.cached_password = Some(password);
                            self.modal = Modal::None;
                            self.status = match &action {
                                PendingAction::Block(ip) => format!("Blocked {ip}"),
                                PendingAction::Unblock(ip) => format!("Unblocked {ip}"),
                            };
                            self.refresh();
                        }
                        Err(e) => {
                            self.cached_password = None;
                            self.status = format!("Auth failed: {e}");
                            if let Modal::Password { input, .. } = &mut self.modal {
                                input.clear();
                            }
                        }
                    }
                }
                KeyCode::Backspace => {
                    if let Modal::Password { input, .. } = &mut self.modal {
                        input.pop();
                    }
                }
                KeyCode::Char(c) => {
                    if let Modal::Password { input, .. } = &mut self.modal {
                        input.push(c);
                    }
                }
                _ => {}
            }
            return false;
        }

        if self.modal != Modal::None {
            if Self::modal_cancel(key.code) {
                self.modal = Modal::None;
            }
            return false;
        }

        match key.code {
            KeyCode::Char('q') => return true,
            KeyCode::Esc => return true,
            KeyCode::Char('r') => self.refresh(),
            KeyCode::Char('a') => {
                self.online_only = !self.online_only;
                self.selected = 0;
                self.status = if self.online_only {
                    "Showing online only".into()
                } else {
                    "Showing all (incl. past guests)".into()
                };
            }
            KeyCode::Char('?') => self.modal = Modal::Help,
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = self.selected.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let n = self.visible_clients().len();
                if n > 0 {
                    self.selected = (self.selected + 1).min(n - 1);
                }
            }
            KeyCode::Char('b') => self.request_block(),
            KeyCode::Char('u') => self.request_unblock(),
            KeyCode::Char('v') => self.vendor_lookup(),
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return true,
            _ => {}
        }
        false
    }

    /// Returns `true` for keys that dismiss a non-password modal.
    fn modal_cancel(code: KeyCode) -> bool {
        matches!(code, KeyCode::Esc | KeyCode::Char('c') | KeyCode::Char('q'))
    }

    /// Currently highlighted client in the filtered table.
    fn selected_client(&self) -> Option<&Client> {
        self.visible_clients().get(self.selected).copied()
    }

    /// Start block flow — uses cached password or opens [`Modal::Password`].
    fn request_block(&mut self) {
        let Some(ip) = self.selected_client().map(|c| c.ip.clone()) else {
            self.status = "No client selected".into();
            return;
        };
        if let Some(ref pw) = self.cached_password {
            match crate::pf::block(&ip, pw) {
                Ok(()) => {
                    self.status = format!("Blocked {ip}");
                    self.refresh();
                    return;
                }
                Err(_) => self.cached_password = None,
            }
        }
        self.modal = Modal::Password {
            input: String::new(),
            action: PendingAction::Block(ip),
        };
        self.status.clear();
    }

    /// Start unblock flow — uses cached password or opens [`Modal::Password`].
    fn request_unblock(&mut self) {
        let Some(ip) = self.selected_client().map(|c| c.ip.clone()) else {
            self.status = "No client selected".into();
            return;
        };
        if let Some(ref pw) = self.cached_password {
            match crate::pf::unblock(&ip, pw) {
                Ok(()) => {
                    self.status = format!("Unblocked {ip}");
                    self.refresh();
                    return;
                }
                Err(_) => self.cached_password = None,
            }
        }
        self.modal = Modal::Password {
            input: String::new(),
            action: PendingAction::Unblock(ip),
        };
        self.status.clear();
    }

    /// Look up MAC vendor via [`net::lookup_vendor`], cached per session.
    fn vendor_lookup(&mut self) {
        let Some(client) = self.selected_client() else {
            self.status = "No client selected".into();
            return;
        };
        if client.mac.is_empty() {
            self.status = "No MAC address".into();
            return;
        }
        if let Some(v) = self.vendor_cache.get(&client.mac) {
            self.modal = Modal::Vendor {
                mac: client.mac.clone(),
                text: v.clone(),
            };
            return;
        }
        let mac = client.mac.clone();
        let tx = self.vendor_tx.clone();
        thread::spawn(move || {
            let result = net::lookup_vendor(&mac);
            let _ = tx.send(VendorMsg::Done { mac, result });
        });
        self.status = "Looking up vendor…".into();
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}
