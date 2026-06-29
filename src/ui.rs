//! Ratatui rendering — layout, table, modals.
//!
//! The screen is divided into three vertical panes:
//!
//! ```text
//! ┌ monit — Internet Sharing ─────────────────────┐  ← draw_status (3 lines)
//! │ Status: ACTIVE  bridge100  192.168.2.1/24     │
//! ├ IP ─── MAC ─── Name ── Online ── ↓/↑ ─────────┤  ← draw_table (flex)
//! │ ▶192.168.2.5  …        ● now   1.2K/340       │
//! ├───────────────────────────────────────────────┤
//! │ ↑/↓ select  r refresh  b block  …             │  ← draw_footer (2 lines)
//! └───────────────────────────────────────────────┘
//!
//! Modals (help, vendor, password) are drawn on top via [`Clear`] + centered rect.
//! ```

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap};

use crate::app::{App, Modal, PendingAction};
use crate::net;

/// Render one full frame: status bar, client table, footer, and any active modal.
pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(2),
        ])
        .split(f.area());

    draw_status(f, app, chunks[0]);
    draw_table(f, app, chunks[1]);
    draw_footer(f, app, chunks[2]);

    match &app.modal {
        Modal::None => {}
        Modal::Help => draw_help(f),
        Modal::Vendor { mac, text } => draw_vendor(f, mac, text),
        Modal::Password { input, action } => draw_password(f, input, action),
    }
}

/// Header bar: sharing status, online count, refresh indicator, status message.
fn draw_status(f: &mut Frame, app: &App, area: Rect) {
    let online = app.online_count();
    let total = app.clients.len();
    let status = if app.sharing.active {
        let filter = if app.online_only {
            format!("{online} online")
        } else {
            format!("{online} online / {total} total")
        };
        format!(
            "ACTIVE  {}  {}/{}  {}",
            app.sharing.interface, app.sharing.gateway, app.sharing.prefix, filter
        )
    } else {
        "INACTIVE — enable Internet Sharing in System Settings".into()
    };

    let mut line = Line::from(vec![
        Span::styled("Status: ", Style::default().add_modifier(Modifier::BOLD)),
        Span::styled(
            status,
            if app.sharing.active {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Yellow)
            },
        ),
    ]);
    if app.refreshing {
        line.spans.push(Span::raw("  "));
        line.spans.push(Span::styled(
            "Refreshing…",
            Style::default().fg(Color::Cyan),
        ));
    }
    if !app.status.is_empty() && !app.refreshing {
        line.spans.push(Span::raw("  "));
        line.spans
            .push(Span::styled(&app.status, Style::default().fg(Color::Cyan)));
    }

    let block = Block::default()
        .title(" monit — Internet Sharing ")
        .borders(Borders::ALL);
    f.render_widget(Paragraph::new(line).block(block), area);
}

/// Main client table with selection highlight and online/past coloring.
fn draw_table(f: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec![
        Cell::from("IP"),
        Cell::from("MAC"),
        Cell::from("Name"),
        Cell::from("Online"),
        Cell::from("↓ in"),
        Cell::from("↑ out"),
        Cell::from(""),
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));

    let visible = app.visible_clients();
    let rows: Vec<Row> = visible
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let sel = i == app.selected;
            let style = if sel {
                Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD)
            } else if c.blocked {
                Style::default().fg(Color::Red)
            } else if c.connected {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            Row::new(vec![
                Cell::from(if sel {
                    format!("▶ {}", c.ip)
                } else {
                    format!("  {}", c.ip)
                }),
                Cell::from(c.mac.as_str()),
                Cell::from(if c.name.is_empty() { "—" } else { &c.name }),
                Cell::from(if c.connected { "● now" } else { "  past" }),
                Cell::from(net::format_bytes(c.bytes_in)),
                Cell::from(net::format_bytes(c.bytes_out)),
                Cell::from(if c.blocked { "BLOCKED" } else { "" }),
            ])
            .style(style)
        })
        .collect();

    let title = if app.online_only {
        " Clients (online only) "
    } else {
        " Clients (all — ● now = connected, past = old DHCP lease) "
    };

    let widths = [
        Constraint::Length(18),
        Constraint::Length(19),
        Constraint::Length(16),
        Constraint::Length(6),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Length(10),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));
    f.render_widget(table, area);
}

/// Keybinding hint line; `a` label toggles based on [`App::online_only`].
fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let filter = if app.online_only { "all" } else { "online" };
    let text = format!(
        "↑/↓ j/k select  r refresh  a show {filter}  b block  u unblock  v vendor  ? help  q quit"
    );
    f.render_widget(
        Paragraph::new(text).style(Style::default().fg(Color::DarkGray)),
        area,
    );
}

/// Help modal: Wi‑Fi password change steps and online vs past explanation.
fn draw_help(f: &mut Frame) {
    let area = centered_rect(60, 40, f.area());
    f.render_widget(Clear, area);
    let text = vec![
        Line::from("Change Wi-Fi password / kick all clients:"),
        Line::from(""),
        Line::from("1. Turn off Internet Sharing"),
        Line::from("2. System Settings → General → Sharing"),
        Line::from("   → Internet Sharing → Wi-Fi Options"),
        Line::from("3. Change the password"),
        Line::from("4. Re-enable Internet Sharing"),
        Line::from(""),
        Line::from("Who is connected right now?"),
        Line::from("● now  = ARP entry on bridge100 (actually on your hotspot)"),
        Line::from("  past = only in dhcpd_leases (connected before, not now)"),
        Line::from("Press a to toggle online-only / show all history"),
        Line::from(""),
        modal_footer(),
    ];
    f.render_widget(
        Paragraph::new(text)
            .block(Block::default().title(" Help ").borders(Borders::ALL))
            .wrap(Wrap { trim: true }),
        area,
    );
}

/// Vendor lookup result modal.
fn draw_vendor(f: &mut Frame, mac: &str, text: &str) {
    let area = centered_rect(50, 20, f.area());
    f.render_widget(Clear, area);
    let lines = vec![
        Line::from(format!("MAC: {mac}")),
        Line::from(""),
        Line::from(text.to_string()),
        Line::from(""),
        modal_footer(),
    ];
    f.render_widget(
        Paragraph::new(lines).block(Block::default().title(" Vendor ").borders(Borders::ALL)),
        area,
    );
}

/// TUI administrator password prompt (masked with `•`).
fn draw_password(f: &mut Frame, input: &str, action: &PendingAction) {
    let area = centered_rect(52, 24, f.area());
    f.render_widget(Clear, area);

    let reason = match action {
        PendingAction::Block(ip) => format!("Block {ip}"),
        PendingAction::Unblock(ip) => format!("Unblock {ip}"),
    };
    let masked: String = input.chars().map(|_| '•').collect();

    let text = vec![
        Line::from("Administrator password required:"),
        Line::from(""),
        Line::from(reason),
        Line::from(""),
        Line::from(format!("Password: {masked}")),
        Line::from(""),
        modal_footer_confirm(),
    ];
    f.render_widget(
        Paragraph::new(text).block(Block::default().title(" Password ").borders(Borders::ALL)),
        area,
    );
}

/// Cancel hint for read-only modals (help, vendor).
fn modal_footer() -> Line<'static> {
    Line::from(Span::styled(
        "  c/Esc cancel",
        Style::default().fg(Color::DarkGray),
    ))
}

/// Confirm/cancel hint for the password modal.
fn modal_footer_confirm() -> Line<'static> {
    Line::from(vec![
        Span::styled("Enter ", Style::default().fg(Color::Green)),
        Span::styled("confirm", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw("    "),
        Span::styled("c/Esc ", Style::default().fg(Color::Yellow)),
        Span::styled("cancel", Style::default().add_modifier(Modifier::BOLD)),
    ])
}

/// Compute a centered rectangle as a percentage of the terminal size.
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup[1])[1]
}
