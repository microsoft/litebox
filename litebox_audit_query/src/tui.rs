// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Interactive terminal UI for the frontier tree (`watch --tree` on a TTY).
//!
//! Renders the [`Frontier`] as a collapsible tree the user navigates with the
//! arrow keys, while continuing to fold new audit events in live. Collapsed by
//! default: each node shows a `(N✓ M✗)` allow/deny path count — with a `×N`
//! attempt tally when a resource was hit more than once — so the shape and the
//! hot spots are visible without expanding.
//!
//! Keys: `↑`/`↓` (or `k`/`j`) move · `→`/`Enter`/`Space` expand · `←` collapse ·
//! `PgUp`/`PgDn` page · `Home`/`End` jump · `q`/`Esc`/`Ctrl-C` quit.

use std::io::{self, Read, Write};
use std::time::Duration;

use crossterm::cursor::{Hide, MoveTo, Show};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    Clear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode,
    enable_raw_mode, size,
};
use crossterm::{execute, queue};

use crate::tree::{BOLD, DIM, Frontier, RESET, Row, format_counts, status_color};

/// How long to block waiting for a keypress before folding in new log data.
const POLL: Duration = Duration::from_millis(120);

/// Run the interactive tree UI, tailing `file` into `frontier` until the user
/// quits. Restores the terminal on any exit path.
pub fn run(frontier: Frontier, file: std::fs::File) -> io::Result<()> {
    enable_raw_mode()?;
    let mut out = io::stdout();
    execute!(out, EnterAlternateScreen, Hide)?;
    let result = event_loop(frontier, file, &mut out);
    let _ = execute!(out, Show, LeaveAlternateScreen);
    let _ = disable_raw_mode();
    result
}

fn event_loop(
    mut frontier: Frontier,
    mut file: std::fs::File,
    out: &mut io::Stdout,
) -> io::Result<()> {
    let mut selected: usize = 0;
    let mut scroll: usize = 0;
    let mut carry: Vec<u8> = Vec::new();
    let mut buf = vec![0u8; 65536];
    let mut dirty = true;

    loop {
        // Drain newly-appended log lines into the model each tick. Cap the work
        // per tick (~4 MiB) so a huge backlog — e.g. a runaway extension host
        // flooding the log — is caught up over several ticks while the UI stays
        // responsive, instead of the old one-64-KiB-chunk-per-tick pace that
        // fell behind unboundedly whenever the log outgrew ~530 KiB/s.
        let mut drained = 0usize;
        loop {
            let n = file.read(&mut buf).unwrap_or(0);
            if n == 0 {
                break;
            }
            carry.extend_from_slice(&buf[..n]);
            while let Some(pos) = carry.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = carry.drain(..=pos).collect();
                let text = String::from_utf8_lossy(&line);
                let trimmed = text.trim();
                if trimmed.starts_with('{')
                    && let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed)
                {
                    dirty |= frontier.ingest(&v);
                }
            }
            drained += n;
            if drained >= 4 * 1024 * 1024 {
                break;
            }
        }

        let rows = frontier.visible_rows();
        if selected >= rows.len() {
            selected = rows.len().saturating_sub(1);
        }
        if dirty {
            render(out, &rows, selected, &mut scroll)?;
            dirty = false;
        }

        if event::poll(POLL)? {
            match event::read()? {
                Event::Key(key) if key.kind != KeyEventKind::Release => {
                    let page = page_size();
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => break,
                        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                            break;
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            selected = selected.saturating_sub(1);
                            dirty = true;
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if selected + 1 < rows.len() {
                                selected += 1;
                            }
                            dirty = true;
                        }
                        KeyCode::Right
                        | KeyCode::Enter
                        | KeyCode::Char(' ')
                        | KeyCode::Char('l') => {
                            if let Some(row) = rows.get(selected) {
                                if row.expandable && !row.expanded {
                                    frontier.set_expanded(&row.path, true);
                                } else if row.expandable
                                    && row.expanded
                                    && selected + 1 < rows.len()
                                {
                                    selected += 1; // step into the first child
                                }
                                dirty = true;
                            }
                        }
                        KeyCode::Left | KeyCode::Char('h') => {
                            if let Some(row) = rows.get(selected) {
                                if row.expandable && row.expanded {
                                    frontier.set_expanded(&row.path, false);
                                } else if let Some(p) = parent_index(&rows, selected) {
                                    selected = p;
                                }
                                dirty = true;
                            }
                        }
                        KeyCode::PageDown => {
                            selected = (selected + page).min(rows.len().saturating_sub(1));
                            dirty = true;
                        }
                        KeyCode::PageUp => {
                            selected = selected.saturating_sub(page);
                            dirty = true;
                        }
                        KeyCode::Home => {
                            selected = 0;
                            dirty = true;
                        }
                        KeyCode::End => {
                            selected = rows.len().saturating_sub(1);
                            dirty = true;
                        }
                        _ => {}
                    }
                }
                // Resize or other events: redraw.
                Event::Resize(_, _) => dirty = true,
                _ => {}
            }
        }
    }
    Ok(())
}

/// Nearest preceding row whose depth is shallower than `idx`'s (its parent).
fn parent_index(rows: &[Row], idx: usize) -> Option<usize> {
    let depth = rows.get(idx)?.depth;
    if depth == 0 {
        return None;
    }
    rows[..idx].iter().rposition(|r| r.depth < depth)
}

fn page_size() -> usize {
    size()
        .map(|(_, h)| (h as usize).saturating_sub(3).max(1))
        .unwrap_or(20)
}

fn render(
    out: &mut io::Stdout,
    rows: &[Row],
    selected: usize,
    scroll: &mut usize,
) -> io::Result<()> {
    let (cols, height) = size().unwrap_or((80, 24));
    let cols = cols as usize;
    let body = (height as usize).saturating_sub(2).max(1);

    // Keep the selection within the visible window.
    if selected < *scroll {
        *scroll = selected;
    } else if selected >= *scroll + body {
        *scroll = selected + 1 - body;
    }

    queue!(out, MoveTo(0, 0), Clear(ClearType::All))?;
    write!(
        out,
        "{BOLD}LiteBox sandbox frontier{RESET}  \
         {DIM}↑↓ move · →/⏎ expand · ← collapse · q quit{RESET}"
    )?;

    let end = (*scroll + body).min(rows.len());
    for (screen, i) in (*scroll..end).enumerate() {
        let y = u16::try_from(screen + 1).unwrap_or(u16::MAX);
        queue!(out, MoveTo(0, y))?;
        write!(out, "{}", format_row(&rows[i], i == selected, cols))?;
    }

    let footer_y = u16::try_from(body + 1).unwrap_or(u16::MAX);
    queue!(out, MoveTo(0, footer_y))?;
    write!(
        out,
        "{DIM}{}/{}{RESET}",
        (selected + 1).min(rows.len()),
        rows.len()
    )?;
    out.flush()
}

fn format_row(row: &Row, selected: bool, cols: usize) -> String {
    let indent = "  ".repeat(row.depth);
    let glyph = if row.expandable {
        if row.expanded { "▾ " } else { "▸ " }
    } else {
        "  "
    };
    let counts = {
        let c = format_counts(
            row.allow_count,
            row.deny_count,
            row.allow_hits,
            row.deny_hits,
        );
        if c.is_empty() {
            String::new()
        } else {
            format!("  {c}")
        }
    };
    let action = if row.action.is_empty() {
        String::new()
    } else {
        format!("  {}", row.action)
    };

    if selected {
        // Reverse-video the whole row as plain text (inner colour resets would
        // otherwise cancel the highlight mid-line). Pad to full width.
        let mut plain = format!("{indent}{glyph}{}{counts}{action}", row.label);
        let vis = plain.chars().count();
        if vis < cols {
            plain.push_str(&" ".repeat(cols - vis));
        }
        return format!("\x1b[7m{plain}\x1b[0m");
    }

    let color = status_color(row.allowed, row.denied);
    let label = if row.is_section {
        format!("{BOLD}{color}{}{RESET}", row.label)
    } else if row.is_self {
        // The `(self)` meta-row is a node's own-path decision, not a real
        // child — render it dim so it's visually distinct from path children.
        format!("{DIM}{}{RESET}", row.label)
    } else {
        format!("{color}{}{RESET}", row.label)
    };
    let counts = if counts.is_empty() {
        String::new()
    } else {
        format!("{DIM}{counts}{RESET}")
    };
    let action = if action.is_empty() {
        String::new()
    } else {
        format!("{DIM}{action}{RESET}")
    };
    format!("{indent}{DIM}{glyph}{RESET}{label}{counts}{action}")
}
