//! The terminal shell for [`ReviewState`]: draws the two sides and reads
//! keys and the mouse. It holds no review logic and decides nothing; every
//! rule lives in `review_view`. Native-only (feature `tui`).

use super::review_view::{Effect, Key, Mode, ReviewState, ReviewView};
use crate::error::Result;
use ratatui::crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    MouseEventKind,
};
use ratatui::crossterm::execute;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::Frame;
use std::time::Duration;

use crate::file_history::ChangeKind;

/// Where each side was drawn last, so a pointer position can be mapped
/// back to a line.
#[derive(Default)]
pub struct Layouts {
    panes: Vec<Rect>,
    lists: Vec<ListState>,
}

fn draw(frame: &mut Frame, state: &ReviewState, message: &str, layouts: &mut Layouts) {
    let status_height = if state.view.status.is_empty() {
        0
    } else {
        state.view.status.len() as u16 + 2
    };
    let rows = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(status_height),
        Constraint::Length(3),
        Constraint::Length(1),
    ])
    .split(frame.area());
    frame.render_widget(Paragraph::new(state.view.title.as_str()), rows[0]);

    let n = state.view.panes.len().max(1) as u32;
    let columns = Layout::horizontal(vec![Constraint::Ratio(1, n); n as usize]).split(rows[1]);
    layouts.panes = columns.to_vec();
    layouts
        .lists
        .resize_with(state.view.panes.len(), ListState::default);
    for (i, pane) in state.view.panes.iter().enumerate() {
        let active = i == state.pane;
        let items: Vec<ListItem> = if pane.lines.is_empty() {
            vec![ListItem::new(pane.note.clone().unwrap_or_default())]
        } else {
            pane.lines
                .iter()
                .map(|l| {
                    let (mark, color) = match l.kind {
                        ChangeKind::Removed => ('-', Color::Red),
                        ChangeKind::Added => ('+', Color::Green),
                    };
                    ListItem::new(Line::from(vec![
                        Span::styled(format!("{mark} {:>4} ", l.number), Style::new().fg(color)),
                        Span::raw(l.text.clone()),
                    ]))
                })
                .collect()
        };
        let border = if active { Color::Cyan } else { Color::DarkGray };
        let list = List::new(items)
            .block(
                Block::new()
                    .borders(Borders::ALL)
                    .border_style(Style::new().fg(border))
                    .title(pane.heading.as_str()),
            )
            .highlight_style(Style::new().add_modifier(Modifier::REVERSED));
        let selected = (active && !pane.lines.is_empty()).then(|| state.cursor());
        layouts.lists[i].select(selected);
        frame.render_stateful_widget(list, columns[i], &mut layouts.lists[i]);
    }

    if status_height > 0 {
        frame.render_widget(
            Paragraph::new(state.view.status.join("\n"))
                .block(Block::new().borders(Borders::ALL).title("merge status")),
            rows[2],
        );
    }
    let who = state.provenance().unwrap_or("").to_string();
    frame.render_widget(
        Paragraph::new(who).block(Block::new().borders(Borders::ALL).title("written by")),
        rows[3],
    );
    let bottom = match state.mode {
        Mode::Command => format!(":{}", state.command),
        Mode::Normal => message.to_string(),
    };
    frame.render_widget(Paragraph::new(bottom), rows[4]);
}

fn key_of(code: KeyCode, modifiers: KeyModifiers) -> Option<Key> {
    Some(match code {
        KeyCode::Char(c) if modifiers.contains(KeyModifiers::CONTROL) => Key::Ctrl(c),
        KeyCode::Char(c) => Key::Char(c),
        KeyCode::Enter => Key::Enter,
        KeyCode::Esc => Key::Esc,
        KeyCode::Tab => Key::Tab,
        KeyCode::BackTab => Key::BackTab,
        KeyCode::Backspace => Key::Backspace,
        KeyCode::Up => Key::Up,
        KeyCode::Down => Key::Down,
        KeyCode::Left => Key::Left,
        KeyCode::Right => Key::Right,
        KeyCode::PageUp => Key::PageUp,
        KeyCode::PageDown => Key::PageDown,
        _ => return None,
    })
}

/// The line of the current side under terminal cell (`column`, `row`).
fn line_at(layouts: &Layouts, pane: usize, column: u16, row: u16) -> Option<usize> {
    let area = layouts.panes.get(pane)?;
    let inside = column > area.x
        && column < area.x + area.width.saturating_sub(1)
        && row > area.y
        && row < area.y + area.height.saturating_sub(1);
    inside.then(|| (row - area.y - 1) as usize + layouts.lists[pane].offset())
}

/// Run the review until the user quits. The terminal is restored on every
/// exit path.
pub fn run(view: ReviewView) -> Result<()> {
    let mut state = ReviewState::new(view);
    let mut layouts = Layouts::default();
    let mut message = String::from("? for help");
    let mut terminal = ratatui::init();
    let _ = execute!(std::io::stdout(), EnableMouseCapture);
    let result = (|| -> std::io::Result<()> {
        loop {
            terminal.draw(|frame| draw(frame, &state, &message, &mut layouts))?;
            if !event::poll(Duration::from_millis(250))? {
                continue;
            }
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    let Some(key) = key_of(key.code, key.modifiers) else {
                        continue;
                    };
                    match state.handle(key) {
                        Effect::Quit => return Ok(()),
                        Effect::Message(text) => message = text,
                        Effect::None => {}
                    }
                }
                Event::Mouse(mouse) if matches!(mouse.kind, MouseEventKind::Moved) => {
                    let index = line_at(&layouts, state.pane, mouse.column, mouse.row);
                    state.hover(index);
                }
                _ => {}
            }
        }
    })();
    let _ = execute!(std::io::stdout(), DisableMouseCapture);
    ratatui::restore();
    Ok(result?)
}

#[cfg(test)]
#[path = "review_tui/tests.rs"]
mod tests;
