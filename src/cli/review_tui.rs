//! The terminal shell for [`ReviewState`]: draws the two sides and reads
//! keys and the mouse. It holds no review logic and decides nothing; every
//! rule lives in `review_view`. Native-only (feature `tui`).

use super::review_view::{Action, Effect, Key, Mode, ReviewState, ReviewView};
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

/// Background of a removed and an added line's text, so a change reads at a
/// glance without relying on the `-`/`+` mark alone.
const REMOVED_BACKGROUND: Color = Color::Rgb(0x4b, 0x1d, 0x22);
const ADDED_BACKGROUND: Color = Color::Rgb(0x14, 0x3d, 0x22);

/// Runs one [`Action`] as the given label and slot, returning the review of
/// the history afterwards (`None` when nothing is left to review).
pub type ActionRunner<'a> = dyn FnMut(&Action, &str, &str) -> Result<Option<ReviewView>> + 'a;

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
            state
                .visible(i)
                .into_iter()
                .map(|index| {
                    let l = &pane.lines[index];
                    let (mark, color, tint) = match (l.context, l.kind) {
                        (true, _) => (' ', Color::DarkGray, Color::Reset),
                        (false, ChangeKind::Removed) => ('-', Color::Red, REMOVED_BACKGROUND),
                        (false, ChangeKind::Added) => ('+', Color::Green, ADDED_BACKGROUND),
                    };
                    let picked = if state.is_picked(i, index) { '*' } else { ' ' };
                    let mut spans = vec![
                        Span::styled(
                            format!("{picked}{mark} {:>4} ", l.number),
                            Style::new().fg(color),
                        ),
                        Span::styled(l.text.clone(), Style::new().bg(tint)),
                    ];
                    if let Some(hidden) = state.fold_hidden(i, index) {
                        spans.push(Span::styled(
                            format!(" ▸{hidden} folded"),
                            Style::new().fg(Color::DarkGray),
                        ));
                    }
                    ListItem::new(Line::from(spans))
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
        let selected = (active && !pane.lines.is_empty())
            .then(|| {
                state
                    .visible(i)
                    .iter()
                    .position(|shown| *shown == state.cursor())
            })
            .flatten();
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
        Mode::Search => format!("/{}", state.command),
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

/// The line index behind the list row `row` of `pane`, past any folds.
fn shown_line(state: &ReviewState, pane: usize, row: usize) -> Option<usize> {
    state.visible(pane).get(row).copied()
}

/// Hand `text` to the person's editor (`$VISUAL`, `$EDITOR`, else `vi`) in a
/// private file, with the terminal given back for the duration, and read
/// the result. The file holds file content, so it is created owner-only and
/// removed afterwards.
fn edit_externally(
    terminal: &mut ratatui::DefaultTerminal,
    text: &str,
) -> std::result::Result<String, String> {
    use rand::RngCore;
    let mut random = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let path = std::env::temp_dir().join(format!("keyquorum-review-{}.txt", hex::encode(random)));
    crate::locked_files::write_owner_only(&path, text.as_bytes())
        .map_err(|error| format!("could not prepare the edit: {error}"))?;
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".to_string());
    let _ = execute!(std::io::stdout(), DisableMouseCapture);
    ratatui::restore();
    let status = std::process::Command::new(&editor).arg(&path).status();
    *terminal = ratatui::init();
    let _ = execute!(std::io::stdout(), EnableMouseCapture);
    let outcome = match status {
        Ok(status) if status.success() => std::fs::read(&path)
            .map_err(|error| format!("could not read the edit: {error}"))
            .and_then(|bytes| {
                String::from_utf8(bytes).map_err(|_| "the edit is not UTF-8 text".to_string())
            }),
        Ok(_) => Err(format!("{editor} did not finish cleanly: edit discarded")),
        Err(error) => Err(format!("could not run {editor}: {error}")),
    };
    let _ = std::fs::remove_file(&path);
    outcome
}

/// Run the review until the user quits. The terminal is restored on every
/// exit path.
///
/// `who` is the label and slot to start from (either can be set later with
/// `:as` and `:slot`). `act` runs one [`Action`] as that person with the
/// terminal handed back, so a passphrase prompt works, and returns the
/// review of the history as it now stands.
pub fn run(
    view: ReviewView,
    who: (Option<String>, Option<String>),
    act: &mut ActionRunner,
) -> Result<()> {
    let mut state = ReviewState::new(view).with_identity(who.0, who.1);
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
                        Effect::Run(action) => {
                            let Some((as_label, slot)) = state.identity() else {
                                continue;
                            };
                            let (as_label, slot) = (as_label.to_string(), slot.to_string());
                            let _ = execute!(std::io::stdout(), DisableMouseCapture);
                            ratatui::restore();
                            let outcome = act(&action, &as_label, &slot);
                            println!("\nPress Enter to return to the review.");
                            let _ = std::io::stdin().read_line(&mut String::new());
                            terminal = ratatui::init();
                            let _ = execute!(std::io::stdout(), EnableMouseCapture);
                            message = match outcome {
                                Ok(Some(view)) => {
                                    state.reload(view);
                                    "done: the review shows the history as it now stands".into()
                                }
                                Ok(None) => "done: nothing is left to review".into(),
                                Err(error) => format!("refused: {error}"),
                            };
                        }
                        Effect::Edit(text) => {
                            message = match edit_externally(&mut terminal, &text) {
                                Ok(edited) => {
                                    state.set_edited(edited);
                                    "edited: :compose to check the result".to_string()
                                }
                                Err(reason) => reason,
                            }
                        }
                        Effect::None => {}
                    }
                }
                Event::Mouse(mouse) if matches!(mouse.kind, MouseEventKind::Moved) => {
                    let index = line_at(&layouts, state.pane, mouse.column, mouse.row)
                        .and_then(|row| shown_line(&state, state.pane, row));
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
