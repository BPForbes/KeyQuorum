use super::*;
use crate::cli::review_view::{Pane, ViewLine};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

fn state() -> ReviewState {
    let line = |kind, number, text: &str, who: &str| ViewLine {
        kind,
        number,
        text: text.to_string(),
        hunk: 0,
        context: false,
        provenance: who.to_string(),
    };
    ReviewState::new(ReviewView {
        title: "plan.txt — merge review".to_string(),
        status: vec![
            "STATUS".to_string(),
            "  review M.S (PriorNeutralOwner)".to_string(),
        ],
        panes: vec![
            Pane {
                heading: "LEFT".into(),
                revision: "M.A rev a".into(),
                lines: vec![
                    line(ChangeKind::Removed, 2, "old total", "M.A rev a"),
                    line(ChangeKind::Added, 2, "new total", "M.A rev a"),
                ],
                note: None,
                ..Default::default()
            },
            Pane {
                heading: "RIGHT".into(),
                revision: "M.B rev b".into(),
                lines: Vec::new(),
                note: Some("not UTF-8 text: no line view".into()),
                ..Default::default()
            },
        ],
        ..Default::default()
    })
}

fn render(state: &ReviewState, message: &str) -> (String, Layouts) {
    let mut terminal = Terminal::new(TestBackend::new(70, 18)).unwrap();
    let mut layouts = Layouts::default();
    terminal
        .draw(|frame| draw(frame, state, message, &mut layouts))
        .unwrap();
    let buffer = terminal.backend().buffer().clone();
    let text = (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol().to_string())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n");
    (text, layouts)
}

#[test]
fn both_sides_the_note_and_who_wrote_the_line_are_drawn() {
    let (text, _) = render(&state(), "? for help");
    assert!(text.contains("plan.txt — merge review"), "{text}");
    assert!(text.contains("- ") && text.contains("old total"), "{text}");
    assert!(text.contains("+ ") && text.contains("new total"), "{text}");
    assert!(text.contains("not UTF-8 text"), "{text}");
    assert!(
        text.contains("written by") && text.contains("M.A rev a"),
        "{text}"
    );
    assert!(text.contains("? for help"));
    assert!(
        text.contains("merge status") && text.contains("PriorNeutralOwner"),
        "{text}"
    );
}

#[test]
fn command_mode_shows_what_is_being_typed() {
    let mut s = state();
    s.handle(Key::Char(':'));
    s.handle(Key::Char('s'));
    let (text, _) = render(&s, "ignored while typing");
    assert!(text.contains(":s"), "{text}");
    assert!(!text.contains("ignored while typing"));
}

#[test]
fn search_mode_shows_what_is_being_typed() {
    let mut s = state();
    s.handle(Key::Char('/'));
    s.handle(Key::Char('n'));
    let (text, _) = render(&s, "ignored while typing");
    assert!(text.contains("/n"), "{text}");
    assert!(!text.contains("ignored while typing"));
}

#[test]
fn a_pointer_position_maps_back_to_a_line() {
    let s = state();
    let (_, layouts) = render(&s, "");
    let area = layouts.panes[0];
    // Row 0 of the block is the border; the first line is one row below.
    assert_eq!(line_at(&layouts, 0, area.x + 3, area.y + 1), Some(0));
    assert_eq!(line_at(&layouts, 0, area.x + 3, area.y + 2), Some(1));
    // The border itself and points outside the pane are not lines.
    assert_eq!(line_at(&layouts, 0, area.x, area.y + 1), None);
    assert_eq!(line_at(&layouts, 0, area.x + 3, area.y), None);
    assert_eq!(line_at(&layouts, 0, 200, 200), None);
}

#[test]
fn keys_map_and_unknown_ones_are_ignored() {
    assert_eq!(
        key_of(KeyCode::Char('j'), KeyModifiers::NONE),
        Some(Key::Char('j'))
    );
    assert_eq!(
        key_of(KeyCode::Char('d'), KeyModifiers::CONTROL),
        Some(Key::Ctrl('d'))
    );
    assert_eq!(
        key_of(KeyCode::BackTab, KeyModifiers::SHIFT),
        Some(Key::BackTab)
    );
    assert_eq!(key_of(KeyCode::F(5), KeyModifiers::NONE), None);
}

#[test]
fn a_folded_change_is_drawn_as_its_first_line_and_a_count() {
    let mut state = state();
    // Both lines of the first side are one change (hunk 0).
    for key in ['z', 'c'] {
        state.handle(Key::Char(key));
    }
    let (text, _) = render(&state, "");
    assert!(text.contains("old total"), "{text}");
    assert!(text.contains("▸1 folded"), "{text}");
    assert!(!text.contains("new total"), "{text}");
}

#[test]
fn removed_and_added_text_are_drawn_on_red_and_green_backgrounds() {
    let mut terminal = Terminal::new(TestBackend::new(70, 18)).unwrap();
    let mut layouts = Layouts::default();
    let state = state();
    terminal
        .draw(|frame| draw(frame, &state, "", &mut layouts))
        .unwrap();
    let buffer = terminal.backend().buffer().clone();
    let background_of = |needle: &str| {
        (0..buffer.area.height)
            .find_map(|y| {
                let row: String = (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol().to_string())
                    .collect();
                let x = row.find(needle)?;
                let column = row[..x].chars().count() as u16;
                Some(buffer[(column, y)].bg)
            })
            .unwrap_or_else(|| panic!("{needle} not drawn"))
    };
    assert_eq!(background_of("old total"), REMOVED_BACKGROUND);
    assert_eq!(background_of("new total"), ADDED_BACKGROUND);
}

#[test]
fn context_lines_are_drawn_dimmed_and_unmarked() {
    let mut state = state();
    // Add an unchanged line before the first change on the left.
    state.reload(ReviewView {
        title: "t".into(),
        panes: vec![Pane {
            heading: "LEFT".into(),
            lines: vec![
                ViewLine {
                    kind: ChangeKind::Added,
                    number: 1,
                    text: "kept line".into(),
                    hunk: 0,
                    context: true,
                    provenance: "unchanged".into(),
                },
                ViewLine {
                    kind: ChangeKind::Added,
                    number: 2,
                    text: "new total".into(),
                    hunk: 0,
                    context: false,
                    provenance: "M.A rev a".into(),
                },
            ],
            ..Default::default()
        }],
        ..Default::default()
    });
    let (text, _) = render(&state, "");
    assert!(text.contains("   1 kept line"), "{text}");
    assert!(
        text.contains("+    2 new total") || text.contains("+ "),
        "{text}"
    );
    assert!(!text.contains("+    1 kept line"), "{text}");

    // The unchanged line is dimmed and carries no change background; the
    // change keeps its green background.
    let mut terminal = Terminal::new(TestBackend::new(70, 18)).unwrap();
    let mut layouts = Layouts::default();
    terminal
        .draw(|frame| draw(frame, &state, "", &mut layouts))
        .unwrap();
    let buffer = terminal.backend().buffer().clone();
    let cell_of = |needle: &str| {
        (0..buffer.area.height)
            .find_map(|y| {
                let row: String = (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol().to_string())
                    .collect();
                let x = row.find(needle)?;
                Some(buffer[(row[..x].chars().count() as u16, y)].clone())
            })
            .unwrap_or_else(|| panic!("{needle} not drawn"))
    };
    let marker = cell_of("   1 ");
    assert_eq!(marker.fg, Color::DarkGray);
    assert_eq!(cell_of("kept line").bg, Color::Reset);
    assert_eq!(cell_of("new total").bg, ADDED_BACKGROUND);
}
