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
