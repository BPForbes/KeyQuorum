use super::*;

fn line(kind: ChangeKind, number: usize, text: &str, who: &str) -> ViewLine {
    ViewLine {
        kind,
        number,
        text: text.to_string(),
        hunk: 0,
        provenance: who.to_string(),
    }
}

fn view() -> ReviewView {
    let pane = |heading: &str, who: &str, count: usize| Pane {
        heading: heading.to_string(),
        revision: who.to_string(),
        lines: (0..count)
            .map(|i| line(ChangeKind::Added, i + 1, &format!("l{i}"), who))
            .collect(),
        note: None,
        ..Default::default()
    };
    ReviewView {
        title: "plan.txt — merge review".to_string(),
        status: Vec::new(),
        panes: vec![pane("LEFT", "M.A rev a", 25), pane("RIGHT", "M.B rev b", 2)],
        ..Default::default()
    }
}

fn keys(state: &mut ReviewState, input: &str) -> Vec<Effect> {
    input.chars().map(|c| state.handle(Key::Char(c))).collect()
}

#[test]
fn vim_keys_move_and_clamp_the_cursor() {
    let mut s = ReviewState::new(view());
    keys(&mut s, "jjj");
    assert_eq!(s.cursor(), 3);
    keys(&mut s, "k");
    assert_eq!(s.cursor(), 2);
    keys(&mut s, "kkkkk");
    assert_eq!(s.cursor(), 0, "clamped at the top");
    keys(&mut s, "G");
    assert_eq!(s.cursor(), 24);
    keys(&mut s, "j");
    assert_eq!(s.cursor(), 24, "clamped at the bottom");
    keys(&mut s, "gg");
    assert_eq!(s.cursor(), 0);
    s.handle(Key::Ctrl('d'));
    assert_eq!(s.cursor(), 10);
    s.handle(Key::PageUp);
    assert_eq!(s.cursor(), 0);
}

#[test]
fn a_single_g_waits_and_any_other_key_cancels_it() {
    let mut s = ReviewState::new(view());
    keys(&mut s, "jjj");
    keys(&mut s, "g");
    assert_eq!(s.cursor(), 3, "one g moves nothing");
    keys(&mut s, "jg");
    keys(&mut s, "j");
    assert_eq!(s.cursor(), 5, "g then j is not gg");
}

#[test]
fn sides_keep_their_own_cursor_and_wrap() {
    let mut s = ReviewState::new(view());
    keys(&mut s, "jjjj");
    s.handle(Key::Tab);
    assert_eq!((s.pane, s.cursor()), (1, 0));
    keys(&mut s, "jjjj");
    assert_eq!(s.cursor(), 1, "the short side clamps to its last line");
    s.handle(Key::Char('l'));
    assert_eq!((s.pane, s.cursor()), (0, 4), "wrapped back with its cursor");
    s.handle(Key::BackTab);
    assert_eq!(s.pane, 1);
}

#[test]
fn provenance_follows_the_pointer_then_the_cursor() {
    let mut s = ReviewState::new(view());
    assert_eq!(s.provenance(), Some("M.A rev a"));
    s.handle(Key::Tab);
    assert_eq!(s.provenance(), Some("M.B rev b"));
    s.hover(Some(1));
    assert_eq!(s.provenance(), Some("M.B rev b"));
    s.hover(Some(99));
    assert_eq!(
        s.provenance(),
        Some("M.B rev b"),
        "off the end falls back to the cursor"
    );
    // An empty side has no provenance to show.
    let mut empty = view();
    empty.panes[0].lines.clear();
    assert_eq!(ReviewState::new(empty).provenance(), None);
}

#[test]
fn commands_quit_help_and_never_act_for_the_user() {
    let mut s = ReviewState::new(view());
    assert_eq!(s.handle(Key::Char('?')), Effect::Message(HELP.to_string()));
    s.handle(Key::Char(':'));
    assert_eq!(s.mode, Mode::Command);
    keys(&mut s, "sign");
    let effect = s.handle(Key::Enter);
    match effect {
        Effect::Message(text) => assert!(text.contains("keyquorum file sign"), "{text}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(s.mode, Mode::Normal);
    for command in ["accept", "reject", "finalize", "countersign"] {
        s.handle(Key::Char(':'));
        keys(&mut s, command);
        assert!(matches!(s.handle(Key::Enter), Effect::Message(t) if t.contains("not available")));
    }
    s.handle(Key::Char(':'));
    keys(&mut s, "bogus");
    assert!(matches!(s.handle(Key::Enter), Effect::Message(t) if t.contains("unknown command")));
    s.handle(Key::Char(':'));
    keys(&mut s, "q");
    assert_eq!(s.handle(Key::Enter), Effect::Quit);
    assert_eq!(keys(&mut ReviewState::new(view()), "q"), vec![Effect::Quit]);
}

#[test]
fn escape_and_backspace_leave_command_mode() {
    let mut s = ReviewState::new(view());
    s.handle(Key::Char(':'));
    keys(&mut s, "ab");
    s.handle(Key::Backspace);
    assert_eq!(s.command, "a");
    s.handle(Key::Backspace);
    s.handle(Key::Backspace);
    assert_eq!(s.mode, Mode::Normal);
    s.handle(Key::Char(':'));
    keys(&mut s, "zz");
    s.handle(Key::Esc);
    assert_eq!((s.mode, s.command.as_str()), (Mode::Normal, ""));
    // Movement keys typed into a command are text, not motion.
    s.handle(Key::Char(':'));
    keys(&mut s, "jjj");
    assert_eq!(s.cursor(), 0);
}

#[test]
fn a_g_before_command_mode_does_not_leave_a_pending_gg() {
    let mut s = ReviewState::new(view());
    keys(&mut s, "jjjjj");
    // g, then into command mode and out again, then a single g: still no motion.
    keys(&mut s, "g");
    s.handle(Key::Char(':'));
    s.handle(Key::Esc);
    keys(&mut s, "g");
    assert_eq!(s.cursor(), 5, "the earlier g must not pair with this one");
    s.handle(Key::Char('x')); // an ignored key clears the g that is now pending
                              // Leaving command mode by an empty Backspace or by Enter does the same.
    keys(&mut s, "g");
    s.handle(Key::Char(':'));
    s.handle(Key::Backspace);
    keys(&mut s, "g");
    assert_eq!(s.cursor(), 5);
    s.handle(Key::Char('x'));
    keys(&mut s, "g");
    s.handle(Key::Char(':'));
    s.handle(Key::Enter);
    keys(&mut s, "g");
    assert_eq!(s.cursor(), 5);
    s.handle(Key::Char('x'));
    // Two g's in a row still go to the top.
    keys(&mut s, "gg");
    assert_eq!(s.cursor(), 0);
}

#[test]
fn search_wraps_and_repeats_in_both_directions() {
    let mut s = ReviewState::new(view());
    s.handle(Key::Char('/'));
    keys(&mut s, "l2");
    assert_eq!(s.mode, Mode::Search);
    assert_eq!(s.handle(Key::Enter), Effect::None);
    assert_eq!(s.cursor(), 2);

    assert_eq!(s.handle(Key::Char('n')), Effect::None);
    assert_eq!(s.cursor(), 20, "matching is substring-based and wraps");
    assert_eq!(s.handle(Key::Char('N')), Effect::None);
    assert_eq!(s.cursor(), 2);
}

#[test]
fn search_reports_absent_patterns_and_can_be_cancelled() {
    let mut s = ReviewState::new(view());
    assert_eq!(
        s.handle(Key::Char('n')),
        Effect::Message("no previous search".to_string())
    );
    s.handle(Key::Char('/'));
    keys(&mut s, "missing");
    assert!(matches!(s.handle(Key::Enter), Effect::Message(t) if t.contains("pattern not found")));
    s.handle(Key::Char('/'));
    keys(&mut s, "discarded");
    s.handle(Key::Esc);
    assert_eq!((s.mode, s.command.as_str()), (Mode::Normal, ""));
}

/// One side with two changes: lines 0-2 are hunk 0, line 3 is hunk 1.
fn hunked() -> ReviewState {
    let at = |number: usize, hunk: usize| ViewLine {
        kind: ChangeKind::Added,
        number,
        text: format!("line {number}"),
        hunk,
        provenance: "M.A rev a".to_string(),
    };
    ReviewState::new(ReviewView {
        title: "plan.txt — merge review".to_string(),
        panes: vec![Pane {
            heading: "LEFT".to_string(),
            lines: vec![at(1, 0), at(2, 0), at(3, 0), at(9, 1)],
            ..Default::default()
        }],
        ..Default::default()
    })
}

#[test]
fn zc_folds_a_change_to_one_line_and_the_cursor_steps_over_it() {
    let mut state = hunked();
    keys(&mut state, "jzc");
    assert_eq!(
        state.visible(0),
        vec![0, 3],
        "hunk 0 shows only its first line"
    );
    assert_eq!(state.cursor(), 0, "the cursor moved to the fold");
    assert_eq!(state.fold_hidden(0, 0), Some(2));
    assert_eq!(state.fold_hidden(0, 3), None);
    keys(&mut state, "j");
    assert_eq!(state.cursor(), 3, "j skips the hidden lines");
    keys(&mut state, "k");
    assert_eq!(state.cursor(), 0);
}

#[test]
fn zo_za_zM_and_zR_open_toggle_and_fold_every_change() {
    let mut state = hunked();
    keys(&mut state, "zM");
    assert_eq!(state.visible(0), vec![0, 3]);
    keys(&mut state, "zR");
    assert_eq!(state.visible(0), vec![0, 1, 2, 3]);
    keys(&mut state, "za");
    assert_eq!(state.visible(0), vec![0, 3]);
    keys(&mut state, "za");
    assert_eq!(state.visible(0), vec![0, 1, 2, 3]);
    keys(&mut state, "zczo");
    assert_eq!(state.visible(0), vec![0, 1, 2, 3]);
    // z then anything else cancels and is not a fold command.
    keys(&mut state, "zx");
    assert_eq!(state.visible(0), vec![0, 1, 2, 3]);
}

#[test]
fn a_search_match_inside_a_fold_opens_it() {
    let mut state = hunked();
    keys(&mut state, "zM");
    state.handle(Key::Char('/'));
    keys(&mut state, "line 3");
    state.handle(Key::Enter);
    assert_eq!(state.cursor(), 2);
    assert_eq!(state.visible(0), vec![0, 1, 2, 3]);
}
