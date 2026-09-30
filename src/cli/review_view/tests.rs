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
fn commands_quit_help_and_do_not_act_until_told_who_is_acting() {
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
    for command in ["accept left", "reject", "finalize"] {
        s.handle(Key::Char(':'));
        keys(&mut s, command);
        assert!(
            matches!(s.handle(Key::Enter), Effect::Message(t) if t.contains(":as LABEL")),
            "{command}"
        );
    }
    s.handle(Key::Char(':'));
    keys(&mut s, "countersign");
    assert!(matches!(s.handle(Key::Enter), Effect::Message(t) if t.contains("not available")));
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

/// Base "a b c d\n" as four lines; LEFT changes line 2 (b -> B), RIGHT
/// changes line 4 (d -> D) and, overlapping LEFT, line 2 (b -> bb).
fn pickable() -> ReviewState {
    let hunk = |start: usize, end: usize, text: &str| DiffHunk {
        start,
        end,
        lines: vec![text.to_string()],
    };
    let at = |number: usize, hunk: usize, text: &str| ViewLine {
        kind: ChangeKind::Added,
        number,
        text: text.to_string(),
        hunk,
        provenance: "M.A rev a".to_string(),
    };
    ReviewState::new(ReviewView {
        title: "t".to_string(),
        base_text: Some("a\nb\nc\nd\n".to_string()),
        panes: vec![
            Pane {
                heading: "LEFT".to_string(),
                lines: vec![at(2, 0, "B")],
                hunks: vec![hunk(1, 2, "B\n")],
                ..Default::default()
            },
            Pane {
                heading: "RIGHT".to_string(),
                lines: vec![at(2, 0, "bb"), at(4, 1, "D")],
                hunks: vec![hunk(1, 2, "bb\n"), hunk(3, 4, "D\n")],
                ..Default::default()
            },
        ],
        ..Default::default()
    })
}

#[test]
fn space_picks_changes_from_both_sides_and_compose_applies_them() {
    let mut state = pickable();
    assert!(state.compose().unwrap_err().contains("nothing picked"));
    // LEFT's change, then RIGHT's second change.
    assert_eq!(
        state.handle(Key::Char(' ')),
        Effect::Message("1 change(s) picked; :compose shows the result".to_string())
    );
    keys(&mut state, "lj");
    state.handle(Key::Char(' '));
    assert_eq!(state.picked_count(), 2);
    assert!(state.is_picked(0, 0) && state.is_picked(1, 1) && !state.is_picked(1, 0));
    assert_eq!(state.compose().unwrap(), "a\nB\nc\nD\n");
    // Space again unpicks.
    state.handle(Key::Char(' '));
    assert_eq!(state.compose().unwrap(), "a\nB\nc\nd\n");
}

#[test]
fn overlapping_picks_are_refused_and_unpick_clears_everything() {
    let mut state = pickable();
    state.handle(Key::Char(' '));
    keys(&mut state, "l");
    state.handle(Key::Char(' '));
    assert!(state.compose().unwrap_err().contains("overlap"));
    for c in ":unpick".chars() {
        state.handle(Key::Char(c));
    }
    assert_eq!(
        state.handle(Key::Enter),
        Effect::Message("picks and edit cleared".to_string())
    );
    assert_eq!(state.picked_count(), 0);
}

#[test]
fn edit_opens_the_current_result_and_the_edit_becomes_the_result() {
    let mut state = pickable();
    let run = |state: &mut ReviewState, command: &str| {
        state.handle(Key::Char(':'));
        for c in command.chars() {
            state.handle(Key::Char(c));
        }
        state.handle(Key::Enter)
    };
    // Nothing picked: the editor starts from the common ancestor.
    assert_eq!(
        run(&mut state, "edit"),
        Effect::Edit("a\nb\nc\nd\n".to_string())
    );
    state.handle(Key::Char(' '));
    assert_eq!(
        run(&mut state, "edit"),
        Effect::Edit("a\nB\nc\nd\n".to_string())
    );
    state.set_edited("a\nB\nC\nd\n".to_string());
    assert_eq!(state.compose().unwrap(), "a\nB\nC\nd\n");
    assert!(matches!(
        run(&mut state, "compose"),
        Effect::Message(text) if text.contains("your edit")
    ));
}

#[test]
fn a_side_with_no_line_changes_has_nothing_to_pick() {
    let mut state = hunked();
    assert!(matches!(
        state.handle(Key::Char(' ')),
        Effect::Message(text) if text.contains("nothing to pick")
    ));
}

fn run(state: &mut ReviewState, command: &str) -> Effect {
    state.handle(Key::Char(':'));
    for c in command.chars() {
        state.handle(Key::Char(c));
    }
    state.handle(Key::Enter)
}

#[test]
fn once_told_who_is_acting_the_commands_hand_an_action_to_the_shell() {
    let mut state = pickable();
    assert!(matches!(run(&mut state, "as"), Effect::Message(t) if t.contains("usage")));
    assert!(matches!(run(&mut state, "slot nope"), Effect::Message(t) if t.contains("usage")));
    assert_eq!(state.identity(), None, "both are needed");
    run(&mut state, "as M.A");
    assert_eq!(state.identity(), None);
    run(&mut state, "slot /usb/ma=M.A");
    assert_eq!(state.identity(), Some(("M.A", "/usb/ma=M.A")));

    assert_eq!(
        run(&mut state, "accept left"),
        Effect::Run(Action::KeepLeft)
    );
    assert_eq!(
        run(&mut state, "accept right"),
        Effect::Run(Action::KeepRight)
    );
    assert_eq!(run(&mut state, "reject"), Effect::Run(Action::Reject));
    assert_eq!(run(&mut state, "sign"), Effect::Run(Action::Sign));
    assert_eq!(run(&mut state, "finalize"), Effect::Run(Action::Finalize));
    assert!(
        matches!(run(&mut state, "accept sideways"), Effect::Message(t) if t.contains("usage"))
    );

    // A result needs something picked or edited first.
    assert!(
        matches!(run(&mut state, "accept result"), Effect::Message(t) if t.contains("nothing picked"))
    );
    state.handle(Key::Char(' '));
    assert_eq!(
        run(&mut state, "accept result"),
        Effect::Run(Action::Result("a\nB\nc\nd\n".to_string()))
    );
}

#[test]
fn a_reload_forgets_picks_and_folds_but_keeps_who_is_acting() {
    let mut state = pickable().with_identity(Some("M.A".into()), Some("/usb/ma=M.A".into()));
    state.handle(Key::Char(' '));
    keys(&mut state, "zc");
    state.reload(pickable().view);
    assert_eq!(state.picked_count(), 0);
    assert_eq!(state.visible(0), vec![0]);
    assert_eq!(state.identity(), Some(("M.A", "/usb/ma=M.A")));
}
