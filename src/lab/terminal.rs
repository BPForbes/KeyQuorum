//! The lab's terminal: a small shell on the lab VM. A few shell builtins
//! (`ls`, `cat`, `cd`, `su`, `usb`) stand in for what a desktop provides;
//! every `keyquorum` / `keyquorum-device` line runs the real CLI through
//! [`LabState::command`], and the shortcuts (`unlock`, `send`, …) call the
//! same [`LabState`] methods as the GUI buttons, which run real command
//! lines too. The terminal only formats results as text.

use super::state::{LabState, Outcome};
use super::view::{RequirementNode, StepStatus, TraceStep};
use super::vm::ORG_DB;
use crate::error::Result;

pub const HELP: &[&str] = &[
    "keyquorum ...               the real CLI (try `keyquorum --help`)",
    "keyquorum-device ...        the real device tool",
    "bridge ...                  shorthand for keyquorum --db <org store> bridge ...",
    "",
    "whoami                      active identity",
    "users                       list lab users",
    "su <name|label>             sign in as someone else (e.g. su david, su M.A)",
    "usb                         list mock USB drives",
    "usb insert|eject <drive>    plug a drive in or pull it out",
    "ls [dir] · cat <file> · cd [dir] · pwd",
    "",
    "Shortcuts (each runs real commands and shows them):",
    "files                       the org's files and how you relate to them",
    "status <file>               key tree, custody policy, and dates",
    "unlock <file>               open a file (access quorum --state 1)",
    "send <file> <user>          deliver a file (deliver send --push)",
    "inbox                       letters in ~/mail",
    "refresh                     relay pull, then deliver ack",
    "receive <id> | reject <id>  deliver open --push-ack",
    "sent                        your sent deliveries",
    "move <label> <drive>        keyquorum-device relocate + device bind",
    "tree                        org tree from your view",
    "reset                       restore the seeded lab",
];

/// Parse one line and run it. `reset` is handled by the caller, which owns
/// the state value; everything else mutates `state` in place.
pub fn run(state: &mut LabState, line: &str) -> Result<(Outcome, Vec<String>)> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let quiet = |ok: bool, output: Vec<String>| {
        (
            Outcome {
                ok,
                message: String::new(),
                trace: vec![],
                opened: None,
            },
            output,
        )
    };
    let with_trace = |outcome: Outcome| {
        let mut output = vec![outcome.message.clone()];
        output.extend(outcome.trace.iter().map(trace_line));
        if let Some(opened) = &outcome.opened {
            output.push(format!("--- {} ---", opened.name));
            output.extend(opened.text.lines().map(str::to_string));
        }
        (outcome, output)
    };

    Ok(match words.as_slice() {
        [] => quiet(true, vec![]),
        ["help"] => quiet(true, HELP.iter().map(|line| line.to_string()).collect()),
        ["keyquorum", ..] | ["keyquorum-device", ..] => command(state, line.trim())?,
        ["bridge", ..] => {
            let rest = line.trim().strip_prefix("bridge").unwrap_or_default();
            command(state, &format!("keyquorum --db {ORG_DB} bridge{rest}"))?
        }
        ["whoami"] => quiet(true, vec![state.active_summary()]),
        ["users"] => quiet(
            true,
            state
                .user_names()
                .into_iter()
                .map(|(name, label, role, active)| {
                    format!(
                        "{} {name:<7} {label:<6} {role}",
                        if active { "*" } else { " " }
                    )
                })
                .collect(),
        ),
        ["su", who] => with_trace(state.switch_user(who)?),
        ["usb"] => {
            let snapshot = state.snapshot()?;
            quiet(
                true,
                snapshot
                    .drives
                    .iter()
                    .map(|drive| {
                        format!(
                            "{:<16} {:<9} {:<24} slots {}",
                            drive.name,
                            if drive.connected {
                                "inserted"
                            } else {
                                "ejected"
                            },
                            drive.mount,
                            drive
                                .slots
                                .iter()
                                .map(|slot| slot.label.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    })
                    .collect(),
            )
        }
        ["usb", "insert", drive] => with_trace(state.set_drive(drive, true)?),
        ["usb", "eject", drive] => with_trace(state.set_drive(drive, false)?),
        ["pwd"] => quiet(true, vec![state.cwd()]),
        ["cd"] => quiet(true, vec![state.cd("~")]),
        ["cd", dir] => quiet(true, vec![state.cd(dir)]),
        ["ls"] => shell(state.ls(".")),
        ["ls", dir] => shell(state.ls(dir)),
        ["cat", path] => shell(
            state
                .read_text(path)
                .map(|text| text.lines().map(str::to_string).collect::<Vec<_>>()),
        ),
        ["move", label, drive] => with_trace(state.move_slot(label, drive)?),
        ["files"] => {
            let snapshot = state.snapshot()?;
            quiet(
                true,
                snapshot
                    .files
                    .iter()
                    .map(|file| {
                        format!(
                            "/{}/{:<24} {:<9} access: {}",
                            file.folder, file.name, file.protection, file.access
                        )
                    })
                    .collect(),
            )
        }
        ["status", file] | ["inspect", file] => match state.inspect(file)? {
            Some(view) => {
                let mut output = vec![format!("{} — {}", view.name, view.lesson)];
                if let Some(id) = view.quorum_file_id {
                    output.push(format!(
                        "$ keyquorum --db {ORG_DB} access quorum --status --id {id}"
                    ));
                }
                if let Some(requirement) = &view.requirement {
                    requirement_lines(requirement, 0, &mut output);
                }
                if let Some(policy) = &view.policy {
                    output.push(format!(
                        "custody {} · minimum devices {} · unlock approval {}",
                        policy.custody, policy.minimum_devices, policy.approval
                    ));
                }
                if !view.created_at.is_empty() {
                    output.push(format!("created {} UTC", view.created_at));
                }
                match (&view.expires_at, view.expired) {
                    (Some(expires_at), true) => {
                        output.push(format!("expired {expires_at} UTC — removed on next access"))
                    }
                    (Some(expires_at), false) => output.push(format!("expires {expires_at} UTC")),
                    (None, _) => output.push("never expires".into()),
                }
                quiet(true, output)
            }
            None => quiet(false, vec![format!("No file named {file}")]),
        },
        ["unlock", file] | ["open", file] => with_trace(state.unlock(file)?),
        ["send", file, to] => with_trace(state.send(file, to)?),
        ["inbox"] => {
            let snapshot = state.snapshot()?;
            let mut output: Vec<String> = snapshot
                .inbox
                .iter()
                .map(|item| {
                    format!(
                        "#{:<3} {:<9} {} {}",
                        item.relay_id,
                        item.status,
                        item.from
                            .as_deref()
                            .unwrap_or("(sealed: open to see sender)"),
                        item.file_name.as_deref().unwrap_or("")
                    )
                })
                .collect();
            if output.is_empty() {
                output.push("No letters sealed to you".into());
            }
            if snapshot.pending_acks > 0 {
                output.push(format!(
                    "{} acknowledgement(s) waiting — insert your drive and run `refresh`",
                    snapshot.pending_acks
                ));
            }
            quiet(true, output)
        }
        ["receive", id] | ["reject", id] => match id.trim_start_matches('#').parse::<i64>() {
            Ok(id) => with_trace(state.receive(id, words[0] == "receive")?),
            Err(_) => quiet(false, vec![format!("Not a letter id: {id}")]),
        },
        ["refresh"] => with_trace(state.refresh_inbox()?),
        ["sent"] => {
            let snapshot = state.snapshot()?;
            let mut output: Vec<String> = snapshot
                .sent
                .iter()
                .map(|item| {
                    format!(
                        "#{:<3} to {} ({}) {} — {}",
                        item.relay_id, item.to, item.to_label, item.file_name, item.status
                    )
                })
                .collect();
            if output.is_empty() {
                output.push("Nothing sent yet".into());
            }
            quiet(true, output)
        }
        ["tree"] => {
            let snapshot = state.snapshot()?;
            let mut output = Vec::new();
            for node in &snapshot.tree.nodes {
                let depth = node.label.matches('.').count();
                output.push(format!(
                    "{}{} {} {}{}",
                    "  ".repeat(depth),
                    node.label,
                    node.person.as_deref().unwrap_or(""),
                    if node.visible {
                        ""
                    } else {
                        "(outside your slice) "
                    },
                    if node.active_user { "← you" } else { "" }
                ));
            }
            for (a, b) in &snapshot.tree.bridges {
                output.push(format!("bridge {a} <-> {b}"));
            }
            output.push(format!(
                "org tree key id {} (e.g. bridge list {})",
                snapshot.tree.key_id, snapshot.tree.key_id
            ));
            quiet(true, output)
        }
        [first, ..] => quiet(
            false,
            vec![format!("{first}: command not found. Type `help`.")],
        ),
    })
}

/// A CLI line: what it printed, verbatim, then the lab's note of whose
/// visible slice changed.
fn command(state: &mut LabState, line: &str) -> Result<(Outcome, Vec<String>)> {
    let (outcome, run) = state.command(line)?;
    let mut output: Vec<String> = run.stderr.lines().map(str::to_string).collect();
    output.extend(run.stdout_text().lines().map(str::to_string));
    // The first transcript steps repeat the line and its output; the rest
    // are the visibility notes.
    let echoed = 1 + run.stderr.lines().count() + run.stdout_text().lines().count();
    output.extend(outcome.trace.iter().skip(echoed).map(trace_line));
    Ok((outcome, output))
}

fn shell(result: Result<Vec<String>>) -> (Outcome, Vec<String>) {
    let (ok, output) = match result {
        Ok(lines) => (true, lines),
        Err(err) => (false, vec![format!("error: {err}")]),
    };
    (
        Outcome {
            ok,
            message: String::new(),
            trace: vec![],
            opened: None,
        },
        output,
    )
}

fn trace_line(step: &TraceStep) -> String {
    let mark = match step.status {
        StepStatus::Pass => "✓",
        StepStatus::Fail => "✕",
        StepStatus::Info => "·",
    };
    format!("  {mark} {}", step.text)
}

fn requirement_lines(node: &RequirementNode, depth: usize, out: &mut Vec<String>) {
    let pad = "  ".repeat(depth + 1);
    match node.threshold {
        Some(threshold) => out.push(format!(
            "{pad}{}: {threshold} of {}",
            node.label,
            node.children.len()
        )),
        None => out.push(format!(
            "{pad}{} {}{}",
            node.label,
            node.holder.as_deref().unwrap_or(""),
            if node.ghost {
                " (ghost — evicted)"
            } else {
                ""
            }
        )),
    }
    for child in &node.children {
        requirement_lines(child, depth + 1, out);
    }
}
