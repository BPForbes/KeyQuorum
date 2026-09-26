//! The lab's advanced terminal. Commands call the same [`LabState`]
//! methods as the GUI buttons, so the two can never disagree; the terminal
//! only formats the result as text.

use super::state::{LabState, Outcome};
use super::view::{RequirementNode, StepStatus, TraceStep};
use crate::error::Result;

pub const HELP: &[&str] = &[
    "whoami                      active identity",
    "users                       list lab users",
    "su <name|label>             switch user (e.g. su david, su M.A)",
    "usb                         list mock USB drives",
    "usb insert|eject <drive>    engineering, accounting, executive",
    "ls                          files visible to you",
    "status <file>               key tree and custody policy",
    "unlock <file>               attempt a quorum unlock",
    "send <file> <user>          seal a file-delivery letter to a user",
    "inbox                       letters sealed to you",
    "receive <id> | reject <id>  answer a delivery letter",
    "refresh                     verify acknowledgements sealed to you",
    "sent                        your sent transfers",
    "approvals                   unlock approvals you asked for or owe",
    "approve <id> | decline <id> answer an approval request",
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
        ["ls"] => {
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
                    output.push(format!("$ keyquorum access quorum --status --id {id}"));
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
                quiet(true, output)
            }
            None => quiet(false, vec![format!("No file named {file}")]),
        },
        ["unlock", file] | ["cat", file] | ["open", file] => with_trace(state.unlock(file)?),
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
                    "{} acknowledgement(s) waiting — run `refresh`",
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
        ["approvals"] => {
            let snapshot = state.snapshot()?;
            let mut output: Vec<String> = snapshot
                .approvals
                .iter()
                .map(|item| {
                    format!(
                        "#{} {} leaf {} · approver {} · requested by {} — {}",
                        item.id,
                        item.file_name,
                        item.leaf,
                        item.approver,
                        item.requested_by,
                        item.status
                    )
                })
                .collect();
            if output.is_empty() {
                output.push("No approval requests".into());
            }
            quiet(true, output)
        }
        ["approve", id] | ["decline", id] => match id.trim_start_matches('#').parse::<u64>() {
            Ok(id) => with_trace(state.answer_approval(id, words[0] == "approve")?),
            Err(_) => quiet(false, vec![format!("Not an approval id: {id}")]),
        },
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
            quiet(true, output)
        }
        _ => quiet(
            false,
            vec![format!("Unknown command: {line}. Type `help`.")],
        ),
    })
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
            "{pad}{} {}",
            node.label,
            node.holder.as_deref().unwrap_or("")
        )),
    }
    for child in &node.children {
        requirement_lines(child, depth + 1, out);
    }
}
