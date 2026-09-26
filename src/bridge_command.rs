//! The `keyquorum bridge allow|deny|add|remove|list` subcommands: their
//! clap definitions and the code that runs them. The `keyquorum` binary
//! flattens [`TreeBridgeCommand`] into its `bridge` subcommand and runs it
//! against stdout; the browser lab parses the same subcommands from its
//! terminal and runs them against its in-memory store, so both surfaces
//! execute this one implementation.

use crate::error::Result;
use crate::key_tree;
use clap::Subcommand;
use rusqlite::Connection;
use std::io::Write;

#[derive(Clone, Debug, Subcommand)]
pub enum TreeBridgeCommand {
    /// Grant --node permission to form a cross-branch link with --peer
    Allow {
        key_id: i64,
        #[arg(long)]
        node: String,
        #[arg(long)]
        peer: String,
    },
    /// Revoke that permission and drop any established link between them
    Deny {
        key_id: i64,
        #[arg(long)]
        node: String,
        #[arg(long)]
        peer: String,
    },
    /// Establish a pairing if either node's whitelist allows it
    Add {
        key_id: i64,
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
    },
    /// Tear down an established pairing (whitelist is left intact)
    Remove {
        key_id: i64,
        #[arg(long)]
        from: String,
        #[arg(long)]
        to: String,
    },
    /// List whitelist entries and established pairings
    List { key_id: i64 },
}

pub fn run(conn: &Connection, command: TreeBridgeCommand, out: &mut dyn Write) -> Result<()> {
    match command {
        TreeBridgeCommand::Allow { key_id, node, peer } => {
            key_tree::allow_bridge(conn, key_id, &node, &peer)?;
            writeln!(out, "Allowed {node} to bridge to {peer}")?;
        }
        TreeBridgeCommand::Deny { key_id, node, peer } => {
            key_tree::deny_bridge(conn, key_id, &node, &peer)?;
            writeln!(out, "Denied {node} bridging to {peer}")?;
        }
        TreeBridgeCommand::Add { key_id, from, to } => {
            key_tree::add_bridge(conn, key_id, &from, &to)?;
            writeln!(out, "Established bridge {from} <-> {to}")?;
        }
        TreeBridgeCommand::Remove { key_id, from, to } => {
            key_tree::remove_bridge(conn, key_id, &from, &to)?;
            writeln!(out, "Removed bridge {from} <-> {to}")?;
        }
        TreeBridgeCommand::List { key_id } => {
            let listing = key_tree::list_bridges(conn, key_id)?;
            writeln!(out, "Allowed:")?;
            if listing.allowed.is_empty() {
                writeln!(out, "  (none)")?;
            } else {
                for (node, peer) in listing.allowed {
                    writeln!(out, "  {node} -> {peer}")?;
                }
            }
            writeln!(out, "Established:")?;
            if listing.established.is_empty() {
                writeln!(out, "  (none)")?;
            } else {
                for link in listing.established {
                    writeln!(out, "  {} <-> {}", link.from, link.to)?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "bridge_command/tests.rs"]
mod tests;
