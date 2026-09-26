//! The `keyquorum` binary: parses [`keyquorum::cli::Cli`] and runs it
//! against the real filesystem and terminal. Every command lives in the
//! library (`keyquorum::cli`) so the browser lab runs the same code; only
//! the provider-only `host` handler is served from here.

use clap::Parser;
#[cfg(feature = "provider")]
use keyquorum::cli::Command;
use keyquorum::cli::{self, Cli};
use std::process::ExitCode;

#[cfg(feature = "provider")]
mod host;

fn main() -> ExitCode {
    let cli = Cli::parse();

    let ran = match cli.command {
        #[cfg(feature = "provider")]
        Command::Host {
            mailbox_db,
            command,
        } => host::run(&mailbox_db, &cli.db, command),
        command => cli::run(&cli.db, command),
    };
    match ran {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
