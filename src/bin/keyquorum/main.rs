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
        Command::Host(opts) => host::run(
            &host::StoreArgs {
                mailbox_db: opts.mailbox_db,
                mongodb_uri_file: opts.mongodb_uri_file,
                mongodb_db: opts.mongodb_db,
            },
            &cli::resolve_db(cli.db.as_deref()),
            opts.command,
        ),
        command => cli::run_cli(Cli { command, ..cli }),
    };
    match ran {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            // Usage mistakes exit 2, clap's own convention.
            if matches!(err, keyquorum::error::Error::Usage(_)) {
                ExitCode::from(2)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
