//! The `keyquorum-device` binary: parses
//! [`keyquorum::cli::device_tool::DeviceToolCli`] and runs it against the
//! real filesystem and terminal. The commands live in the library so the
//! browser lab runs the same code.

use clap::Parser;
use keyquorum::cli::device_tool::{self, DeviceToolCli};
use std::process::ExitCode;

fn main() -> ExitCode {
    match device_tool::run(DeviceToolCli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
