//! Notices for the commands `send` and `inbox` replace. The old commands
//! still work exactly as before; after one succeeds, a line on stderr names
//! the command to use instead. Stdout and the exit status are untouched, so a
//! script that parses either keeps working.

use super::env::errln;

/// Say, after a legacy command ran, what to use in its place.
pub(crate) fn notice(old: &str, instead: &str) {
    errln!("note: `keyquorum {old}` is a legacy command and will be retired. Use: {instead}");
}

pub(crate) const SEND: &str = "keyquorum send <file> --to <label>";
pub(crate) const OPEN: &str = "keyquorum inbox open";
pub(crate) const PULL: &str =
    "keyquorum inbox (to list) or keyquorum inbox open (to open and answer)";
