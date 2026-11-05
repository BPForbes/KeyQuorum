//! The allocation types and macros the standard prelude provides, for the pure modules
//! to import in a build without `std` (`--no-default-features`). With `std` they are the
//! same items the prelude already names, so a module that imports this changes nothing.

pub(crate) use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
