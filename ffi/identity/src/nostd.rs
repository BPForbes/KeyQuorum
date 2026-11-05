//! The allocation types and macros the standard prelude provides, imported by
//! the modules in a build without `std`. With `std` they are the same items
//! the prelude names.

pub(crate) use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};
