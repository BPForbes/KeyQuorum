//! C-callable account heritage for Flinstone.
//!
//! Account key ids are dotted labels such as `Root.Flinstone.Bob`. The
//! topology (ancestry, parent, relation) is KeyQuorum's own, from
//! [`keyquorum::authority`]. This crate adds only the account policy that
//! Flinstone needs: the master is `Root`, names are `[A-Za-z0-9_-]{1,31}`,
//! at most eight levels deep, and a home directory mirrors the key id.
//!
//! [`account`] adds account keys: an Ed25519 signing key per account, sealed
//! under its password, and the signatures on account bridges.
//!
//! No exported function stores anything or reads a clock; the key functions
//! read the operating system's random source. Buffers are caller-owned and
//! the C header is `include/keyquorum_identity.h`.

pub mod account;
pub mod ffi;
pub mod heritage;
