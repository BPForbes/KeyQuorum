//! C-callable account heritage for Flinstone.
//!
//! Account key ids are dotted labels such as `Root.Flinstone.Bob`. The
//! topology (ancestry, parent, relation) is KeyQuorum's own, from
//! [`keyquorum::authority`]. This crate adds only the account policy that
//! Flinstone needs: the master is `Root`, names are `[A-Za-z0-9_-]{1,31}`,
//! at most eight levels deep, and a home directory mirrors the key id.
//!
//! Every exported function is pure: no storage, no clock, no allocation
//! that outlives the call. Buffers are caller-owned and the C header is
//! `include/keyquorum_identity.h`.

pub mod ffi;
pub mod heritage;
