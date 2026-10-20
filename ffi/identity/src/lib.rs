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
//! [`ffi::files`] exports tracked files and co-signed delivery
//! (`include/keyquorum_files.h`): check in and sign, the public offer a host
//! verifies without the content, the recipient's co-signature, letters sealed
//! to an account's X25519 box key, delivery readiness, reads limited to what
//! a host accepted by a request time, and freshness. Trust comes from a key
//! table the caller fills from its own registry, never from a container.
//!
//! No exported function stores anything or reads a clock; the key functions
//! read the operating system's random source. Buffers are caller-owned and
//! the C headers are `include/keyquorum_identity.h` and
//! `include/keyquorum_files.h`.

pub mod account;
pub mod ffi;
pub mod heritage;
