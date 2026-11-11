//! The three facts tree reconstruction needs from outside the tree.
//!
//! Reconstruction asks whether a leaf is a ghost, which physical device a
//! key sits on and what the key's custody policy is. [`SqlContext`] answers
//! them from the SQLite store through the existing `device` functions;
//! [`StaticContext`] answers them from plain data, for a caller with no
//! database. The rule that uses the answers is one function either way.

use crate::device::{self, CustodyPolicy, DEVICE_ID_LEN};
use crate::error::{Error, Result};
use crate::keys;
use rusqlite::Connection;
use std::collections::{BTreeMap, BTreeSet};

/// Facts about one key tree that reconstruction and custody checks read.
pub trait TreeContext {
    /// True when this hardware key is a ghost identity.
    fn is_ghost(&self, hardware_key_id: i64) -> Result<bool>;
    /// Device id and slot label (if placed) of a hardware key. A key with
    /// no placement is its own device ([`device::solo_device_id`]).
    fn device_of(&self, hardware_key_id: i64) -> Result<([u8; DEVICE_ID_LEN], Option<String>)>;
    /// The tree's custody policy.
    fn policy(&self) -> Result<CustodyPolicy>;
}

/// [`TreeContext`] over a SQLite store: delegates to the `device` functions.
pub struct SqlContext<'a> {
    pub conn: &'a Connection,
    pub key_id: i64,
}

impl<'a> SqlContext<'a> {
    pub fn new(conn: &'a Connection, key_id: i64) -> Self {
        Self { conn, key_id }
    }
}

impl TreeContext for SqlContext<'_> {
    fn is_ghost(&self, hardware_key_id: i64) -> Result<bool> {
        device::leaf_is_ghost(self.conn, hardware_key_id)
    }

    fn device_of(&self, hardware_key_id: i64) -> Result<([u8; DEVICE_ID_LEN], Option<String>)> {
        let key = keys::get_key(self.conn, hardware_key_id)?;
        device::device_for_key(self.conn, &key)
    }

    fn policy(&self) -> Result<CustodyPolicy> {
        device::custody_policy(self.conn, self.key_id)
    }
}

/// What a [`StaticContext`] knows about one hardware key.
#[derive(Clone, Debug)]
pub struct StaticKey {
    /// The key's public key (an unplaced key's device id derives from it).
    pub public_key: Vec<u8>,
    /// Device id and slot label of its placement, if it has one.
    pub placement: Option<([u8; DEVICE_ID_LEN], String)>,
}

/// [`TreeContext`] over plain data supplied by the caller.
#[derive(Clone, Debug, Default)]
pub struct StaticContext {
    pub ghosts: BTreeSet<i64>,
    pub keys: BTreeMap<i64, StaticKey>,
    pub policy: CustodyPolicy,
}

impl TreeContext for StaticContext {
    fn is_ghost(&self, hardware_key_id: i64) -> Result<bool> {
        Ok(self.ghosts.contains(&hardware_key_id))
    }

    fn device_of(&self, hardware_key_id: i64) -> Result<([u8; DEVICE_ID_LEN], Option<String>)> {
        let key = self
            .keys
            .get(&hardware_key_id)
            .ok_or(Error::InvalidDevice)?;
        Ok(match &key.placement {
            Some((id, slot)) => (*id, Some(slot.clone())),
            None => (device::solo_device_id(&key.public_key), None),
        })
    }

    fn policy(&self) -> Result<CustodyPolicy> {
        Ok(self.policy.clone())
    }
}
