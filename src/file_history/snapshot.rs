//! `KQHS`: a portable snapshot of a file's event history, without payloads,
//! revisions or proofs. It is protocol data, not a document: decoding
//! rebuilds the hash chain and checks the stated root, so a snapshot that
//! decodes is internally consistent. Whether it matches a given container
//! is a separate question, answered by [`HistorySnapshot::is_prefix_of`].
//!
//! Layout (big-endian): `magic(4) | version(1) | file_id(16) |
//! history_root(32) | event_count(u32) | events…`.

use super::codec::{bad, take_fixed};
use super::container::TrackedFile;
use super::event::{genesis_hash, verify_chain, HistoryEvent};
use crate::envelope::take_u32;
use crate::error::{Error, Result};

pub const SNAPSHOT_MAGIC: &[u8; 4] = b"KQHS";
pub const SNAPSHOT_VERSION: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistorySnapshot {
    pub file_id: [u8; 16],
    pub history_root: [u8; 32],
    pub events: Vec<HistoryEvent>,
}

impl TrackedFile {
    /// The whole event history as a snapshot.
    pub fn history_snapshot(&self) -> HistorySnapshot {
        HistorySnapshot {
            file_id: self.file_id,
            history_root: self.history_root(),
            events: self.events.clone(),
        }
    }
}

impl HistorySnapshot {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let root = verify_chain(&self.file_id, &self.events)?;
        if root != self.history_root {
            return Err(Error::InvalidTrackedFile);
        }
        let count = u32::try_from(self.events.len()).map_err(|_| Error::BundleFieldTooLarge)?;
        let mut out = Vec::new();
        out.extend_from_slice(SNAPSHOT_MAGIC);
        out.push(SNAPSHOT_VERSION);
        out.extend_from_slice(&self.file_id);
        out.extend_from_slice(&self.history_root);
        out.extend_from_slice(&count.to_be_bytes());
        for event in &self.events {
            event.encode(&mut out)?;
        }
        Ok(out)
    }

    /// Parse and verify: the chain must be unbroken for this file and end
    /// at the stated root. Trailing bytes are rejected.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut data = bytes;
        if take_fixed::<4>(&mut data)? != *SNAPSHOT_MAGIC
            || take_fixed::<1>(&mut data)?[0] != SNAPSHOT_VERSION
        {
            return Err(Error::InvalidTrackedFile);
        }
        let file_id = take_fixed::<16>(&mut data)?;
        let history_root = take_fixed::<32>(&mut data)?;
        let count = bad(take_u32(&mut data))?;
        let mut events = Vec::new();
        for _ in 0..count {
            events.push(HistoryEvent::decode(&mut data)?);
        }
        if !data.is_empty() || verify_chain(&file_id, &events)? != history_root {
            return Err(Error::InvalidTrackedFile);
        }
        Ok(Self {
            file_id,
            history_root,
            events,
        })
    }

    /// True when `file` holds exactly these events as the start of its own
    /// history: the snapshot is a point the file's history passed through.
    pub fn is_prefix_of(&self, file: &TrackedFile) -> bool {
        self.file_id == file.file_id
            && file.events.len() >= self.events.len()
            && file.events[..self.events.len()] == self.events[..]
            && (self.events.is_empty() && self.history_root == genesis_hash(&self.file_id)
                || self.events.last().map(|e| e.event_hash) == Some(self.history_root))
    }
}
