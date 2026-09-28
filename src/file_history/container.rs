//! `KQTF`: the tracked-file container. Layout (all integers big-endian):
//!
//! `magic(4) | version(1) | file_id(16) | lp(logical_name) | history_root(32)
//!  | lp32(payload) | event_count(u32) | events…`
//!
//! Decoding rebuilds the chain from the events and refuses a container
//! whose stored `history_root` disagrees. Revision checkpoints and content
//! signatures arrive with the revision DAG and will bump the version.

use super::codec::{bad, take_fixed};
use super::event::{genesis_hash, verify_chain, HistoryEvent, NewEvent};
use crate::envelope::{
    push_len_prefixed, push_len_prefixed_u32, take_len_prefixed, take_len_prefixed_u32, take_u32,
    utf8,
};
use crate::error::{Error, Result};
use rand::rngs::OsRng;
use rand::RngCore;

pub const CONTAINER_MAGIC: &[u8; 4] = b"KQTF";
pub const CONTAINER_VERSION: u8 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrackedFile {
    /// Stable identity, independent of name, path or revision.
    pub file_id: [u8; 16],
    pub logical_name: String,
    /// The native file bytes, wrapped rather than modified.
    pub payload: Vec<u8>,
    /// Read through [`TrackedFile::events`]; only this module appends, so
    /// callers cannot rewrite or drop events behind the chain's back.
    pub(super) events: Vec<HistoryEvent>,
}

impl TrackedFile {
    pub fn new(file_id: [u8; 16], logical_name: &str, payload: Vec<u8>) -> Self {
        Self {
            file_id,
            logical_name: logical_name.to_string(),
            payload,
            events: Vec::new(),
        }
    }

    pub fn events(&self) -> &[HistoryEvent] {
        &self.events
    }

    /// Last event hash, or the file's genesis hash before any event.
    pub fn history_root(&self) -> [u8; 32] {
        self.events
            .last()
            .map_or_else(|| genesis_hash(&self.file_id), |event| event.event_hash)
    }

    /// Append an event: assigns a random event id, the next sequence and
    /// the link to the current root. Existing events are never touched, and
    /// the chain is verified first so a damaged history is not extended.
    pub fn append(&mut self, new: NewEvent) -> Result<&HistoryEvent> {
        verify_chain(&self.file_id, &self.events)?;
        let mut event_id = [0u8; 16];
        OsRng.fill_bytes(&mut event_id);
        let event = HistoryEvent::seal(
            event_id,
            self.events.len() as u64,
            self.file_id,
            self.history_root(),
            new,
        )?;
        self.events.push(event);
        Ok(&self.events[self.events.len() - 1])
    }

    /// Serialize, refusing a history that would not decode again.
    pub fn encode(&self) -> Result<Vec<u8>> {
        verify_chain(&self.file_id, &self.events)?;
        let count = u32::try_from(self.events.len()).map_err(|_| Error::BundleFieldTooLarge)?;
        let mut out = Vec::new();
        out.extend_from_slice(CONTAINER_MAGIC);
        out.push(CONTAINER_VERSION);
        out.extend_from_slice(&self.file_id);
        push_len_prefixed(&mut out, self.logical_name.as_bytes())?;
        out.extend_from_slice(&self.history_root());
        push_len_prefixed_u32(&mut out, &self.payload)?;
        out.extend_from_slice(&count.to_be_bytes());
        for event in &self.events {
            event.encode(&mut out)?;
        }
        Ok(out)
    }

    /// Parse a container and verify its history chain and stored root.
    /// Trailing bytes are rejected.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut data = bytes;
        if take_fixed::<4>(&mut data)? != *CONTAINER_MAGIC
            || take_fixed::<1>(&mut data)?[0] != CONTAINER_VERSION
        {
            return Err(Error::InvalidTrackedFile);
        }
        let file_id = take_fixed::<16>(&mut data)?;
        let logical_name = bad(take_len_prefixed(&mut data).and_then(utf8))?;
        let stored_root = take_fixed::<32>(&mut data)?;
        let payload = bad(take_len_prefixed_u32(&mut data))?.to_vec();
        let count = bad(take_u32(&mut data))?;
        let mut events = Vec::new();
        for _ in 0..count {
            events.push(HistoryEvent::decode(&mut data)?);
        }
        if !data.is_empty() || verify_chain(&file_id, &events)? != stored_root {
            return Err(Error::InvalidTrackedFile);
        }
        Ok(Self {
            file_id,
            logical_name,
            payload,
            events,
        })
    }
}
