//! Each person's outbox: a fixed-capacity ring buffer of the sealed letters
//! (`KQPB`) they have queued for other people, kept in their own store.
//!
//! The ring has a write pointer (`write_index`), a read pointer
//! (`read_index`) and a `size`, the number of slots held: queued and not
//! yet sent. [`push`] writes at the write pointer. Only [`send_next`], a
//! send to the letter's trusted recipient, moves the read pointer, and the
//! slot it frees is wiped. [`RingState`] says how the ring can be used: an
//! `Empty` ring has nothing to send, and a `Full` one refuses new letters.
//! It never overwrites one that has not been sent.
//!
//! A `KQPB` is the passport: nothing crosses from one person's ring to
//! another's except inside a sealed, signed letter. Every other `.kq*` file
//! travels inside one: a tracked file (`KQTF`) as a tracked-file letter, a
//! history snapshot (`KQHS`) as a snapshot letter, and an export bundle or
//! signature artifact as an ordinary delivery (`keyquorum send`). Device
//! letters (`KQTX` and relocations) are refused: they move a person's own
//! identity between their own devices, through the device mailbox.
//!
//! A recipient is trusted when this store holds an active encryption key for
//! them and the letter is sealed to it ([`keys::is_active_key`]), checked
//! when the letter is queued and again before it is sent, so revoking the
//! recipient's key stops a queued send. A tracked-file letter must also come
//! in its exchange's order (request, answer, file, receipt, snapshot): the
//! owner names their copy of the file and [`exchange::require_step`] reads
//! that copy's history.
//!
//! This module owns `outbox_rings` and `outbox_slots` and decides no other
//! rule: keys are `keys`, framing is `envelope`, the exchange order is
//! `file_delivery::exchange`.

use crate::envelope;
use crate::error::{Error, Result};
use crate::file_delivery::exchange::{self, Step};
use crate::file_history::TrackedFile;
use crate::keys::{self, KeyType};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

/// Slots a new ring gets.
pub const DEFAULT_CAPACITY: u32 = 32;
/// Largest ring a person may configure (the schema enforces it too).
pub const MAX_CAPACITY: u32 = 1024;
/// Largest single item, so a ring's footprint in the store stays bounded.
pub const MAX_ITEM_BYTES: usize = 16 * 1024 * 1024;

/// How the ring can be used right now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingState {
    /// Nothing is held: there is nothing to send.
    Empty,
    /// Some slots are held and some are free: items can be added and sent.
    Partial,
    /// Every slot is held: nothing can be added until an item is sent.
    Full,
}

impl RingState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Partial => "partial",
            Self::Full => "full",
        }
    }
}

/// One person's ring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ring {
    pub owner: String,
    pub capacity: u32,
    /// The slot the next send reads.
    pub read_index: u32,
    /// The slot the next item is written to.
    pub write_index: u32,
    /// Slots held: queued and not yet sent.
    pub size: u32,
    /// Items sent from this ring, ever.
    pub sent_total: u64,
}

impl Ring {
    pub fn state(&self) -> RingState {
        if self.size == 0 {
            RingState::Empty
        } else if self.size >= self.capacity {
            RingState::Full
        } else {
            RingState::Partial
        }
    }

    /// Slots still free for new items.
    pub fn free(&self) -> u32 {
        self.capacity - self.size
    }

    fn unused(owner: &str) -> Self {
        Self {
            owner: owner.to_string(),
            capacity: DEFAULT_CAPACITY,
            read_index: 0,
            write_index: 0,
            size: 0,
            sent_total: 0,
        }
    }
}

/// A held slot, without its content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedItem {
    /// Which slot of the ring holds it.
    pub index: u32,
    /// The letter's kind byte, from its outer header.
    pub kind: u8,
    pub recipient: String,
    pub content_hash: String,
    pub len: usize,
    pub queued_at: String,
}

/// The ring for `owner`. A person who has never queued anything has an
/// empty ring of [`DEFAULT_CAPACITY`]; nothing is written until they do.
pub fn ring(conn: &Connection, owner: &str) -> Result<Ring> {
    Ok(load_ring(conn, owner)?.unwrap_or_else(|| Ring::unused(owner)))
}

fn load_ring(conn: &Connection, owner: &str) -> Result<Option<Ring>> {
    conn.query_row(
        "SELECT capacity, read_index, write_index, size, sent_total
         FROM outbox_rings WHERE owner_label = ?1",
        params![owner],
        |row| {
            Ok(Ring {
                owner: owner.to_string(),
                capacity: row.get(0)?,
                read_index: row.get(1)?,
                write_index: row.get(2)?,
                size: row.get(3)?,
                sent_total: row.get::<_, i64>(4)? as u64,
            })
        },
    )
    .optional()
    .map_err(Error::from)
}

fn ensure_ring(conn: &Connection, owner: &str) -> Result<Ring> {
    conn.execute(
        "INSERT OR IGNORE INTO outbox_rings (owner_label, capacity) VALUES (?1, ?2)",
        params![owner, DEFAULT_CAPACITY],
    )?;
    load_ring(conn, owner)?.ok_or(Error::IntegrityCheckFailed)
}

/// The owner must be a person this store knows: one with an active key.
fn require_owner(conn: &Connection, owner: &str) -> Result<()> {
    let known = !keys::active_keys_for(conn, owner, KeyType::Encryption)?.is_empty()
        || !keys::active_keys_for(conn, owner, KeyType::Signing)?.is_empty();
    if known {
        Ok(())
    } else {
        Err(Error::NodeNotFound)
    }
}

/// The letter's kind and the key it is sealed to, from its outer header.
/// Anything that is not a whole `KQPB` letter, or is a device letter, is
/// refused.
fn passport(bytes: &[u8]) -> Result<(u8, [u8; 32])> {
    let (kind, sealed_to, _) =
        envelope::parse_outer(bytes).map_err(|_| Error::OutboxItemRefused)?;
    if envelope::is_device_workflow_kind(kind) {
        return Err(Error::OutboxItemRefused);
    }
    Ok((kind, sealed_to))
}

/// The recipient is trusted for this letter: it is sealed to an active
/// encryption key this store holds for them.
fn require_trusted(conn: &Connection, recipient: &str, sealed_to: &[u8; 32]) -> Result<()> {
    if keys::is_active_key(conn, recipient, KeyType::Encryption, sealed_to)? {
        Ok(())
    } else {
        Err(Error::UntrustedRecipient)
    }
}

/// Change the number of slots. Only an empty ring can be resized, so no
/// held item is moved or lost.
pub fn set_capacity(conn: &Connection, owner: &str, capacity: u32) -> Result<Ring> {
    if capacity == 0 || capacity > MAX_CAPACITY {
        return Err(Error::InvalidSlot);
    }
    require_owner(conn, owner)?;
    crate::db::with_immediate_transaction(conn, || {
        let ring = ensure_ring(conn, owner)?;
        if ring.state() != RingState::Empty {
            return Err(Error::OutboxNotEmpty);
        }
        conn.execute(
            "UPDATE outbox_rings SET capacity = ?1, read_index = 0, write_index = 0
             WHERE owner_label = ?2",
            params![capacity, owner],
        )?;
        load_ring(conn, owner)?.ok_or(Error::IntegrityCheckFailed)
    })
}

/// Queue the letter `bytes` for `recipient` at the write pointer. Refused
/// when the ring is full, the file is not a person-to-person `KQPB`, the
/// recipient is not trusted for it, or, for a tracked-file letter, when
/// `copy` (the owner's copy of the file) does not show the step before it.
pub fn push(
    conn: &Connection,
    owner: &str,
    recipient: &str,
    bytes: &[u8],
    copy: Option<&TrackedFile>,
) -> Result<QueuedItem> {
    if bytes.len() > MAX_ITEM_BYTES {
        return Err(Error::BundleFieldTooLarge);
    }
    let (kind, sealed_to) = passport(bytes)?;
    require_owner(conn, owner)?;
    require_trusted(conn, recipient, &sealed_to)?;
    match (Step::for_kind(kind), copy) {
        (None | Some(Step::Request), _) => {}
        (Some(step), Some(copy)) => exchange::require_step(copy, owner, recipient, step)?,
        (Some(step), None) => {
            return Err(Error::ExchangeOutOfOrder(format!(
                "a {} needs your copy of the file it concerns, so its order can be checked",
                step.name()
            )))
        }
    }
    crate::db::with_immediate_transaction(conn, || {
        let ring = ensure_ring(conn, owner)?;
        if ring.state() == RingState::Full {
            return Err(Error::OutboxFull);
        }
        let index = ring.write_index;
        let content_hash = hex::encode(Sha256::digest(bytes));
        conn.execute(
            "INSERT INTO outbox_slots
             (owner_label, slot_index, envelope_kind, recipient_label, content, content_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![owner, index, kind, recipient, bytes, content_hash],
        )?;
        conn.execute(
            "UPDATE outbox_rings
             SET write_index = (write_index + 1) % capacity, size = size + 1
             WHERE owner_label = ?1",
            params![owner],
        )?;
        item_at(conn, owner, index)?.ok_or(Error::IntegrityCheckFailed)
    })
}

fn item_at(conn: &Connection, owner: &str, index: u32) -> Result<Option<QueuedItem>> {
    let row: Option<(u32, u8, String, String, i64, String)> = conn
        .query_row(
            "SELECT slot_index, envelope_kind, recipient_label, content_hash, length(content), queued_at
             FROM outbox_slots WHERE owner_label = ?1 AND slot_index = ?2",
            params![owner, index],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    row.map(|(index, kind, recipient, content_hash, len, queued_at)| {
        Ok(QueuedItem {
            index,
            kind,
            recipient,
            content_hash,
            len: usize::try_from(len).map_err(|_| Error::IntegrityCheckFailed)?,
            queued_at,
        })
    })
    .transpose()
}

/// Every held item, in the order sends will take them (oldest first). Moves
/// no pointer.
pub fn list(conn: &Connection, owner: &str) -> Result<Vec<QueuedItem>> {
    let ring = ring(conn, owner)?;
    let mut items = Vec::with_capacity(ring.size as usize);
    for offset in 0..ring.size {
        let index = (ring.read_index + offset) % ring.capacity;
        items.push(item_at(conn, owner, index)?.ok_or(Error::IntegrityCheckFailed)?);
    }
    Ok(items)
}

/// Wipe and free the slot at the read pointer, then move the pointer on.
fn release_head(conn: &Connection, owner: &str, ring: &Ring, sent: bool) -> Result<()> {
    // Overwrite before deleting, with secure_delete on, so the sealed
    // bytes do not linger in the freed page.
    conn.pragma_update(None, "secure_delete", true)?;
    conn.execute(
        "UPDATE outbox_slots SET content = zeroblob(length(content))
         WHERE owner_label = ?1 AND slot_index = ?2",
        params![owner, ring.read_index],
    )?;
    conn.execute(
        "DELETE FROM outbox_slots WHERE owner_label = ?1 AND slot_index = ?2",
        params![owner, ring.read_index],
    )?;
    conn.execute(
        "UPDATE outbox_rings
         SET read_index = (read_index + 1) % capacity, size = size - 1,
             sent_total = sent_total + ?2
         WHERE owner_label = ?1",
        params![owner, i64::from(sent)],
    )?;
    Ok(())
}

/// Send the item at the read pointer: re-check that its recipient is still
/// trusted for it, hand it to `deliver`, and only when `deliver` succeeds
/// free the slot and move the read pointer. A refused or failed send moves
/// nothing, so order is kept and nothing is lost. `None` when the ring is
/// empty. The ring stays locked for the whole send, so two sends from the
/// same store never take the same item.
pub fn send_next(
    conn: &Connection,
    owner: &str,
    deliver: impl FnOnce(&QueuedItem, &[u8]) -> Result<()>,
) -> Result<Option<QueuedItem>> {
    crate::db::with_immediate_transaction(conn, || {
        let ring = ring(conn, owner)?;
        if ring.state() == RingState::Empty {
            return Ok(None);
        }
        let item = item_at(conn, owner, ring.read_index)?.ok_or(Error::IntegrityCheckFailed)?;
        let bytes: zeroize::Zeroizing<Vec<u8>> = zeroize::Zeroizing::new(conn.query_row(
            "SELECT content FROM outbox_slots WHERE owner_label = ?1 AND slot_index = ?2",
            params![owner, ring.read_index],
            |row| row.get(0),
        )?);
        if hex::encode(Sha256::digest(&*bytes)) != item.content_hash {
            return Err(Error::IntegrityCheckFailed);
        }
        let (_, sealed_to) = passport(&bytes)?;
        require_trusted(conn, &item.recipient, &sealed_to)?;
        deliver(&item, &bytes)?;
        release_head(conn, owner, &ring, true)?;
        Ok(Some(item))
    })
}

/// Discard the item at the read pointer without sending it (the owner's
/// call, for an item whose recipient is no longer trusted). Wiped like a
/// sent slot, but not counted as sent.
pub fn drop_next(conn: &Connection, owner: &str) -> Result<Option<QueuedItem>> {
    crate::db::with_immediate_transaction(conn, || {
        let ring = ring(conn, owner)?;
        if ring.state() == RingState::Empty {
            return Ok(None);
        }
        let item = item_at(conn, owner, ring.read_index)?.ok_or(Error::IntegrityCheckFailed)?;
        release_head(conn, owner, &ring, false)?;
        Ok(Some(item))
    })
}

#[cfg(test)]
#[path = "outbox/tests.rs"]
mod tests;
