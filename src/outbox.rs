//! Each person's outbox: a fixed-capacity ring buffer of the sealed letters
//! (`KQPB`) they have queued for other people, kept in their own store. It is
//! the default way out: `keyquorum send` queues every letter it makes here and
//! sends from the ring (`outbox add` queues one made elsewhere). The pointer
//! arithmetic is `ring`'s, shared with the inbox ring.
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
//! that copy's history. The ring cannot open the letter, so that confirms the
//! step before it exists in the named copy with that recipient, not that the
//! letter belongs to that copy or request; the receiver binds those when it
//! opens the letter.
//!
//! In border terms: the `KQPB` is the passport; the destination printed on
//! it is the recipient key it is sealed to, which must be one this store
//! recognises; an accepted request answer is the visa a tracked file needs;
//! device letters are residence papers that never cross. A letter turned
//! away at departure is recorded in `outbox_refusals` ([`Refusal`],
//! [`refusals`]): who it was for, its kind and step, and the rule it broke,
//! never the letter. A delivery that fails in transit (the relay is down) is
//! not a refusal and leaves the letter queued.
//!
//! This module owns `outbox_rings`, `outbox_slots` and `outbox_refusals` and
//! decides no other rule: keys are `keys`, framing is `envelope`, the
//! exchange order is `file_delivery::exchange`.

use crate::envelope;
use crate::error::{Error, Result};
use crate::file_delivery::exchange::{self, Step, Visa};
use crate::file_history::TrackedFile;
use crate::keys::{self, KeyType};
use crate::ring;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

/// Slots a new ring gets.
pub const DEFAULT_CAPACITY: u32 = 32;
/// Largest ring a person may configure (the schema enforces it too).
pub const MAX_CAPACITY: u32 = 1024;
/// Largest single item, so a ring's footprint in the store stays bounded.
pub const MAX_ITEM_BYTES: usize = 16 * 1024 * 1024;
/// Refusals kept per owner; older ones are dropped as new ones arrive.
pub const MAX_REFUSALS_KEPT: u32 = 256;

/// Why the ring turned a letter away at departure. Stored by name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Not a whole `KQPB` letter: no passport.
    NoPassport,
    /// A device letter: residence papers that never leave your own devices.
    DeviceLetter,
    /// Not sealed to an active key this store holds for the recipient.
    UnrecognisedDestination,
    /// A tracked-file letter whose step before it is missing.
    OutOfOrder,
    /// Every slot is held by a letter not yet sent.
    RingFull,
    /// Larger than [`MAX_ITEM_BYTES`].
    Oversized,
    /// The held letter no longer matches what was queued.
    Tampered,
}

impl Refusal {
    pub const ALL: [Refusal; 7] = [
        Refusal::NoPassport,
        Refusal::DeviceLetter,
        Refusal::UnrecognisedDestination,
        Refusal::OutOfOrder,
        Refusal::RingFull,
        Refusal::Oversized,
        Refusal::Tampered,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoPassport => "no_passport",
            Self::DeviceLetter => "device_letter",
            Self::UnrecognisedDestination => "unrecognised_destination",
            Self::OutOfOrder => "out_of_order",
            Self::RingFull => "ring_full",
            Self::Oversized => "oversized",
            Self::Tampered => "tampered",
        }
    }

    fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == name)
    }

    /// The error a caller sees for this refusal.
    fn error(self, step: Option<&str>) -> Error {
        match self {
            Self::NoPassport | Self::DeviceLetter => Error::OutboxItemRefused,
            Self::UnrecognisedDestination => Error::UntrustedRecipient,
            Self::OutOfOrder => Error::ExchangeOutOfOrder(step.unwrap_or_default().to_string()),
            Self::RingFull => Error::OutboxFull,
            Self::Oversized => Error::BundleFieldTooLarge,
            Self::Tampered => Error::IntegrityCheckFailed,
        }
    }
}

/// One letter the ring turned away. Holds nothing from the letter itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefusalRecord {
    pub recipient: String,
    /// The letter's kind byte, when it had a readable outer header.
    pub kind: Option<u8>,
    /// For a tracked-file letter refused out of order, what was missing.
    pub step: Option<String>,
    pub refusal: Refusal,
    pub refused_at: String,
}

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

/// The outbox ring's storage, for the shared ring arithmetic in `ring`.
const TABLE: ring::Table = ring::Table {
    rings: "outbox_rings",
    slots: "outbox_slots",
    key: "owner_label",
    content: Some("content"),
};

fn ensure_ring(conn: &Connection, owner: &str) -> Result<Ring> {
    ring::ensure(conn, &TABLE, owner, DEFAULT_CAPACITY)?;
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
fn passport(bytes: &[u8]) -> std::result::Result<(u8, [u8; 32]), Refusal> {
    let (kind, sealed_to, _) = envelope::parse_outer(bytes).map_err(|_| Refusal::NoPassport)?;
    if envelope::is_device_workflow_kind(kind) {
        return Err(Refusal::DeviceLetter);
    }
    Ok((kind, sealed_to))
}

/// The recipient is trusted for this letter: it is sealed to an active
/// encryption key this store holds for them.
fn is_trusted(conn: &Connection, recipient: &str, sealed_to: &[u8; 32]) -> Result<bool> {
    keys::is_active_key(conn, recipient, KeyType::Encryption, sealed_to)
}

/// A refusal: recorded for `owner`, then returned as the caller's error.
struct Denied {
    refusal: Refusal,
    kind: Option<u8>,
    step: Option<String>,
}

impl Denied {
    fn new(refusal: Refusal, kind: Option<u8>) -> Self {
        Self {
            refusal,
            kind,
            step: None,
        }
    }

    /// Record the refusal and give the error it stands for. Recording is
    /// best effort: a refusal is never turned into a different failure.
    fn record(self, conn: &Connection, owner: &str, recipient: &str) -> Error {
        let _ = record_refusal(conn, owner, recipient, &self);
        self.refusal.error(self.step.as_deref())
    }
}

fn record_refusal(conn: &Connection, owner: &str, recipient: &str, denied: &Denied) -> Result<()> {
    conn.execute(
        "INSERT INTO outbox_refusals (owner_label, recipient_label, envelope_kind, step, rule)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            owner,
            recipient,
            denied.kind,
            denied.step,
            denied.refusal.as_str()
        ],
    )?;
    conn.execute(
        "DELETE FROM outbox_refusals WHERE owner_label = ?1 AND id NOT IN
         (SELECT id FROM outbox_refusals WHERE owner_label = ?1 ORDER BY id DESC LIMIT ?2)",
        params![owner, MAX_REFUSALS_KEPT],
    )?;
    Ok(())
}

/// The letters `owner`'s ring turned away, newest first, at most `limit`.
pub fn refusals(conn: &Connection, owner: &str, limit: u32) -> Result<Vec<RefusalRecord>> {
    let mut stmt = conn.prepare(
        "SELECT recipient_label, envelope_kind, step, rule, refused_at
         FROM outbox_refusals WHERE owner_label = ?1 ORDER BY id DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![owner, limit], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<u8>>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
        ))
    })?;
    rows.map(|row| {
        let (recipient, kind, step, rule, refused_at) = row?;
        Ok(RefusalRecord {
            recipient,
            kind,
            step,
            refusal: Refusal::parse(&rule).ok_or(Error::IntegrityCheckFailed)?,
            refused_at,
        })
    })
    .collect()
}

/// Change the number of slots. Only an empty ring can be resized, so no
/// held item is moved or lost.
pub fn set_capacity(conn: &Connection, owner: &str, capacity: u32) -> Result<Ring> {
    if capacity == 0 || capacity > MAX_CAPACITY {
        return Err(Error::InvalidSlot);
    }
    require_owner(conn, owner)?;
    crate::db::with_immediate_transaction(conn, || {
        if !ring::resize(conn, &TABLE, owner, capacity)? {
            return Err(Error::OutboxNotEmpty);
        }
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
    copy: Option<(&TrackedFile, Visa)>,
) -> Result<QueuedItem> {
    // An owner this store does not know has no ring, and nothing to record.
    require_owner(conn, owner)?;
    match departure_check(conn, owner, recipient, bytes, copy)? {
        Ok(kind) => queue(conn, owner, recipient, bytes, kind).map_err(|err| match err {
            Error::OutboxFull => {
                Denied::new(Refusal::RingFull, Some(kind)).record(conn, owner, recipient)
            }
            other => other,
        }),
        Err(denied) => Err(denied.record(conn, owner, recipient)),
    }
}

/// Every check a letter meets before it may be queued, in border order:
/// size, passport, destination, then the visa (its exchange step). The
/// outer `Result` is a failure to check; the inner one is the verdict.
fn departure_check(
    conn: &Connection,
    owner: &str,
    recipient: &str,
    bytes: &[u8],
    copy: Option<(&TrackedFile, Visa)>,
) -> Result<std::result::Result<u8, Denied>> {
    if bytes.len() > MAX_ITEM_BYTES {
        return Ok(Err(Denied::new(Refusal::Oversized, None)));
    }
    let (kind, sealed_to) = match passport(bytes) {
        Ok(found) => found,
        Err(refusal) => {
            let kind = envelope::parse_outer(bytes).ok().map(|(kind, _, _)| kind);
            return Ok(Err(Denied::new(refusal, kind)));
        }
    };
    if !is_trusted(conn, recipient, &sealed_to)? {
        return Ok(Err(Denied::new(
            Refusal::UnrecognisedDestination,
            Some(kind),
        )));
    }
    let missing = match (Step::for_kind(kind), copy) {
        (None | Some(Step::Request), _) => None,
        (Some(step), Some((copy, visa))) => {
            match exchange::require_step(copy, owner, recipient, step, visa) {
                Ok(()) => None,
                Err(Error::ExchangeOutOfOrder(missing)) => Some(missing),
                Err(other) => return Err(other),
            }
        }
        (Some(step), None) => Some(format!(
            "a {} needs your copy of the file it concerns, so its order can be checked",
            step.name()
        )),
    };
    Ok(match missing {
        Some(missing) => Err(Denied {
            refusal: Refusal::OutOfOrder,
            kind: Some(kind),
            step: Some(missing),
        }),
        None => Ok(kind),
    })
}

/// Write a checked letter at the write pointer.
fn queue(
    conn: &Connection,
    owner: &str,
    recipient: &str,
    bytes: &[u8],
    kind: u8,
) -> Result<QueuedItem> {
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
        ring::advance_write(conn, &TABLE, owner)?;
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
fn release_head(conn: &Connection, owner: &str, head: &Ring, sent: bool) -> Result<()> {
    ring::release(conn, &TABLE, owner, head.read_index)?;
    if sent {
        conn.execute(
            "UPDATE outbox_rings SET sent_total = sent_total + 1 WHERE owner_label = ?1",
            params![owner],
        )?;
    }
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
    // A refusal is recorded after the transaction, which rolls back.
    let mut denied: Option<(String, Denied)> = None;
    let sent = crate::db::with_immediate_transaction(conn, || {
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
        // Checked again at the gate: the slot is what was queued, it is
        // still a passport, and its destination is still recognised.
        let verdict = if hex::encode(Sha256::digest(&*bytes)) != item.content_hash {
            Some(Refusal::Tampered)
        } else {
            match passport(&bytes) {
                Err(refusal) => Some(refusal),
                Ok((_, sealed_to)) if !is_trusted(conn, &item.recipient, &sealed_to)? => {
                    Some(Refusal::UnrecognisedDestination)
                }
                Ok(_) => None,
            }
        };
        if let Some(refusal) = verdict {
            let error = refusal.error(None);
            denied = Some((
                item.recipient.clone(),
                Denied::new(refusal, Some(item.kind)),
            ));
            return Err(error);
        }
        deliver(&item, &bytes)?;
        release_head(conn, owner, &ring, true)?;
        Ok(Some(item))
    });
    match (sent, denied) {
        (Err(_), Some((recipient, denied))) => Err(denied.record(conn, owner, &recipient)),
        (sent, _) => sent,
    }
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
