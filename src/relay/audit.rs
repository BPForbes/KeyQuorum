//! Tamper evidence for the relay's audit tables (`api_key_events`,
//! `provider_auth_events`).
//!
//! Every row carries `prev_hash` and `entry_hash`: a SHA-256 chain over the
//! row's own fields and the row before it, so editing, reordering or
//! deleting a row breaks every hash after it. A chain alone does not stop
//! someone who can write the database from rebuilding it, so the relay also
//! signs the chain head into `audit_anchors` with its relay key, alongside
//! the KeyQuorum-signed certificate that names that key.
//!
//! Only the holder of a trusted relay key can author an anchor, and only
//! for the period its certificate covers: [`verify`] accepts an anchor when
//! the certificate chains to the provider root, is not revoked, and was
//! valid (`issued_at` to `expires_at`) at the anchor's `signed_at`. Rows
//! after the newest accepted anchor are reported as pending, not trusted.
//!
//! An anchor's `signed_at` is the signer's own word, so it alone cannot
//! stop someone who holds a relay key after its certificate expired (and
//! can write the database) from rebuilding the chain and signing a new
//! anchor dated inside the old validity window. A [`Checkpoint`] closes
//! that: every table's row count and head, signed when it is taken and
//! kept by the operator off the relay (write-once storage they control).
//! Given one, [`verify`] requires the chain to still reach that head at that
//! row, and refuses any anchor that covers rows past the checkpoint yet
//! claims a `signed_at` before it was taken. A key expired by then can no
//! longer vouch for anything, so only the time since the newest checkpoint
//! is left to a key's own word, and the operator decides how short that is.
//! Nothing here records or signs a bearer, a key hash or a challenge.

use super::service::ProviderIdentity;
use crate::envelope::hash_len_prefixed;
use crate::error::{Error, Result};
use crate::provider::{self, Certificate};
use crate::signing;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

const ENTRY_DOMAIN: &[u8] = b"KQ-RELAY-AUDIT-ENTRY-v1";
pub(crate) const GENESIS: [u8; 32] = [0u8; 32];
const CHECKPOINT_FORMAT: &str = "KQ-RELAY-AUDIT-CHECKPOINT-v1";

/// An audit table this module chains and anchors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditTable {
    ApiKeyEvents,
    ProviderAuthEvents,
}

impl AuditTable {
    pub const ALL: [AuditTable; 2] = [AuditTable::ApiKeyEvents, AuditTable::ProviderAuthEvents];

    pub fn name(self) -> &'static str {
        match self {
            Self::ApiKeyEvents => "api_key_events",
            Self::ProviderAuthEvents => "provider_auth_events",
        }
    }

    /// Every recorded column, as text (NULL stays NULL), in a fixed order.
    fn fields_sql(self) -> &'static str {
        match self {
            Self::ApiKeyEvents => {
                "SELECT id, CAST(api_key_id AS TEXT), event, actor,
                        CAST(related_key_id AS TEXT), occurred_at, prev_hash, entry_hash
                 FROM api_key_events"
            }
            Self::ProviderAuthEvents => {
                "SELECT id, operation, provider_id, network_id, hardware_fingerprints,
                        CAST(success AS TEXT), attempted_at, prev_hash, entry_hash
                 FROM provider_auth_events"
            }
        }
    }

    fn field_count(self) -> usize {
        match self {
            Self::ApiKeyEvents => 5,
            Self::ProviderAuthEvents => 6,
        }
    }
}

/// One audit row as the chain sees it: its id, its recorded fields in the
/// table's fixed order (see [`AuditTable::fields_sql`]), and the two hashes.
/// Every backend reads its rows into this shape; the chain arithmetic below
/// never touches a database.
pub(crate) struct Row {
    pub id: i64,
    pub fields: Vec<Option<String>>,
    pub prev_hash: Option<String>,
    pub entry_hash: Option<String>,
}

/// One relay-key anchor as stored: the row count and head it vouches for,
/// when, under which certificate, and the signature.
pub(crate) struct AnchorRow {
    pub row_count: i64,
    pub head_hash: String,
    pub signed_at: String,
    pub certificate: Vec<u8>,
    pub signature: Vec<u8>,
}

fn read_rows(conn: &Connection, table: AuditTable, filter: &str) -> Result<Vec<Row>> {
    let n = table.field_count();
    let sql = format!("{} {filter} ORDER BY id", table.fields_sql());
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map([], |row| {
        let mut fields = Vec::with_capacity(n);
        for i in 0..n {
            fields.push(row.get::<_, Option<String>>(i + 1)?);
        }
        Ok(Row {
            id: row.get(0)?,
            fields,
            prev_hash: row.get(n + 1)?,
            entry_hash: row.get(n + 2)?,
        })
    })?;
    rows.collect::<rusqlite::Result<_>>().map_err(Error::from)
}

/// The chain hash of one row: domain, table, the previous row's hash, then
/// each field tagged present (`1 || len || bytes`) or absent (`0`), so a
/// NULL can never collide with an empty string.
pub(crate) fn entry_hash(
    table: AuditTable,
    prev: &[u8; 32],
    fields: &[Option<String>],
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(ENTRY_DOMAIN);
    hash_len_prefixed(&mut hasher, table.name().as_bytes())?;
    hasher.update(prev);
    for field in fields {
        match field {
            Some(value) => {
                hasher.update([1u8]);
                hash_len_prefixed(&mut hasher, value.as_bytes())?;
            }
            None => hasher.update([0u8]),
        }
    }
    Ok(hasher.finalize().into())
}

pub(crate) fn decode_hash(hex_hash: &str) -> Option<[u8; 32]> {
    hex::decode(hex_hash).ok()?.try_into().ok()
}

/// Chain the row `id` onto the row before it. Called in the same
/// transaction as the insert, so a row is never left unchained.
pub(crate) fn seal_row(conn: &Connection, table: AuditTable, id: i64) -> Result<()> {
    let prev: Option<Option<String>> = conn
        .query_row(
            &format!(
                "SELECT entry_hash FROM {} WHERE id < ?1 ORDER BY id DESC LIMIT 1",
                table.name()
            ),
            params![id],
            |row| row.get(0),
        )
        .optional()?;
    let prev = match prev {
        None => GENESIS,
        Some(hash) => hash
            .as_deref()
            .and_then(decode_hash)
            .ok_or(Error::IntegrityCheckFailed)?,
    };
    let row = read_rows(conn, table, &format!("WHERE id = {id}"))?
        .pop()
        .ok_or(Error::IntegrityCheckFailed)?;
    let hash = entry_hash(table, &prev, &row.fields)?;
    conn.execute(
        &format!(
            "UPDATE {} SET prev_hash = ?1, entry_hash = ?2 WHERE id = ?3",
            table.name()
        ),
        params![hex::encode(prev), hex::encode(hash), id],
    )?;
    Ok(())
}

/// Chain rows written before the chain existed, oldest first. Run by the
/// schema migration; those rows are vouched for only from the first anchor
/// signed after it.
pub(crate) fn backfill(conn: &Connection) -> Result<()> {
    for table in AuditTable::ALL {
        let exists: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![table.name()],
            |row| row.get(0),
        )?;
        if exists == 0 {
            continue;
        }
        let ids: Vec<i64> = read_rows(conn, table, "WHERE entry_hash IS NULL")?
            .into_iter()
            .map(|row| row.id)
            .collect();
        for id in ids {
            seal_row(conn, table, id)?;
        }
    }
    Ok(())
}

fn head(conn: &Connection, table: AuditTable) -> Result<Option<(u64, [u8; 32])>> {
    let row: Option<(i64, Option<String>)> = conn
        .query_row(
            &format!(
                "SELECT (SELECT COUNT(*) FROM {t}), entry_hash FROM {t} ORDER BY id DESC LIMIT 1",
                t = table.name()
            ),
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    match row {
        None => Ok(None),
        Some((count, hash)) => {
            let hash = hash
                .as_deref()
                .and_then(decode_hash)
                .ok_or(Error::IntegrityCheckFailed)?;
            Ok(Some((count as u64, hash)))
        }
    }
}

/// Sign each table's current chain head with the relay key, unless the
/// newest anchor already covers it. Returns how many anchors were written.
pub fn anchor(conn: &Connection, identity: &ProviderIdentity, signed_at: &str) -> Result<usize> {
    crate::db::with_immediate_transaction(conn, || {
        let mut written = 0;
        for table in AuditTable::ALL {
            let Some((count, head_hash)) = head(conn, table)? else {
                continue;
            };
            let covered: Option<i64> = conn
                .query_row(
                    "SELECT row_count FROM audit_anchors WHERE table_name = ?1
                     ORDER BY id DESC LIMIT 1",
                    params![table.name()],
                    |row| row.get(0),
                )
                .optional()?;
            if covered == Some(count as i64) {
                continue;
            }
            let signature = sign_anchor(identity, table, count, &head_hash, signed_at)?;
            conn.execute(
                "INSERT INTO audit_anchors
                 (table_name, row_count, head_hash, signed_at, certificate, signature)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    table.name(),
                    count as i64,
                    hex::encode(head_hash),
                    signed_at,
                    identity.certificate,
                    signature.to_vec()
                ],
            )?;
            written += 1;
        }
        Ok(written)
    })
}

/// The relay key's signature over an anchor for `table` at `count` rows
/// with head `head_hash`, dated `signed_at`.
pub(crate) fn sign_anchor(
    identity: &ProviderIdentity,
    table: AuditTable,
    count: u64,
    head_hash: &[u8; 32],
    signed_at: &str,
) -> Result<[u8; 64]> {
    let preimage = signing::relay_audit_anchor_preimage(
        table.name(),
        count,
        head_hash,
        signed_at,
        &identity.certificate,
    )?;
    Ok(signing::sign(&identity.relay_private_key, &preimage))
}

/// One table's place in a [`Checkpoint`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointHead {
    pub table: String,
    pub row_count: u64,
    /// Hex chain head at `row_count` (all zeros for an empty table).
    pub head_hash: String,
}

/// Every audit table's row count and chain head at `taken_at`, signed by
/// the relay key. Its strength is where it is kept: off the relay, where
/// whoever can write the relay database cannot rewrite it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub format: String,
    pub taken_at: String,
    pub heads: Vec<CheckpointHead>,
    /// Hex `provider.kqcert` naming the signing key.
    pub certificate: String,
    /// Hex Ed25519 signature over [`signing::relay_audit_checkpoint_preimage`].
    pub signature: String,
}

impl Checkpoint {
    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(|_| Error::IntegrityCheckFailed)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let checkpoint: Self =
            serde_json::from_slice(bytes).map_err(|_| Error::IntegrityCheckFailed)?;
        if checkpoint.format != CHECKPOINT_FORMAT {
            return Err(Error::IntegrityCheckFailed);
        }
        Ok(checkpoint)
    }

    fn heads(&self) -> Result<Vec<(&str, u64, [u8; 32])>> {
        self.heads
            .iter()
            .map(|h| {
                let hash = decode_hash(&h.head_hash).ok_or(Error::IntegrityCheckFailed)?;
                Ok((h.table.as_str(), h.row_count, hash))
            })
            .collect()
    }

    /// The row count and head this checkpoint holds for `table`; an empty
    /// table, or one it does not name, is at row 0.
    fn head_for(&self, table: AuditTable) -> Result<(u64, [u8; 32])> {
        Ok(self
            .heads()?
            .into_iter()
            .find(|(name, _, _)| *name == table.name())
            .map_or((0, GENESIS), |(_, count, hash)| (count, hash)))
    }

    /// Signed by a relay key whose certificate chains to the root, is not
    /// revoked and was valid when the checkpoint was taken. Only a yes or a
    /// no comes out: nothing read from the certificate leaves this check.
    pub(crate) fn is_signed_by_trusted_relay(
        &self,
        root_public_key: &[u8; 32],
        revoked: &HashSet<String>,
    ) -> bool {
        let checked = || -> Option<()> {
            let certificate = hex::decode(&self.certificate).ok()?;
            let cert =
                certificate_at(root_public_key, &certificate, &self.taken_at, revoked).ok()?;
            let signature: [u8; 64] = hex::decode(&self.signature).ok()?.try_into().ok()?;
            let preimage = signing::relay_audit_checkpoint_preimage(
                &self.heads().ok()?,
                &self.taken_at,
                &certificate,
            )
            .ok()?;
            signing::verify_signature(&cert.relay_public_key, &preimage, &signature).ok()
        };
        checked().is_some()
    }
}

/// Take a [`Checkpoint`] of every audit table now (`taken_at`), signed with
/// the relay key, for the operator to store off the relay.
pub fn checkpoint(
    conn: &Connection,
    identity: &ProviderIdentity,
    taken_at: &str,
) -> Result<Checkpoint> {
    let mut heads = Vec::new();
    for table in AuditTable::ALL {
        let (count, hash) = head(conn, table)?.unwrap_or((0, GENESIS));
        heads.push((table.name(), count, hash));
    }
    sign_checkpoint(&heads, identity, taken_at)
}

/// A [`Checkpoint`] over the given heads (one per table, an empty table at
/// row 0 with the genesis hash), signed with the relay key.
pub(crate) fn sign_checkpoint(
    heads: &[(&str, u64, [u8; 32])],
    identity: &ProviderIdentity,
    taken_at: &str,
) -> Result<Checkpoint> {
    let heads = heads.to_vec();
    let preimage =
        signing::relay_audit_checkpoint_preimage(&heads, taken_at, &identity.certificate)?;
    let signature = signing::sign(&identity.relay_private_key, &preimage);
    Ok(Checkpoint {
        format: CHECKPOINT_FORMAT.to_string(),
        taken_at: taken_at.to_string(),
        heads: heads
            .into_iter()
            .map(|(table, row_count, hash)| CheckpointHead {
                table: table.to_string(),
                row_count,
                head_hash: hex::encode(hash),
            })
            .collect(),
        certificate: hex::encode(&identity.certificate),
        signature: hex::encode(signature),
    })
}

/// How a table stood against the checkpoint [`verify`] was given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointReport {
    pub row_count: u64,
    pub taken_at: String,
    /// The chain still reaches the checkpoint's head at its row. When it
    /// does not, the rows the checkpoint covered were rewritten.
    pub matches: bool,
}

/// The newest anchor [`verify`] accepted for a table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedAnchor {
    pub row_count: u64,
    pub signed_at: String,
    pub provider_id: String,
    pub serial: String,
}

/// What [`verify`] found for one table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableReport {
    pub table: &'static str,
    pub rows: u64,
    /// The first row whose chain does not hold; every row from it on is
    /// unverifiable.
    pub broken_at: Option<i64>,
    pub trusted: Option<TrustedAnchor>,
    /// Anchors that failed: bad signature, a certificate that was not valid
    /// when it was signed, a head that does not match the chain, or (given a
    /// checkpoint) rows past the checkpoint vouched for by an anchor dated
    /// before it.
    pub rejected_anchors: u64,
    /// Present when [`verify`] was given a checkpoint.
    pub checkpoint: Option<CheckpointReport>,
}

impl TableReport {
    /// Rows the newest accepted anchor, or a matching checkpoint, vouches
    /// for.
    pub fn anchored_rows(&self) -> u64 {
        let anchored = self.trusted.as_ref().map_or(0, |a| a.row_count);
        let checkpointed = self
            .checkpoint
            .as_ref()
            .filter(|c| c.matches)
            .map_or(0, |c| c.row_count);
        anchored.max(checkpointed)
    }

    /// Rows written since the newest accepted anchor.
    pub fn pending_rows(&self) -> u64 {
        self.rows.saturating_sub(self.anchored_rows())
    }

    /// The chain holds, no anchor was refused, and the chain still matches
    /// the checkpoint, if one was given.
    pub fn is_intact(&self) -> bool {
        self.broken_at.is_none()
            && self.rejected_anchors == 0
            && self.checkpoint.as_ref().is_none_or(|c| c.matches)
    }
}

/// A certificate the relay key was trusted under at `signed_at`.
fn certificate_at(
    root_public_key: &[u8; 32],
    certificate: &[u8],
    signed_at: &str,
    revoked: &HashSet<String>,
) -> Result<Certificate> {
    let cert = provider::verify_certificate(root_public_key, certificate, signed_at, revoked)?;
    if signed_at < cert.issued_at.as_str() {
        return Err(Error::InvalidProviderCertificate);
    }
    Ok(cert)
}

/// Re-walk every chain and check every anchor against the provider root,
/// and, given the operator's off-relay `checkpoint`, check the chain against
/// it and refuse anchors that predate it but cover rows past it. A
/// checkpoint that does not verify is an error, never ignored.
pub fn verify(
    conn: &Connection,
    root_public_key: &[u8; 32],
    revoked: &HashSet<String>,
    checkpoint: Option<&Checkpoint>,
) -> Result<Vec<TableReport>> {
    if checkpoint.is_some_and(|c| !c.is_signed_by_trusted_relay(root_public_key, revoked)) {
        return Err(Error::IntegrityCheckFailed);
    }
    let mut reports = Vec::new();
    for table in AuditTable::ALL {
        let rows = read_rows(conn, table, "")?;
        let mut stmt = conn.prepare(
            "SELECT row_count, head_hash, signed_at, certificate, signature
             FROM audit_anchors WHERE table_name = ?1 ORDER BY id",
        )?;
        let anchors = stmt
            .query_map(params![table.name()], |row| {
                Ok(AnchorRow {
                    row_count: row.get(0)?,
                    head_hash: row.get(1)?,
                    signed_at: row.get(2)?,
                    certificate: row.get(3)?,
                    signature: row.get(4)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        reports.push(verify_table(
            table,
            &rows,
            &anchors,
            root_public_key,
            revoked,
            checkpoint,
        )?);
    }
    Ok(reports)
}

/// Re-walk one table's chain and judge its anchors; the checkpoint, if
/// given, has already been checked to be signed by a trusted relay key.
pub(crate) fn verify_table(
    table: AuditTable,
    rows: &[Row],
    anchors: &[AnchorRow],
    root_public_key: &[u8; 32],
    revoked: &HashSet<String>,
    checkpoint: Option<&Checkpoint>,
) -> Result<TableReport> {
    {
        let mut heads = vec![GENESIS];
        let mut broken_at = None;
        for row in rows {
            let prev = *heads.last().expect("starts with genesis");
            let recorded_prev = row.prev_hash.as_deref().and_then(decode_hash);
            let recorded = row.entry_hash.as_deref().and_then(decode_hash);
            let expected = entry_hash(table, &prev, &row.fields)?;
            if recorded_prev != Some(prev) || recorded != Some(expected) {
                broken_at = Some(row.id);
                break;
            }
            heads.push(expected);
        }

        let checkpointed = checkpoint
            .map(|c| c.head_for(table).map(|head| (c, head)))
            .transpose()?;
        let checkpoint_report = checkpointed.map(|(c, (count, head_hash))| CheckpointReport {
            row_count: count,
            taken_at: c.taken_at.clone(),
            matches: usize::try_from(count)
                .ok()
                .and_then(|count| heads.get(count))
                == Some(&head_hash),
        });

        let mut trusted: Option<TrustedAnchor> = None;
        let mut rejected_anchors = 0;
        for anchor in anchors {
            let AnchorRow {
                row_count: count,
                head_hash: head_hex,
                signed_at,
                certificate,
                signature,
            } = anchor;
            let accepted = (|| -> Option<TrustedAnchor> {
                let count = u64::try_from(*count).ok()?;
                let head_hash = decode_hash(head_hex)?;
                if heads.get(usize::try_from(count).ok()?) != Some(&head_hash) {
                    return None;
                }
                // Rows past the checkpoint did not exist when it was taken,
                // so an anchor over them dated earlier was backdated.
                if let Some((c, (checkpoint_rows, _))) = &checkpointed {
                    if count > *checkpoint_rows && signed_at.as_str() < c.taken_at.as_str() {
                        return None;
                    }
                }
                let cert = certificate_at(root_public_key, certificate, signed_at, revoked).ok()?;
                let signature: [u8; 64] = signature.as_slice().try_into().ok()?;
                let preimage = signing::relay_audit_anchor_preimage(
                    table.name(),
                    count,
                    &head_hash,
                    signed_at,
                    certificate,
                )
                .ok()?;
                signing::verify_signature(&cert.relay_public_key, &preimage, &signature).ok()?;
                Some(TrustedAnchor {
                    row_count: count,
                    signed_at: signed_at.clone(),
                    provider_id: cert.provider_id,
                    serial: cert.serial,
                })
            })();
            match accepted {
                Some(anchor) => {
                    if trusted
                        .as_ref()
                        .is_none_or(|best| anchor.row_count >= best.row_count)
                    {
                        trusted = Some(anchor);
                    }
                }
                None => rejected_anchors += 1,
            }
        }
        Ok(TableReport {
            table: table.name(),
            rows: rows.len() as u64,
            broken_at,
            trusted,
            rejected_anchors,
            checkpoint: checkpoint_report,
        })
    }
}

#[cfg(test)]
#[path = "audit/tests.rs"]
mod tests;
