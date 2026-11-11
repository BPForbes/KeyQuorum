//! Parent-key assembly (KQ-16, issue #161): a parent account's signing seed
//! split among its children, so that enough of them together can assemble it.
//!
//! ```text
//!        M.A  (accounting manager)   <- the seed, assembled from the shares below
//!        /  \
//!     M.A.1  M.A.2                   <- each holds one Shamir share, sealed to its own box key
//! ```
//!
//! This is the key tree's own move (a split's value comes from its children's
//! shares) and uses the same pieces: `blahaj`'s Shamir dealer and recovery, a
//! `crypto_box` seal to each holder, and `pss::require_distinct_nonzero_xs` for
//! the share coordinates. It needs no database: a caller with its own account
//! registry (an operating system's) passes the facts it holds, which is why the
//! custody rule here takes plain device ids instead of a store.
//!
//! What the module decides, and nothing else:
//!
//! * [`assembly_threshold`] fixes the threshold from the number of holders. It
//!   is a function, never a choice.
//! * [`split_parent_key`] deals a seed and seals one share per child.
//! * [`assemble_parent_key`] opens the shares of the children that are unlocked
//!   now, requires the threshold from enough distinct physical devices, recovers
//!   the seed and accepts it only if it derives the parent's signing public key
//!   the caller expects. The sealed shares are anonymous (anyone who knows a
//!   child's public key can seal one), so this check is what stops a planted
//!   share from producing a wrong key.
//! * [`reissue_assembly`] is the parent's answer to a revoked child: a new seed
//!   dealt at the next generation. Re-splitting the old seed would leave a
//!   revoked child's share valid, so the seed itself must change.
//!
//! The wire record is `KQAS` (its own magic and version; it is not a sealed
//! envelope, it only frames shares that are each sealed to a child). It uses
//! `envelope`'s length-prefixed codec. Quorum rules stay here and in
//! `key_tree`; the caller supplies keys and device ids and never re-derives them.

use crate::envelope::{
    is_weak_x25519_public_key, push_len_prefixed, take_array, take_len_prefixed, take_u32, take_u8,
    utf8,
};
use crate::error::{Error, Result};
use crate::pss;
use crate::signing;
use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use blahaj::{Share, Sharks};
use zeroize::Zeroizing;

/// Magic of an encoded [`Assembly`].
pub const ASSEMBLY_MAGIC: [u8; 4] = *b"KQAS";
/// Version of the encoding.
pub const ASSEMBLY_VERSION: u8 = 1;
/// Length of a device id (`device::DEVICE_ID_LEN`; this module is database-free).
pub const DEVICE_ID_LEN: usize = 16;
/// At most this many holders: share x-coordinates are `1..=255`.
pub const MAX_HOLDERS: usize = 255;
/// The longest label an assembly names (a key id is at most eight 31-byte segments).
pub const MAX_LABEL_LEN: usize = 255;

/// A share is its x-coordinate and the 32 bytes of the seed.
const RAW_SHARE_LEN: usize = 1 + 32;
/// `crypto_box` seal overhead over a raw share.
const SEALED_SHARE_LEN: usize = RAW_SHARE_LEN + crypto_box::SEALBYTES;

/// A child that will hold a share: its label and the X25519 public key the
/// share is sealed to.
#[derive(Clone, Copy, Debug)]
pub struct ChildHolder<'a> {
    pub label: &'a str,
    pub encryption_public: [u8; 32],
}

/// A share sealed to one child. Safe to store: only that child's key opens it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedShare {
    pub child_label: String,
    pub sealed: Vec<u8>,
}

/// A parent's seed split among its children.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assembly {
    pub threshold: u8,
    /// Starts at the caller's value and rises by exactly one at each reissue.
    pub generation: u32,
    pub shares: Vec<SealedShare>,
}

/// A child that is unlocked now: the X25519 secret that opens its share, and
/// the physical device it sits on (for the custody minimum).
pub struct UnlockedChild<'a> {
    pub label: &'a str,
    pub encryption_secret: &'a [u8; 32],
    pub device_id: [u8; DEVICE_ID_LEN],
}

/// The threshold for `holders` children: `x` for one or two, otherwise
/// `round(2x / 3)` (integer form `(2x + 1) / 3`; `2x / 3` never ends in .5).
/// 1, 2, 2, 3, 3, 4, 5, 5, 6, 7 ... for 1, 2, 3, 4 ... holders, 170 at 255.
/// `None` for no holders (no assembly) and for more than [`MAX_HOLDERS`].
pub const fn assembly_threshold(holders: usize) -> Option<usize> {
    match holders {
        0 => None,
        1 | 2 => Some(holders),
        x if x <= MAX_HOLDERS => Some((2 * x + 1) / 3),
        _ => None,
    }
}

fn check_holders(children: &[ChildHolder<'_>]) -> Result<()> {
    let mut seen = BTreeSet::new();
    for child in children {
        if child.label.is_empty()
            || child.label.len() > MAX_LABEL_LEN
            || is_weak_x25519_public_key(&child.encryption_public)
            || !seen.insert(child.label)
        {
            return Err(Error::InvalidQuorumThreshold);
        }
    }
    Ok(())
}

/// Deals `seed` among `children` at the threshold [`assembly_threshold`] gives
/// and seals each share to its child. `Ok(None)` when there are no children (an
/// ordinary account, no assembly). More than [`MAX_HOLDERS`] children, a repeated
/// or empty label, or a weak public key are refused.
pub fn split_parent_key(
    seed: &[u8; 32],
    children: &[ChildHolder<'_>],
    generation: u32,
) -> Result<Option<Assembly>> {
    let Some(threshold) = assembly_threshold(children.len()) else {
        return if children.is_empty() {
            Ok(None)
        } else {
            Err(Error::InvalidQuorumThreshold)
        };
    };
    check_holders(children)?;
    let shares: Vec<Share> = Sharks(threshold as u8)
        .dealer_rng(seed, &mut crate::crypto::os_rng())
        .take(children.len())
        .collect();
    // zip() would stop at the shorter side and drop a holder without an error.
    if shares.len() != children.len() {
        return Err(Error::InvalidQuorumThreshold);
    }
    let mut sealed_shares = Vec::with_capacity(children.len());
    for (child, share) in children.iter().zip(shares.iter()) {
        let raw = Zeroizing::new(Vec::from(share));
        let sealed = crypto_box::PublicKey::from_bytes(child.encryption_public)
            .seal(&mut crate::crypto::os_rng(), &raw)
            .map_err(|_| Error::InvalidPublicKey)?;
        sealed_shares.push(SealedShare {
            child_label: child.label.into(),
            sealed,
        });
    }
    Ok(Some(Assembly {
        threshold: threshold as u8,
        generation,
        shares: sealed_shares,
    }))
}

/// Assembles the parent's seed from the children unlocked now.
///
/// Each unlocked child's own share is opened with its secret (a share sealed to
/// another child, one that does not open, or one whose x-coordinate is zero or
/// already held is skipped). The threshold must be
/// met by shares from distinct x-coordinates, and the children that supplied
/// them must sit on at least `minimum_devices` distinct physical devices (0 or 1
/// puts no extra rule). The recovered seed is accepted only if it derives
/// `expected_signing_public`, the key the caller's registry holds for the
/// parent. Every intermediate is wiped. `QuorumNotMet` for too few usable
/// shares or too few devices, `IntegrityCheckFailed` for a seed that is not the
/// parent's.
pub fn assemble_parent_key(
    assembly: &Assembly,
    unlocked: &[UnlockedChild<'_>],
    minimum_devices: usize,
    expected_signing_public: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let threshold = assembly.threshold as usize;
    if threshold == 0 || assembly_threshold(assembly.shares.len()) != Some(threshold) {
        return Err(Error::InvalidQuorumThreshold);
    }
    let mut raws: Vec<Zeroizing<Vec<u8>>> = Vec::new();
    let mut labels: BTreeSet<&str> = BTreeSet::new();
    let mut xs_seen: BTreeSet<u8> = BTreeSet::new();
    let mut devices: BTreeSet<[u8; DEVICE_ID_LEN]> = BTreeSet::new();
    for child in unlocked {
        // A child counts once, but only once its share has opened: an entry that fails (a wrong
        // secret) must not shadow a later entry for the same child that opens.
        if labels.contains(child.label) {
            continue;
        }
        let Some(held) = assembly
            .shares
            .iter()
            .find(|s| s.child_label == child.label)
        else {
            continue;
        };
        if held.sealed.len() != SEALED_SHARE_LEN {
            continue;
        }
        let secret = crypto_box::SecretKey::from(*child.encryption_secret);
        let Ok(raw) = secret.unseal(&held.sealed) else {
            continue;
        };
        let raw = Zeroizing::new(raw);
        // A share with a zero or an already-held x-coordinate is damaged or planted (sealing is
        // anonymous): it is left out, so it cannot reject a group whose other shares are good. The
        // recovered seed is still checked against the parent's public key below.
        if raw.len() != RAW_SHARE_LEN || raw[0] == 0 || !xs_seen.insert(raw[0]) {
            continue;
        }
        labels.insert(child.label);
        raws.push(raw);
        devices.insert(child.device_id);
    }
    if raws.len() < threshold || devices.len() < minimum_devices {
        return Err(Error::QuorumNotMet);
    }
    let xs: Vec<u8> = raws.iter().map(|r| r[0]).collect();
    pss::require_distinct_nonzero_xs(&xs)?;
    let mut shares = Vec::with_capacity(raws.len());
    for raw in &raws {
        shares.push(Share::try_from(raw.as_slice()).map_err(|_| Error::QuorumNotMet)?);
    }
    let recovered = Zeroizing::new(
        Sharks(assembly.threshold)
            .recover(shares.iter())
            .map_err(|_| Error::QuorumNotMet)?,
    );
    let mut seed = Zeroizing::new([0u8; 32]);
    if recovered.len() != 32 {
        return Err(Error::IntegrityCheckFailed);
    }
    seed.copy_from_slice(&recovered);
    if signing::public_key(&seed) != *expected_signing_public {
        return Err(Error::IntegrityCheckFailed);
    }
    Ok(seed)
}

/// The parent's reissue after a child's key was revoked: `new_seed` (a rotated
/// signing key) dealt among the surviving and replacement children at the
/// generation one past `old`'s. The new seed must differ from the old one, which
/// the caller proves by rotating the parent's key first; this only enforces the
/// generation rule (`org_update`'s "exactly one past").
pub fn reissue_assembly(
    old: &Assembly,
    new_seed: &[u8; 32],
    children: &[ChildHolder<'_>],
) -> Result<Option<Assembly>> {
    let generation = old
        .generation
        .checked_add(1)
        .ok_or(Error::InvalidQuorumThreshold)?;
    split_parent_key(new_seed, children, generation)
}

impl Assembly {
    /// `KQAS` v1: magic, version, generation (u32), threshold, count, then each
    /// share as a length-prefixed label and a length-prefixed sealed share.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.shares.is_empty() || self.shares.len() > MAX_HOLDERS {
            return Err(Error::InvalidQuorumThreshold);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&ASSEMBLY_MAGIC);
        out.push(ASSEMBLY_VERSION);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.push(self.threshold);
        out.push(self.shares.len() as u8);
        for share in &self.shares {
            push_len_prefixed(&mut out, share.child_label.as_bytes())?;
            push_len_prefixed(&mut out, &share.sealed)?;
        }
        Ok(out)
    }

    /// Decodes and bounds an encoding. It checks shape only: the threshold must
    /// be the one [`assembly_threshold`] gives for the count, labels must be
    /// distinct, and nothing may trail. It opens nothing.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut data = bytes;
        if take_array::<4>(&mut data)? != ASSEMBLY_MAGIC || take_u8(&mut data)? != ASSEMBLY_VERSION
        {
            return Err(Error::InvalidBridgePackage);
        }
        let generation = take_u32(&mut data)?;
        let threshold = take_u8(&mut data)?;
        let count = take_u8(&mut data)? as usize;
        if assembly_threshold(count) != Some(threshold as usize) {
            return Err(Error::InvalidQuorumThreshold);
        }
        let mut shares = Vec::with_capacity(count);
        let mut seen = BTreeSet::new();
        for _ in 0..count {
            let label = utf8(take_len_prefixed(&mut data)?)?;
            let sealed = take_len_prefixed(&mut data)?.to_vec();
            if label.is_empty() || label.len() > MAX_LABEL_LEN || sealed.len() != SEALED_SHARE_LEN {
                return Err(Error::InvalidBridgePackage);
            }
            if !seen.insert(label.clone()) {
                return Err(Error::InvalidBridgePackage);
            }
            shares.push(SealedShare {
                child_label: label,
                sealed,
            });
        }
        if !data.is_empty() {
            return Err(Error::InvalidBridgePackage);
        }
        Ok(Self {
            threshold,
            generation,
            shares,
        })
    }
}

#[cfg(test)]
#[path = "assembly/tests.rs"]
mod tests;
