//! A customer API key as a relay issues it: sealed to the customer, signed
//! by the relay, never shown in the clear.
//!
//! The host mints a `kq_…` bearer and, instead of printing it, builds a
//! [`KeyIssue`]: the relay URL the key is for, the key's id and scope, the
//! bearer, when it was issued, an optional expiry, an optional device the
//! key is bound to, the relay's `KQPC` certificate, and an optional licence
//! statement for the customer to read. The relay signs every field together
//! with the recipient's X25519 public key
//! ([`signing::relay_api_key_issue_preimage`]) and the signed payload is
//! sealed to that key in one of two carriers, both framed by
//! [`crate::envelope`]:
//!
//! - a [`envelope::PACKAGE`] letter of kind [`envelope::KIND_API_KEY_ISSUE`],
//!   stored in the customer's mailbox for a rotated key, which the next
//!   pull with the old key collects; or
//! - an [`envelope::EXPORT_BUNDLE`] of type [`export::BUNDLE_TYPE_API_KEY`],
//!   written as a `.kqkey` file for a first key, when there is no bearer
//!   yet to pull with.
//!
//! [`open`] takes either, checks that the frame was sealed to the key that
//! opened it, verifies the carried certificate against the provider root
//! and the revocation list, verifies the relay's signature with the key that
//! certificate names, and refuses an expired issue. It decides nothing about
//! the relay URL or the device: the command that loads the key knows which
//! relay it is loading for and which container opened it, and checks those
//! ([`Error::KeyIssueRelayMismatch`], [`Error::KeyIssueDeviceMismatch`]).
//! The relay side (`relay::key_delivery`) builds issues inside the same
//! transaction that mints the key; this module never touches a database.
//!
//! The payload, before sealing, is length-prefixed with `envelope`'s codec:
//!
//! ```text
//! version (1) | relay_url | key_id (8, BE) | scope | token | issued_at
//!   | expires_at? | device_id? | certificate | licence? | signature (64)
//! ```
//!
//! where each `?` field is a presence byte followed, when set, by the
//! field. The `kql_…` operator lock and the provider policy never travel
//! this way: they authorize minting on the host and stay there.

use crate::envelope::{self, push_len_prefixed, take_array, take_len_prefixed, take_u8};
use crate::error::{Error, Result};
use crate::export;
use crate::provider::{self, Certificate};
use crate::relay::ProviderIdentity;
use crate::signing;
use std::collections::HashSet;
use zeroize::Zeroizing;

/// Payload version written after the kind byte. Bump only with a new
/// decoder branch; old issues keep opening.
pub const PAYLOAD_VERSION: u8 = 1;
/// Length of a device id, as `device.kq` writes it.
pub const DEVICE_ID_LEN: usize = 16;
/// The longest licence statement an issue carries (UTF-8 bytes).
pub const MAX_LICENCE_BYTES: usize = 16 * 1024;
const SIGNATURE_LEN: usize = 64;

/// Everything a customer needs to load a relay key, as the relay signed it.
#[derive(Clone)]
pub struct KeyIssue {
    /// The relay the key is for, normalized (no trailing slash).
    pub relay_url: String,
    /// The key's id on that relay.
    pub key_id: i64,
    /// The key's scope, as `ApiKeyScope::as_str` spells it.
    pub scope: String,
    /// The bearer. Zeroed on drop, never shown by `Debug`.
    pub token: Zeroizing<String>,
    /// When the relay issued it (UTC, the relay's clock).
    pub issued_at: String,
    /// When the issue itself stops being loadable (UTC), if ever.
    pub expires_at: Option<String>,
    /// The container this key may be loaded from, if bound to one.
    pub device_id: Option<[u8; DEVICE_ID_LEN]>,
    /// The relay's `KQPC` certificate: it names the key that signed this
    /// issue and the client pins it after verifying it against the root.
    pub certificate: Vec<u8>,
    /// What the customer is entitled to, in words, if the operator wrote it.
    pub licence: Option<String>,
}

impl std::fmt::Debug for KeyIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyIssue")
            .field("relay_url", &self.relay_url)
            .field("key_id", &self.key_id)
            .field("scope", &self.scope)
            .field("token", &"<redacted>")
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .field("device_id", &self.device_id.map(hex::encode))
            .field("certificate_len", &self.certificate.len())
            .field("licence", &self.licence)
            .finish()
    }
}

/// Which sealed carrier an issue travels in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    /// `KQPB`, kind [`envelope::KIND_API_KEY_ISSUE`]: through the mailbox.
    Letter,
    /// `KQXB`, type [`export::BUNDLE_TYPE_API_KEY`]: a `.kqkey` file.
    Bundle,
}

impl Carrier {
    /// The word a message uses for this carrier.
    pub fn noun(self) -> &'static str {
        match self {
            Carrier::Letter => "letter",
            Carrier::Bundle => "bundle",
        }
    }
}

/// An issue that [`open`] accepted: where it came from, whom it was sealed
/// to, what it says, and the certificate that vouched for its signature.
#[derive(Debug)]
pub struct Opened {
    pub carrier: Carrier,
    pub recipient_public_key: [u8; 32],
    pub issue: KeyIssue,
    pub certificate: Certificate,
}

/// Sign `issue` for `recipient_public_key` with the relay key and encode
/// the payload. The result is plaintext and holds the bearer, so it is
/// zeroed on drop; it exists only to be sealed by [`seal_letter`] or
/// [`seal_bundle`].
pub fn sign(
    identity: &ProviderIdentity,
    recipient_public_key: &[u8; 32],
    issue: &KeyIssue,
) -> Result<Zeroizing<Vec<u8>>> {
    if issue.certificate != identity.certificate {
        return Err(Error::InvalidKeyIssue);
    }
    if issue
        .licence
        .as_ref()
        .is_some_and(|text| text.len() > MAX_LICENCE_BYTES)
    {
        return Err(Error::BundleFieldTooLarge);
    }
    let preimage = preimage(recipient_public_key, issue)?;
    let signature = signing::sign(&identity.relay_private_key, &preimage);
    let mut out = Zeroizing::new(Vec::new());
    out.push(PAYLOAD_VERSION);
    push_len_prefixed(&mut out, issue.relay_url.as_bytes())?;
    out.extend_from_slice(&issue.key_id.to_be_bytes());
    push_len_prefixed(&mut out, issue.scope.as_bytes())?;
    push_len_prefixed(&mut out, issue.token.as_bytes())?;
    push_len_prefixed(&mut out, issue.issued_at.as_bytes())?;
    push_optional(&mut out, issue.expires_at.as_deref().map(str::as_bytes))?;
    push_optional(&mut out, issue.device_id.as_ref().map(|id| &id[..]))?;
    push_len_prefixed(&mut out, &issue.certificate)?;
    push_optional(&mut out, issue.licence.as_deref().map(str::as_bytes))?;
    out.extend_from_slice(&signature);
    Ok(out)
}

/// `issue`, signed and sealed as a mailbox letter for `recipient_public_key`.
pub fn seal_letter(
    identity: &ProviderIdentity,
    recipient_public_key: &[u8; 32],
    issue: &KeyIssue,
) -> Result<Vec<u8>> {
    let payload = sign(identity, recipient_public_key, issue)?;
    envelope::seal(
        envelope::PACKAGE,
        envelope::KIND_API_KEY_ISSUE,
        recipient_public_key,
        &payload,
    )
}

/// `issue`, signed and sealed as a `.kqkey` bundle for `recipient_public_key`.
pub fn seal_bundle(
    identity: &ProviderIdentity,
    recipient_public_key: &[u8; 32],
    issue: &KeyIssue,
) -> Result<Vec<u8>> {
    let payload = sign(identity, recipient_public_key, issue)?;
    export::export_api_key_issue(&payload, recipient_public_key)
}

/// Which carrier `bytes` is, by its magic and kind byte alone. `None` when
/// it is neither a key letter nor a key bundle.
pub fn carrier_of(bytes: &[u8]) -> Option<Carrier> {
    let format = envelope::format_of(bytes)?;
    let (kind, _, _) = envelope::parse_outer_as(format, bytes).ok()?;
    if format == envelope::PACKAGE && kind == envelope::KIND_API_KEY_ISSUE {
        Some(Carrier::Letter)
    } else if format == envelope::EXPORT_BUNDLE && kind == export::BUNDLE_TYPE_API_KEY {
        Some(Carrier::Bundle)
    } else {
        None
    }
}

/// Open a key letter or bundle with the recipient's X25519 secret and
/// accept it only if the frame was sealed to that key, the carried
/// certificate chains to `root_public_key`, is unrevoked and valid at
/// `now_utc`, the relay's signature verifies under the key that certificate
/// names, and the issue has not expired.
pub fn open(
    bytes: &[u8],
    recipient_secret: &[u8; 32],
    root_public_key: &[u8; 32],
    now_utc: &str,
    revoked: &HashSet<String>,
) -> Result<Opened> {
    let carrier = carrier_of(bytes).ok_or(Error::InvalidKeyIssue)?;
    let format = match carrier {
        Carrier::Letter => envelope::PACKAGE,
        Carrier::Bundle => envelope::EXPORT_BUNDLE,
    };
    let (_, header_public_key, payload) =
        envelope::open_as(format, bytes, recipient_secret).map_err(|_| Error::InvalidKeyIssue)?;
    // The header is a routing slip anyone can rewrite; what the signature
    // binds is the key that actually opened the box.
    let recipient_public_key = *crypto_box::SecretKey::from(*recipient_secret)
        .public_key()
        .as_bytes();
    if header_public_key != recipient_public_key {
        return Err(Error::InvalidKeyIssue);
    }
    let (issue, signature) = decode(&payload)?;
    let certificate =
        provider::verify_certificate(root_public_key, &issue.certificate, now_utc, revoked)?;
    let preimage = preimage(&recipient_public_key, &issue)?;
    signing::verify_signature(&certificate.relay_public_key, &preimage, &signature)
        .map_err(|_| Error::InvalidKeyIssue)?;
    if issue
        .expires_at
        .as_deref()
        .is_some_and(|expires| expires <= now_utc)
    {
        return Err(Error::KeyIssueExpired);
    }
    Ok(Opened {
        carrier,
        recipient_public_key,
        issue,
        certificate,
    })
}

fn preimage(recipient_public_key: &[u8; 32], issue: &KeyIssue) -> Result<[u8; 32]> {
    signing::relay_api_key_issue_preimage(
        recipient_public_key,
        &issue.relay_url,
        issue.key_id,
        &issue.scope,
        &issue.token,
        &issue.issued_at,
        issue.expires_at.as_deref(),
        issue.device_id.as_ref(),
        &issue.certificate,
        issue.licence.as_deref(),
    )
}

fn push_optional(out: &mut Vec<u8>, field: Option<&[u8]>) -> Result<()> {
    match field {
        Some(bytes) => {
            out.push(1);
            push_len_prefixed(out, bytes)
        }
        None => {
            out.push(0);
            Ok(())
        }
    }
}

fn take_optional<'a>(data: &mut &'a [u8]) -> Result<Option<&'a [u8]>> {
    match take_u8(data)? {
        0 => Ok(None),
        1 => Ok(Some(take_len_prefixed(data)?)),
        _ => Err(Error::InvalidBridgePackage),
    }
}

fn utf8(bytes: &[u8]) -> Result<String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| Error::InvalidKeyIssue)
}

fn decode(payload: &[u8]) -> Result<(KeyIssue, [u8; SIGNATURE_LEN])> {
    decode_fields(payload).map_err(|_| Error::InvalidKeyIssue)
}

fn decode_fields(payload: &[u8]) -> Result<(KeyIssue, [u8; SIGNATURE_LEN])> {
    let mut data = payload;
    if take_u8(&mut data)? != PAYLOAD_VERSION {
        return Err(Error::InvalidKeyIssue);
    }
    let relay_url = utf8(take_len_prefixed(&mut data)?)?;
    let key_id = i64::from_be_bytes(take_array(&mut data)?);
    let scope = utf8(take_len_prefixed(&mut data)?)?;
    let token = Zeroizing::new(utf8(take_len_prefixed(&mut data)?)?);
    let issued_at = utf8(take_len_prefixed(&mut data)?)?;
    let expires_at = take_optional(&mut data)?.map(utf8).transpose()?;
    let device_id = match take_optional(&mut data)? {
        None => None,
        Some(id) => Some(<[u8; DEVICE_ID_LEN]>::try_from(id).map_err(|_| Error::InvalidKeyIssue)?),
    };
    let certificate = take_len_prefixed(&mut data)?.to_vec();
    let licence = take_optional(&mut data)?.map(utf8).transpose()?;
    if licence
        .as_ref()
        .is_some_and(|text| text.len() > MAX_LICENCE_BYTES)
    {
        return Err(Error::InvalidKeyIssue);
    }
    let signature: [u8; SIGNATURE_LEN] = take_array(&mut data)?;
    if !data.is_empty() {
        return Err(Error::InvalidKeyIssue);
    }
    Ok((
        KeyIssue {
            relay_url,
            key_id,
            scope,
            token,
            issued_at,
            expires_at,
            device_id,
            certificate,
            licence,
        },
        signature,
    ))
}

#[cfg(test)]
#[path = "api_key_delivery/tests.rs"]
mod tests;
