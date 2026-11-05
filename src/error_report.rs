//! `KQER`: a signed error report about one artifact (a delivered package, a letter, a
//! container), written by the party that refused or failed it and carried as a sidecar
//! named by the artifact's SHA-256. It is protocol data with its own magic and version,
//! not a sealed envelope (so it does not belong in `envelope.rs`); it reuses the
//! envelope's length-prefixed codec and `signing` owns its preimage. A `KQPB` cannot
//! carry it in place (its outer parse rejects trailing bytes and the sealed payload is
//! authenticated), hence a sidecar.
//!
//! Nothing in a report is free text. The code and class are closed sets, `object_ref` is
//! a SHA-256 of the failed artifact (never its content), the reporter's label and the
//! time are charset-checked, and `detail` takes only the counts listed in
//! [`DETAIL_KEYS`], each a bounded decimal number, never text. A report is a claim by its signer:
//! [`verify`] proves who made it and which artifact it names, and [`inject`] then records
//! it in a tracked file's history as an `ErrorReported` event. It decides no trust.
//!
//! Layout (big-endian): `magic(4) | version(1) | code(u16) | class(1) | step(1) |
//! object_ref(32) | actor_label(len16) | occurred_at(len16) | detail_count(1) |
//! (key(len16) value(len16))… | signature(64)`. The signature covers every byte before it.

use crate::envelope::{push_len_prefixed, take_array, take_len_prefixed, take_u8};
use crate::error::{Error, Result};
use crate::file_history::HistoryEventType;
use crate::file_history::{EventDetails, HistoryOutcome, NewEvent, TrackedFile};
#[allow(unused_imports)]
use crate::nostd::*;
use crate::signing;

pub const MAGIC: &[u8; 4] = b"KQER";
pub const VERSION: u8 = 1;
/// A report is a few hundred bytes; anything larger is refused unread.
pub const MAX_ENCODED_LEN: usize = 1024;
/// The only detail keys a report may carry: the quorum gate's counts. Each
/// value is a decimal number of at most [`MAX_DETAIL_VALUE_LEN`] digits that
/// fits a `u32`.
pub const DETAIL_KEYS: &[&str] = &["devices", "minimum_devices", "shares", "threshold"];
pub const MAX_DETAIL_ENTRIES: usize = 8;
pub const MAX_DETAIL_VALUE_LEN: usize = 16;
const MAX_LABEL_LEN: usize = 64;
const MAX_TIME_LEN: usize = 32;

/// Closed set. Append only; never renumber.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorCode {
    Framing = 1,
    Untrusted = 2,
    Integrity = 3,
    Replayed = 4,
    NotNewer = 5,
    Forked = 6,
    BelowThreshold = 7,
    Denied = 8,
}

impl ErrorCode {
    pub fn from_u16(code: u16) -> Result<Self> {
        Ok(match code {
            1 => Self::Framing,
            2 => Self::Untrusted,
            3 => Self::Integrity,
            4 => Self::Replayed,
            5 => Self::NotNewer,
            6 => Self::Forked,
            7 => Self::BelowThreshold,
            8 => Self::Denied,
            _ => return Err(Error::InvalidErrorReport),
        })
    }

    /// The static name, for a log or a C caller (`kq_error_name`).
    pub fn name_of(code: u16) -> Option<&'static core::ffi::CStr> {
        Self::from_u16(code).ok().map(Self::name_c)
    }

    pub fn name_c(self) -> &'static core::ffi::CStr {
        match self {
            Self::Framing => c"Framing",
            Self::Untrusted => c"Untrusted",
            Self::Integrity => c"Integrity",
            Self::Replayed => c"Replayed",
            Self::NotNewer => c"NotNewer",
            Self::Forked => c"Forked",
            Self::BelowThreshold => c"BelowThreshold",
            Self::Denied => c"Denied",
        }
    }
}

/// The coarse reason a remote peer may see. Closed set. Append only; never
/// renumber.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Class {
    Framing = 1,
    Auth = 2,
    Integrity = 3,
    Freshness = 4,
    Policy = 5,
    Storage = 6,
    Resource = 7,
    Internal = 8,
}

impl Class {
    pub fn from_u8(class: u8) -> Result<Self> {
        Ok(match class {
            1 => Self::Framing,
            2 => Self::Auth,
            3 => Self::Integrity,
            4 => Self::Freshness,
            5 => Self::Policy,
            6 => Self::Storage,
            7 => Self::Resource,
            8 => Self::Internal,
            _ => return Err(Error::InvalidErrorReport),
        })
    }

    /// The fixed word recorded as `error_class` in history.
    pub fn word(self) -> &'static str {
        match self {
            Self::Framing => "framing",
            Self::Auth => "auth",
            Self::Integrity => "integrity",
            Self::Freshness => "freshness",
            Self::Policy => "policy",
            Self::Storage => "storage",
            Self::Resource => "resource",
            Self::Internal => "internal",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub code: ErrorCode,
    pub class: Class,
    /// Which step of the flow refused (the caller's own numbering).
    pub step: u8,
    /// SHA-256 of the failed artifact; never its content.
    pub object_ref: [u8; 32],
    pub actor_label: String,
    /// UTC text, digits and `-:.TZ` only.
    pub occurred_at: String,
    /// Only keys from [`DETAIL_KEYS`].
    pub detail: Vec<(String, String)>,
}

fn label_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
}

fn time_char(c: char) -> bool {
    c.is_ascii_digit() || matches!(c, '-' | ':' | '.' | 'T' | 'Z')
}

/// A detail value is a count: ASCII digits that fit a `u32`, so no word,
/// however short, is representable.
fn count_value(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DETAIL_VALUE_LEN
        && value.bytes().all(|b| b.is_ascii_digit())
        && value.parse::<u32>().is_ok()
}

impl Report {
    /// The rules a report must meet to be written or accepted: no free text
    /// anywhere.
    fn check(&self) -> Result<()> {
        let bounded = |text: &str, max: usize, ok: fn(char) -> bool| {
            !text.is_empty() && text.len() <= max && text.chars().all(ok)
        };
        if !bounded(&self.actor_label, MAX_LABEL_LEN, label_char)
            || !bounded(&self.occurred_at, MAX_TIME_LEN, time_char)
            || self.detail.len() > MAX_DETAIL_ENTRIES
        {
            return Err(Error::InvalidErrorReport);
        }
        for (n, (key, value)) in self.detail.iter().enumerate() {
            if !DETAIL_KEYS.contains(&key.as_str())
                || !count_value(value)
                || self.detail[..n].iter().any(|(earlier, _)| earlier == key)
            {
                return Err(Error::InvalidErrorReport);
            }
        }
        Ok(())
    }

    fn body(&self) -> Result<Vec<u8>> {
        self.check()?;
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&(self.code as u16).to_be_bytes());
        out.push(self.class as u8);
        out.push(self.step);
        out.extend_from_slice(&self.object_ref);
        push_len_prefixed(&mut out, self.actor_label.as_bytes())?;
        push_len_prefixed(&mut out, self.occurred_at.as_bytes())?;
        out.push(u8::try_from(self.detail.len()).map_err(|_| Error::InvalidErrorReport)?);
        for (key, value) in &self.detail {
            push_len_prefixed(&mut out, key.as_bytes())?;
            push_len_prefixed(&mut out, value.as_bytes())?;
        }
        Ok(out)
    }
}

pub fn encode_signed(report: &Report, signing_secret: &[u8; 32]) -> Result<Vec<u8>> {
    let mut out = report.body()?;
    let signature = signing::sign(signing_secret, &signing::error_report_preimage(&out));
    out.extend_from_slice(&signature);
    Ok(out)
}

fn text(bytes: &[u8]) -> Result<String> {
    core::str::from_utf8(bytes)
        .map(ToString::to_string)
        .map_err(|_| Error::InvalidErrorReport)
}

fn bad<T>(_: T) -> Error {
    Error::InvalidErrorReport
}

fn take_header(data: &mut &[u8]) -> Result<(ErrorCode, Class, u8, [u8; 32])> {
    if take_array::<4>(data).map_err(bad)? != *MAGIC || take_u8(data).map_err(bad)? != VERSION {
        return Err(Error::InvalidErrorReport);
    }
    let code = ErrorCode::from_u16(u16::from_be_bytes(take_array(data).map_err(bad)?))?;
    let class = Class::from_u8(take_u8(data).map_err(bad)?)?;
    let step = take_u8(data).map_err(bad)?;
    let object_ref: [u8; 32] = take_array(data).map_err(bad)?;
    Ok((code, class, step, object_ref))
}

fn take_detail(data: &mut &[u8], count: usize) -> Result<Vec<(String, String)>> {
    let mut detail = Vec::new();
    for _ in 0..count.min(MAX_DETAIL_ENTRIES + 1) {
        let key = text(take_len_prefixed(data).map_err(bad)?)?;
        let value = text(take_len_prefixed(data).map_err(bad)?)?;
        detail.push((key, value));
    }
    Ok(detail)
}

fn decode_body(body: &[u8]) -> Result<Report> {
    let mut data = body;
    let (code, class, step, object_ref) = take_header(&mut data)?;
    let actor_label = text(take_len_prefixed(&mut data).map_err(bad)?)?;
    let occurred_at = text(take_len_prefixed(&mut data).map_err(bad)?)?;
    let count = usize::from(take_u8(&mut data).map_err(bad)?);
    let detail = take_detail(&mut data, count)?;
    if !data.is_empty() || detail.len() != count {
        return Err(Error::InvalidErrorReport);
    }
    let report = Report {
        code,
        class,
        step,
        object_ref,
        actor_label,
        occurred_at,
        detail,
    };
    report.check()?;
    Ok(report)
}

/// Parse the framing and the field rules; the signature is returned, not
/// checked.
fn decode(bytes: &[u8]) -> Result<(Report, &[u8], [u8; 64])> {
    if bytes.len() > MAX_ENCODED_LEN || bytes.len() < MAGIC.len() + 1 + 64 {
        return Err(Error::InvalidErrorReport);
    }
    let (body, sig) = bytes.split_at(bytes.len() - 64);
    let signature: [u8; 64] = sig.try_into().map_err(bad)?;
    Ok((decode_body(body)?, body, signature))
}

/// Decode a sidecar and accept it only when the reporter's signature verifies
/// and it names `expected_object_ref` (the SHA-256 of the artifact the caller
/// actually holds).
pub fn verify(
    bytes: &[u8],
    reporter_public: &[u8; 32],
    expected_object_ref: &[u8; 32],
) -> Result<Report> {
    let (report, body, signature) = decode(bytes)?;
    signing::verify_signature(
        reporter_public,
        &signing::error_report_preimage(body),
        &signature,
    )?;
    if report.object_ref != *expected_object_ref {
        return Err(Error::IntegrityCheckFailed);
    }
    Ok(report)
}

/// The history event a verified report becomes. Every detail value is derived:
/// the class is one fixed word, the code a decimal integer, and `error_ref`
/// the lower-case hex of the 32-byte `object_ref`, so no message text can
/// reach history through it.
pub fn history_event(report: &Report) -> NewEvent {
    NewEvent {
        revision_id: None,
        occurred_at: report.occurred_at.clone(),
        actor_identity: None,
        actor_label: Some(report.actor_label.clone()),
        topology_generation: None,
        event_type: HistoryEventType::ErrorReported,
        outcome: if report.code == ErrorCode::Denied {
            HistoryOutcome::Denied
        } else {
            HistoryOutcome::Failure
        },
        details: EventDetails::new()
            .with("error_class", report.class.word())
            .with("error_code", &(report.code as u16).to_string())
            .with("error_ref", &hex::encode(report.object_ref)),
    }
}

pub fn inject(
    file: &mut TrackedFile,
    sidecar: &[u8],
    reporter_public: &[u8; 32],
    expected_object_ref: &[u8; 32],
) -> Result<Report> {
    let report = verify(sidecar, reporter_public, expected_object_ref)?;
    file.append(history_event(&report))?;
    Ok(report)
}

#[cfg(all(test, feature = "host"))]
#[path = "error_report/tests.rs"]
mod tests;
