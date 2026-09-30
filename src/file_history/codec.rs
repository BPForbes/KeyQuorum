//! Field encoders for history events and the container, built on the
//! `envelope` length-prefixed helpers so bounds and parsing match the rest
//! of the crate. Every decode failure surfaces as `InvalidTrackedFile`.

use crate::envelope::{push_len_prefixed, take_array, take_len_prefixed, take_u8, utf8};
use crate::error::{Error, Result};

pub(super) fn bad<T>(result: Result<T>) -> Result<T> {
    result.map_err(|_| Error::InvalidTrackedFile)
}

pub(super) fn push_str(out: &mut Vec<u8>, value: &str) -> Result<()> {
    push_len_prefixed(out, value.as_bytes())
}

pub(super) fn take_str(data: &mut &[u8]) -> Result<String> {
    bad(take_len_prefixed(data).and_then(utf8))
}

pub(super) fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(super) fn take_u64(data: &mut &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(bad(take_array::<8>(data))?))
}

pub(super) fn take_fixed<const N: usize>(data: &mut &[u8]) -> Result<[u8; N]> {
    bad(take_array::<N>(data))
}

pub(super) fn take_byte(data: &mut &[u8]) -> Result<u8> {
    bad(take_u8(data))
}

/// `0` for absent, `1 || bytes` for present. Any other tag is malformed, so
/// one value cannot have two encodings.
pub(super) fn push_opt_array<const N: usize>(out: &mut Vec<u8>, value: Option<&[u8; N]>) {
    match value {
        Some(bytes) => {
            out.push(1);
            out.extend_from_slice(bytes);
        }
        None => out.push(0),
    }
}

pub(super) fn take_opt_array<const N: usize>(data: &mut &[u8]) -> Result<Option<[u8; N]>> {
    match take_byte(data)? {
        0 => Ok(None),
        1 => Ok(Some(take_fixed::<N>(data)?)),
        _ => Err(Error::InvalidTrackedFile),
    }
}

pub(super) fn push_opt_str(out: &mut Vec<u8>, value: Option<&str>) -> Result<()> {
    match value {
        Some(text) => {
            out.push(1);
            push_str(out, text)
        }
        None => {
            out.push(0);
            Ok(())
        }
    }
}

pub(super) fn take_opt_str(data: &mut &[u8]) -> Result<Option<String>> {
    match take_byte(data)? {
        0 => Ok(None),
        1 => Ok(Some(take_str(data)?)),
        _ => Err(Error::InvalidTrackedFile),
    }
}

pub(super) fn push_opt_u64(out: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(number) => {
            out.push(1);
            push_u64(out, number);
        }
        None => out.push(0),
    }
}

pub(super) fn take_opt_u64(data: &mut &[u8]) -> Result<Option<u64>> {
    match take_byte(data)? {
        0 => Ok(None),
        1 => Ok(Some(take_u64(data)?)),
        _ => Err(Error::InvalidTrackedFile),
    }
}
