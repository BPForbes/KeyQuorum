//! The `no_std` entropy path: without `host`, `crypto::fill_random` (and everything that
//! draws randomness through it) calls the embedder's `kq_platform_random`. This test is
//! the embedder: it defines that symbol with a switchable status and checks that an empty
//! request makes no call, status 0 fills the buffer, and a non-zero status panics rather
//! than hand back weak bytes. Run with
//! `cargo test --no-default-features --features std --test platform_entropy`.

// With `host` the OS supplies entropy and the hook is never called: nothing to test.
#![cfg(not(feature = "host"))]

use keyquorum::{crypto, envelope, keys};
use std::ffi::c_int;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

static CALLS: AtomicUsize = AtomicUsize::new(0);
static STATUS: AtomicU8 = AtomicU8::new(0);
static COUNTER: AtomicU8 = AtomicU8::new(1);

/// The embedder's hook. Status 0 fills the buffer with a non-constant byte sequence.
#[no_mangle]
extern "C" fn kq_platform_random(buf: *mut u8, len: usize) -> c_int {
    CALLS.fetch_add(1, Ordering::SeqCst);
    let status = STATUS.load(Ordering::SeqCst);
    if status != 0 {
        return c_int::from(status);
    }
    // SAFETY: the library passes a valid writable buffer of `len` bytes.
    let out = unsafe { std::slice::from_raw_parts_mut(buf, len) };
    for byte in out {
        *byte = COUNTER.fetch_add(7, Ordering::SeqCst);
    }
    0
}

fn calls() -> usize {
    CALLS.load(Ordering::SeqCst)
}

fn set_status(status: u8) {
    STATUS.store(status, Ordering::SeqCst);
}

fn panics<R>(f: impl FnOnce() -> R) -> bool {
    catch_unwind(AssertUnwindSafe(f)).is_err()
}

// One test, so the switchable hook is never raced by a parallel one.
#[test]
fn the_embedder_hook_supplies_entropy_and_a_failure_fails_closed() {
    // An empty request never reaches the hook.
    set_status(0);
    let before = calls();
    crypto::fill_random(&mut []);
    assert_eq!(calls(), before);

    // Status 0: the bytes come from the hook.
    let mut first = [0u8; 32];
    crypto::fill_random(&mut first);
    assert_eq!(calls(), before + 1);
    assert_ne!(first, [0u8; 32]);

    // Everything built on the seam draws from it too.
    let (_, recipient_public) = keys::generate_encryption_keypair();
    let after_keygen = calls();
    let (_, _) = keys::generate_signing_keypair();
    assert!(calls() > after_keygen);

    // A non-zero status panics in every entry point and never yields a buffer.
    set_status(5);
    let mut untouched = [0xA5u8; 32];
    assert!(panics(|| crypto::fill_random(&mut untouched)));
    assert_eq!(untouched, [0xA5u8; 32]);
    assert!(panics(keys::generate_signing_keypair));
    assert!(panics(keys::generate_encryption_keypair));
    assert!(panics(|| envelope::seal(
        envelope::PACKAGE,
        1,
        &recipient_public,
        b"payload"
    )));

    // The hook recovers: the failure is not sticky state in the library.
    set_status(0);
    let mut again = [0u8; 16];
    crypto::fill_random(&mut again);
    assert_ne!(again, [0u8; 16]);
}
