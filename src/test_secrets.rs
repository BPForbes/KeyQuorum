//! Secrets for tests, drawn fresh at run time.
//!
//! A passphrase, PIN, password or nonce written into a test as a literal is,
//! to a scanner, a hard-coded credential (CodeQL
//! `rust/hard-coded-cryptographic-value`), and it teaches by example the
//! very thing the code forbids. Tests draw their secrets here instead, so no
//! secret value appears in the source.

use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use rand::RngExt;

fn rng() -> UnwrapErr<SysRng> {
    UnwrapErr(SysRng)
}

/// A fresh random passphrase or password.
pub(crate) fn passphrase() -> String {
    let bytes: [u8; 16] = rng().random();
    hex::encode(bytes)
}

/// A fresh random passphrase that is not `than`.
pub(crate) fn other_passphrase(than: &str) -> String {
    loop {
        let candidate = passphrase();
        if candidate != than {
            return candidate;
        }
    }
}

/// A fresh random four-digit PIN.
pub(crate) fn pin() -> String {
    let n: u16 = rng().random();
    format!("{:04}", n % 10_000)
}

/// A fresh random four-digit PIN that is not `than`.
pub(crate) fn other_pin(than: &str) -> String {
    loop {
        let candidate = pin();
        if candidate != than {
            return candidate;
        }
    }
}

/// Fresh random bytes, for a nonce or challenge.
pub(crate) fn bytes32() -> [u8; 32] {
    rng().random()
}

/// One random passphrase for the whole test run, for fixtures that several
/// helpers must agree on (a slot provisioned in one and opened in another).
pub(crate) fn shared_passphrase() -> &'static str {
    static SHARED: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    SHARED.get_or_init(passphrase)
}
