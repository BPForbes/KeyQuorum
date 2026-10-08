/// Refuse a wasm32 build that enables both `lab` and `provider`.
///
/// The browser lab is public, inspectable WASM and must never carry
/// mailbox-host code. `lib.rs` has the same guard as a `compile_error!`,
/// but provider's dependencies (tokio/mio) fail on wasm32 before the crate
/// itself is compiled, so this build script is what reliably names the
/// reason. Native builds may combine the two (`--all-features` test runs).
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let lab = std::env::var_os("CARGO_FEATURE_LAB").is_some();
    let provider = std::env::var_os("CARGO_FEATURE_PROVIDER").is_some();
    let wasm = std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("wasm32");
    let tui = std::env::var_os("CARGO_FEATURE_TUI").is_some();
    let workers = std::env::var_os("CARGO_FEATURE_WORKERS").is_some();
    let console = std::env::var_os("CARGO_FEATURE_CONSOLE").is_some();
    if console && wasm && (lab || provider || workers) {
        panic!("the console feature stands alone on wasm32: the admin console's module carries only provider::provision");
    }
    if tui && wasm {
        panic!("the tui feature is native-only: the browser lab has no terminal");
    }
    if workers && wasm && (lab || provider) {
        panic!("the workers feature excludes provider and lab on wasm32: the public Worker must not carry mailbox-host code or the browser lab");
    }
    if lab && provider && wasm {
        panic!("provider and lab builds are mutually exclusive: the lab WASM must not carry mailbox-host code");
    }
    pin_provider_root();
}

// The one root public key every official client trusts, compiled in as
// `provider::KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY`, 64 hex characters of a
// public value the console's setup guide or `host provision` generated as
// `root.pub`. Nothing is committed: a build reads `KEYQUORUM_PROVIDER_ROOT`
// (the same value the relay's `PROVIDER_ROOT` deploy variable holds), else
// `provider-root.pub` beside Cargo.toml (git-ignored; `root.pub` copied
// there), else a placeholder whose private half nobody holds, so a client
// built with neither trusts no relay at all. The relay never reads any of it.
/// Generated once with `host root generate`; its private half was destroyed
/// unrecorded, so nothing can ever be signed under it.
const PLACEHOLDER_ROOT: &str = "3ad178f9783cf922bd1ad04868a8f2530472f4f1ded4dfbbeb18eb0603fc3f6d";

/// Writes `provider_root.rs` into `OUT_DIR` with the root this build pins
/// (see the comment above), refusing anything but 64 hex characters.
fn pin_provider_root() {
    println!("cargo:rerun-if-env-changed=KEYQUORUM_PROVIDER_ROOT");
    println!("cargo:rerun-if-changed=provider-root.pub");
    let (text, source) = match std::env::var("KEYQUORUM_PROVIDER_ROOT") {
        Ok(value) if !value.trim().is_empty() => (value, "KEYQUORUM_PROVIDER_ROOT"),
        _ => match std::fs::read_to_string("provider-root.pub") {
            Ok(value) => (value, "provider-root.pub"),
            Err(_) => (PLACEHOLDER_ROOT.to_string(), "the placeholder"),
        },
    };
    let hex = text.trim();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        panic!("{source} must hold exactly 64 hexadecimal characters (a provider root public key)");
    }
    let bytes: Vec<String> = (0..32)
        .map(|i| format!("0x{}", &hex[2 * i..2 * i + 2]))
        .collect();
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(
        out.join("provider_root.rs"),
        format!(
            "/// The provider-root verifying key this build pins (see build.rs).\n\
             /// The matching private key must never appear in git, CI, or this tree.\n\
             pub const KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY: [u8; 32] = [{}];\n",
            bytes.join(", ")
        ),
    )
    .expect("write provider_root.rs");
}
