// Refuse a wasm32 build that enables both `lab` and `provider`.
//
// The browser lab is public, inspectable WASM and must never carry
// mailbox-host code. `lib.rs` has the same guard as a `compile_error!`,
// but provider's dependencies (tokio/mio) fail on wasm32 before the crate
// itself is compiled, so this build script is what reliably names the
// reason. Native builds may combine the two (`--all-features` test runs).
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let lab = std::env::var_os("CARGO_FEATURE_LAB").is_some();
    let provider = std::env::var_os("CARGO_FEATURE_PROVIDER").is_some();
    let wasm = std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("wasm32");
    let tui = std::env::var_os("CARGO_FEATURE_TUI").is_some();
    let workers = std::env::var_os("CARGO_FEATURE_WORKERS").is_some();
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

// The one root public key the relay and every official client trust is the
// 64 hex characters in `provider-root.pub` at the repository root, a public
// value (`host provision` writes it as `root.pub`). It is compiled in as
// `provider::KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY`, so pinning a root is
// committing that file and rebuilding; nothing reads it at run time.
fn pin_provider_root() {
    println!("cargo:rerun-if-changed=provider-root.pub");
    let text = std::fs::read_to_string("provider-root.pub")
        .expect("provider-root.pub (the pinned provider root public key) must exist");
    let hex = text.trim();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        panic!("provider-root.pub must hold exactly 64 hexadecimal characters");
    }
    let bytes: Vec<String> = (0..32)
        .map(|i| format!("0x{}", &hex[2 * i..2 * i + 2]))
        .collect();
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    std::fs::write(
        out.join("provider_root.rs"),
        format!(
            "/// The provider-root verifying key this build pins (`provider-root.pub`).\n\
             /// The matching private key must never appear in git, CI, or this tree.\n\
             pub const KEYQUORUM_PROVIDER_ROOT_PUBLIC_KEY: [u8; 32] = [{}];\n",
            bytes.join(", ")
        ),
    )
    .expect("write provider_root.rs");
}
