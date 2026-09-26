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
    if lab && provider && wasm {
        panic!("provider and lab builds are mutually exclusive: the lab WASM must not carry mailbox-host code");
    }
}
