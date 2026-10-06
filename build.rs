// Refuse a wasm32 build that enables both `lab` and `provider`, and embed
// the relay operator console into a provider build.
//
// The browser lab is public, inspectable WASM and must never carry
// mailbox-host code. `lib.rs` has the same guard as a `compile_error!`,
// but provider's dependencies (tokio/mio) fail on wasm32 before the crate
// itself is compiled, so this build script is what reliably names the
// reason. Native builds may combine the two (`--all-features` test runs).
//
// With `provider`, the console the relay serves at `/console/`
// (`src/relay/console.rs`) is the Vite build in `relay-console/dist`,
// listed here as `include_bytes!` entries so the binary carries it and the
// running relay never reads a file. Without that build the relay serves
// `src/relay/console/placeholder.html`, which says how to build it.
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let lab = std::env::var_os("CARGO_FEATURE_LAB").is_some();
    let provider = std::env::var_os("CARGO_FEATURE_PROVIDER").is_some();
    let wasm = std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("wasm32");
    let tui = std::env::var_os("CARGO_FEATURE_TUI").is_some();
    let mongodb = std::env::var_os("CARGO_FEATURE_MONGODB").is_some();
    if tui && wasm {
        panic!("the tui feature is native-only: the browser lab has no terminal");
    }
    if mongodb && wasm {
        panic!("the mongodb feature is native-only: the browser lab's relay runs in memory");
    }
    if lab && provider && wasm {
        panic!("provider and lab builds are mutually exclusive: the lab WASM must not carry mailbox-host code");
    }
    if provider {
        embed_relay_console();
    }
}

/// Write `$OUT_DIR/relay_console_assets.rs`: the console bundle as static
/// byte slices, or the placeholder page when `relay-console/dist` holds no
/// build. Paths are relative to `dist` with `/` separators, which is how
/// the router looks them up.
fn embed_relay_console() {
    let manifest_dir =
        PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set"));
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR is set"));
    let dist = manifest_dir.join("relay-console").join("dist");
    let placeholder = manifest_dir
        .join("src")
        .join("relay")
        .join("console")
        .join("placeholder.html");
    // A watched directory is scanned for changes. While there is no build,
    // the console directory itself is watched instead, so a later
    // `npm run build` is noticed; a missing path would re-run this script,
    // and so recompile the crate, on every build.
    if dist.is_dir() {
        println!("cargo:rerun-if-changed={}", dist.display());
    } else {
        println!(
            "cargo:rerun-if-changed={}",
            dist.parent().unwrap().display()
        );
    }
    println!("cargo:rerun-if-changed={}", placeholder.display());

    let mut files = Vec::new();
    if dist.join("index.html").is_file() {
        collect_files(&dist, &dist, &mut files);
        files.sort();
    }
    let built = !files.is_empty();
    let mut code = format!("pub const BUILT: bool = {built};\npub static ASSETS: &[Asset] = &[\n");
    if built {
        for (relative, absolute) in &files {
            code.push_str(&format!(
                "    Asset {{ path: {relative:?}, bytes: include_bytes!({absolute:?}) }},\n"
            ));
        }
    } else {
        code.push_str(&format!(
            "    Asset {{ path: \"index.html\", bytes: include_bytes!({placeholder:?}) }},\n"
        ));
    }
    code.push_str("];\n");
    fs::write(out_dir.join("relay_console_assets.rs"), code)
        .expect("write the relay console asset table");
}

/// Every regular file under `dir`, as (`relative/path`, absolute path).
/// Hidden files and source maps are left out: neither belongs in a binary.
fn collect_files(root: &Path, dir: &Path, files: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            collect_files(root, &path, files);
        } else if path.is_file() && !name.ends_with(".map") {
            let relative = path
                .strip_prefix(root)
                .expect("under the dist directory")
                .to_string_lossy()
                .replace('\\', "/");
            files.push((relative, path));
        }
    }
}
