# Linking the freestanding build (for the Flinstone side)

Not customer-facing. This is what an embedder with no operating system needs to link
`libkeyquorum_identity.a` built with `--no-default-features` (the `std` feature off,
which turns KeyQuorum's `host` feature off too).

Build: `cargo build --release --no-default-features --target <bare-metal target>` in
`ffi/identity`. Checked in CI on `thumbv7em-none-eabi` (clippy) and by hand for the
archive.

## What the embedder must define

Declared in `ffi/identity/include/keyquorum_identity.h`, "Embedder must provide":

- `kq_platform_random(buf, len)`: secure random bytes, 0 on success, non-zero fails
  closed (the library panics). The no_std entropy path has a test, `tests/platform_entropy.rs`.
- `kq_platform_alloc(len, align)` / `kq_platform_free(ptr, len, align)`: the heap (the
  library installs a `#[global_allocator]` over them). Zero freed memory.
- `kq_platform_panic()`: never returns; fail the check closed.

## x86_64-unknown-none (checked)

```
cd ffi/identity
cargo build --locked --release --no-default-features --target x86_64-unknown-none
```

This works because `.cargo/config.toml` (in this repository, applying to that target only) adds
`--cfg curve25519_dalek_backend="serial" --cfg poly1305_force_soft --cfg polyval_backend="soft"
--cfg sha2_backend="soft" --cfg aes_backend="soft"`. Without them rustc's LLVM crashes ("Do not know
how to split the result of this operator!", then SIGILL) while compiling `polyval`, `poly1305`,
`curve25519-dalek`, `sha2` and `aes` for the soft-float, no-SSE target, in debug and release. If you
build from a copy of `ffi/identity` that does not sit under this repository's `.cargo/`, pass the same
five flags as `RUSTFLAGS`.

Cargo defines `[target.<triple>].rustflags` per triple, so the config applies to every build run inside this workspace and to the Flinstone build of the archive from its `third_party/keyquorum` submodule directory (that directory holds this `.cargo/config.toml`). A build from outside any directory holding it must pass the same five cfgs itself (`curve25519_dalek_backend="serial"`, `poly1305_force_soft`, `polyval_backend="soft"`, `sha2_backend="soft"`, `aes_backend="soft"`). Warning: a `RUSTFLAGS` environment variable overrides those config entries, it does not append to them. A build that sets `RUSTFLAGS` must include all five cfgs and must not rely on the config. Observed here: `RUSTFLAGS="-C target-cpu=generic" cargo build --no-default-features --target x86_64-unknown-none` compiled `curve25519-dalek` with `curve25519_dalek_backend="simd"` and failed with "rustc-LLVM ERROR: Do not know how to split the result of this operator!". Opt-level, `-C target-feature` and `-C target-cpu` changes did not help;
the cfgs are the fix. Needs no `build-std` and no nightly.

Checked: the archive's only undefined symbols are the four hooks (the portable backends bring no libc
calls on this target). It was linked with a C stub built `-ffreestanding -mgeneral-regs-only
-mno-red-zone -mcmodel=kernel` and the four hooks, with `ld --gc-sections`: the linked image holds no
SSE/AVX instruction, `kq_account_keygen` and `kq_heritage_depth` ran correctly as a static Linux
process (the hook fed deterministic bytes, so that proves linking and execution, not entropy). The
image size (about 69 KiB of text for those two calls) is the reachable code for that stub only; the
size of an image that uses every export is not measured.

## Other bare-metal targets

`thumbv7em-none-eabi` (CI checks clippy, and the archive builds) has no SIMD backends, but leaves
`fma`, `fmaximum_num`, `fminimum_num`, `memcmp` and `strlen` undefined: provide them from
`compiler-builtins` (with its `mem` feature) or the kernel's libc. `nm -u libkeyquorum_identity.a`
lists the full set; the four hooks above are the only `kq_` names.

## What the archive exports (ABI version 4)

`kq_file_abi_version()` returns 4. Headers in `ffi/identity/include/`:
`keyquorum_identity.h` (heritage, account keys, `kq_bridge_connects`), `keyquorum_files.h` (tracked files,
co-signed delivery, kind-15 and kind-17 letters), `keyquorum_error.h` (`KQER` reports), `keyquorum_slots.h`
(`kq_slot_open`), `keyquorum_bridge.h` (`kq_bridge_prove`, `kq_bridge_verify`) and `keyquorum_access.h`
(`kq_access_requirement`: which factor a switch demands). Every export is a pure function over what the caller
passes in; none touches a file, a database or the network.
