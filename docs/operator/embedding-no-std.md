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

## What else stays undefined in the archive

Compiler runtime and libc routines the dependencies call: `fma`, `fmaximum_num`,
`fminimum_num`, `memcmp`, `strlen`. Provide them from `compiler-builtins` (with its `mem`
feature) or the kernel's libc. `nm -u libkeyquorum_identity.a` lists the full set; the
four hooks above are the only `kq_` names.

## Targets

`x86_64-unknown-none` does not build: rustc's LLVM crashes ("Do not know how to split the
result of this operator", or SIGILL) compiling `curve25519-dalek`, `poly1305` and
`polyval`, in debug and release, with or without `-C target-feature=+sse,+sse2`. It is in
those third-party crates, not in KeyQuorum. Use a custom target spec or a toolchain that
compiles them; this was not found. The linked image size is not measured.
