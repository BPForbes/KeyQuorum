#!/usr/bin/env bash
# Installs what `npm run build:relay-wasm` needs on Cloudflare's Workers Builds
# image, which has Node, Go, Python and Ruby but no Rust and no clang: a pinned
# Rust toolchain with the wasm32 target, the wasm-bindgen CLI at the version
# Cargo.lock pins, and clang from the wasi-sdk release, which the crate's
# bundled SQLite (compiled from C for wasm32 by the `sqlite-wasm-rs` build
# script) needs. ensure-relay-wasm.mjs points `CC_wasm32_unknown_unknown` and
# `AR_wasm32_unknown_unknown` at it. Run by `npm run builds:build` (docs/operator/relay-hosting.md,
# "Workers Builds and previews"); the GitHub workflow installs the same things
# with its own, SHA-pinned actions and never runs this.
#
# Each download is checked against a SHA-256 written here, so a changed
# download fails the build instead of running. Nothing here reads a secret, and
# the build token Cloudflare holds for the build is not given to anything this
# script downloads. Raising a version means raising its hash in the same commit.
set -euo pipefail

RUSTUP_VERSION="1.28.2"
RUSTUP_SHA256="20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c"
RUST_TOOLCHAIN="1.97.0"
WASM_BINDGEN_VERSION="0.2.129"
WASM_BINDGEN_SHA256="82d12bb940e2d4e72e0d5605387fc1b8ca179044e012b620f0ce4e7440e8320e"
WASI_SDK_VERSION="25.0"
WASI_SDK_SHA256="52640dde13599bf127a95499e61d6d640256119456d1af8897ab6725bcf3d89c"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "${here}/../.." && pwd)"

locked="$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/version = |"/, ""); print; exit }' "${repo}/Cargo.lock")"
if [ "${locked}" != "${WASM_BINDGEN_VERSION}" ]; then
  echo "error: Cargo.lock pins wasm-bindgen ${locked}, but this script is pinned to ${WASM_BINDGEN_VERSION}." >&2
  echo "Update WASM_BINDGEN_VERSION and WASM_BINDGEN_SHA256 together." >&2
  exit 1
fi

export CARGO_HOME="${CARGO_HOME:-${HOME}/.cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-${HOME}/.rustup}"
WASI_SDK_DIR="${WASI_SDK_DIR:-${HOME}/.wasi-sdk}"
export PATH="${CARGO_HOME}/bin:${PATH}"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

# fetch URL FILE SHA256: over HTTPS only, and only a file that matches its hash.
fetch() {
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location --retry 3 --output "$2" "$1"
  if ! echo "$3  $2" | sha256sum --check --status; then
    echo "error: the download for $2 does not match its pinned SHA-256; refusing to run it." >&2
    exit 1
  fi
}

if ! rustc --version 2>/dev/null | grep -q "^rustc ${RUST_TOOLCHAIN} "; then
  fetch "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init" \
    "${work}/rustup-init" "${RUSTUP_SHA256}"
  chmod +x "${work}/rustup-init"
  "${work}/rustup-init" -y --no-modify-path --profile minimal \
    --default-toolchain "${RUST_TOOLCHAIN}" --target wasm32-unknown-unknown
fi
rustup target add wasm32-unknown-unknown --toolchain "${RUST_TOOLCHAIN}"

if ! wasm-bindgen --version 2>/dev/null | grep -q " ${WASM_BINDGEN_VERSION}\$"; then
  archive="wasm-bindgen-${WASM_BINDGEN_VERSION}-x86_64-unknown-linux-musl"
  fetch "https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${WASM_BINDGEN_VERSION}/${archive}.tar.gz" \
    "${work}/wasm-bindgen.tar.gz" "${WASM_BINDGEN_SHA256}"
  tar -xzf "${work}/wasm-bindgen.tar.gz" -C "${work}"
  mkdir -p "${CARGO_HOME}/bin"
  install -m 0755 "${work}/${archive}/wasm-bindgen" "${CARGO_HOME}/bin/wasm-bindgen"
fi

# Only the compiler, its two shared libraries, its archiver and clang's own
# headers are kept: the whole SDK is 360 MB and the crate needs none of the rest.
if [ ! -x "${WASI_SDK_DIR}/bin/clang" ] || [ ! -x "${WASI_SDK_DIR}/bin/llvm-ar" ]; then
  archive="wasi-sdk-${WASI_SDK_VERSION}-x86_64-linux"
  fetch "https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_SDK_VERSION%%.*}/${archive}.tar.gz" \
    "${work}/wasi-sdk.tar.gz" "${WASI_SDK_SHA256}"
  mkdir -p "${WASI_SDK_DIR}"
  tar -xzf "${work}/wasi-sdk.tar.gz" -C "${WASI_SDK_DIR}" --strip-components=1 --wildcards \
    '*/bin/clang' '*/bin/clang-[0-9]*' '*/bin/llvm-ar' '*/lib/lib*.so*' '*/lib/clang/*'
fi

echo "rust: $(rustc --version); $(wasm-bindgen --version); $("${WASI_SDK_DIR}/bin/clang" --version | head -1)"
