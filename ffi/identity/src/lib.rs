//! C-callable account heritage for Flinstone.
//!
//! Account key ids are dotted labels such as `Root.Flinstone.Bob`. The
//! topology (ancestry, parent, relation) is KeyQuorum's own, from
//! [`keyquorum::authority`]. This crate adds only the account policy that
//! Flinstone needs: the master is `Root`, names are `[A-Za-z0-9_-]{1,31}`,
//! at most eight levels deep, and a home directory mirrors the key id.
//!
//! [`account`] adds account keys: an Ed25519 signing key per account, sealed
//! under its password, and the signatures on account bridges.
//!
//! [`ffi::files`] exports tracked files and co-signed delivery
//! (`include/keyquorum_files.h`): check in and sign, the public offer a host
//! verifies without the content, the recipient's co-signature, letters sealed
//! to an account's X25519 box key, delivery readiness, reads limited to what
//! a host accepted by a request time, and freshness. Trust comes from a key
//! table the caller fills from its own registry, never from a container.
//!
//! No exported function stores anything or reads a clock; the key functions
//! take their randomness from the operating system in the `std` build and from
//! the embedder's `kq_platform_random` in the `no_std` build. Buffers are
//! caller-owned and the C headers are `include/keyquorum_identity.h` and
//! `include/keyquorum_files.h`.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod account;
pub mod ffi;
pub mod heritage;
mod nostd;

/// What a panic means in the kernel build: the embedder decides (Flinstone
/// fails the check closed). A silent spin on a login path would be a denial of
/// service.
#[cfg(not(feature = "std"))]
#[panic_handler]
fn on_panic(_: &core::panic::PanicInfo) -> ! {
    extern "C" {
        fn kq_platform_panic() -> !;
    }
    // SAFETY: the embedder's function takes no arguments and never returns.
    unsafe { kq_platform_panic() }
}

/// The kernel's heap, supplied by the embedder: a `no_std` staticlib needs a
/// global allocator and this crate owns none. A null return is an allocation
/// failure (the `alloc` crate then aborts through the panic handler above).
#[cfg(not(feature = "std"))]
mod platform_heap {
    use core::alloc::{GlobalAlloc, Layout};

    extern "C" {
        fn kq_platform_alloc(size: usize, align: usize) -> *mut u8;
        fn kq_platform_free(ptr: *mut u8, size: usize, align: usize);
    }

    struct PlatformHeap;

    // SAFETY: `GlobalAlloc`'s contract is passed straight to the embedder's
    // functions, which must return memory of at least `size` bytes aligned to
    // `align`, or null.
    unsafe impl GlobalAlloc for PlatformHeap {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            kq_platform_alloc(layout.size(), layout.align())
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            kq_platform_free(ptr, layout.size(), layout.align());
        }
    }

    #[global_allocator]
    static HEAP: PlatformHeap = PlatformHeap;
}
