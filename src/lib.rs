#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

// The browser lab is public, inspectable WASM. Mailbox-host (provider)
// capabilities must never be compiled into it.
#[cfg(all(feature = "provider", feature = "lab", target_arch = "wasm32"))]
compile_error!(
    "provider and lab builds are mutually exclusive: the lab WASM must not carry mailbox-host code"
);

#[cfg(all(
    feature = "workers",
    any(feature = "provider", feature = "lab"),
    target_arch = "wasm32"
))]
compile_error!(
    "the workers feature excludes provider and lab on wasm32: the public Worker must not carry mailbox-host code or the browser lab"
);

#[cfg(all(
    feature = "console",
    any(feature = "provider", feature = "lab", feature = "workers"),
    target_arch = "wasm32"
))]
compile_error!(
    "the console feature stands alone on wasm32: the admin console's module carries only provider::provision"
);

// Pure modules: always compiled. Their database-bound functions are gated
// inside with `#[cfg(feature = "host")]`.
pub mod authority;
pub mod crypto;
pub mod envelope;
pub mod error;
pub mod error_report;
pub mod file_delivery;
pub mod file_history;
pub mod keys;
pub(crate) mod nostd;
pub mod signing;
pub mod slot_token;

// Host-only: SQLite, files, the terminal, the network, the relay.
#[cfg(feature = "host")]
pub mod api_key_delivery;
#[cfg(feature = "host")]
pub mod bridge_command;
#[cfg(feature = "host")]
pub mod cli;
#[cfg(feature = "host")]
pub mod db;
#[cfg(feature = "host")]
pub mod device;
#[cfg(feature = "host")]
pub mod device_relay;
#[cfg(feature = "host")]
pub mod enrollment;
#[cfg(feature = "host")]
pub mod export;
#[cfg(feature = "host")]
pub mod key_tree;
#[cfg(feature = "lab")]
pub mod lab;
#[cfg(feature = "host")]
pub mod locked_files;
#[cfg(feature = "host")]
pub mod org_update;
#[cfg(feature = "host")]
pub mod outbox;
#[cfg(feature = "host")]
pub mod package;
#[cfg(feature = "host")]
pub mod pin;
#[cfg(feature = "host")]
pub mod private_bridge;
#[cfg(feature = "host")]
pub mod provider;
#[cfg(feature = "host")]
pub mod pss;
#[cfg(feature = "host")]
pub mod quorum;
#[cfg(feature = "host")]
pub mod relay;
#[cfg(feature = "host")]
pub(crate) mod ring;
#[cfg(feature = "host")]
pub mod setup_manifest;
#[cfg(feature = "host")]
pub mod sharing;
#[cfg(feature = "host")]
pub mod storage;
#[cfg(feature = "host")]
pub mod transfer;
#[cfg(feature = "host")]
pub mod vault;

#[cfg(all(test, feature = "host"))]
pub(crate) mod test_secrets;
