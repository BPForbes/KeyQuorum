// The browser lab is public, inspectable WASM. Mailbox-host (provider)
// capabilities must never be compiled into it.
#[cfg(all(feature = "provider", feature = "lab", target_arch = "wasm32"))]
compile_error!(
    "provider and lab builds are mutually exclusive: the lab WASM must not carry mailbox-host code"
);

pub mod authority;
pub mod crypto;
pub mod db;
pub mod device;
pub mod device_relay;
pub mod envelope;
pub mod error;
pub mod export;
pub mod file_delivery;
pub mod key_tree;
pub mod keys;
#[cfg(feature = "lab")]
pub mod lab;
pub mod locked_files;
pub mod org_update;
pub mod pin;
pub mod private_bridge;
pub mod provider;
pub mod pss;
pub mod quorum;
pub mod relay;
pub mod sharing;
pub mod signing;
pub mod storage;
pub mod transfer;
pub mod vault;
