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

pub mod api_key_delivery;
pub mod authority;
pub mod bridge_command;
pub mod cli;
pub mod crypto;
pub mod db;
pub mod device;
pub mod device_relay;
pub mod enrollment;
pub mod envelope;
pub mod error;
pub mod export;
pub mod file_delivery;
pub mod file_history;
pub mod key_tree;
pub mod keys;
#[cfg(feature = "lab")]
pub mod lab;
pub mod locked_files;
pub mod org_update;
pub mod outbox;
pub mod package;
pub mod pin;
pub mod private_bridge;
pub mod provider;
pub mod pss;
pub mod quorum;
pub mod relay;
pub(crate) mod ring;
pub mod setup_manifest;
pub mod sharing;
pub mod signing;
pub mod storage;
pub mod transfer;
pub mod vault;

#[cfg(test)]
pub(crate) mod test_secrets;
