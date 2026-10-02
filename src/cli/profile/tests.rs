use super::*;
use crate::db::open_in_memory;
use crate::device;

fn conn_with_profile() -> Connection {
    let conn = open_in_memory().unwrap();
    profile::set(&conn, profile::DEFAULT_CONTAINER, "/usb/alice").unwrap();
    profile::set(&conn, profile::DEFAULT_SLOT_LABEL, "alice").unwrap();
    profile::set(&conn, profile::DEFAULT_LABEL, "alice").unwrap();
    conn
}

#[test]
fn explicit_slot_and_label_win_over_the_profile() {
    let conn = conn_with_profile();
    let id = resolve_identity(&conn, Some("bob"), Some("/usb/bob=bob")).unwrap();
    assert_eq!(id.label, "bob");
    assert_eq!(id.slot, "/usb/bob=bob");
}

#[test]
fn a_slot_alone_names_its_own_label() {
    let conn = open_in_memory().unwrap();
    let id = resolve_identity(&conn, None, Some("/usb/bob=bob")).unwrap();
    assert_eq!(id.label, "bob");
}

#[test]
fn as_and_slot_that_name_different_labels_are_refused() {
    let conn = conn_with_profile();
    let err = resolve_identity(&conn, Some("M.A"), Some("/usb/alice=alice")).unwrap_err();
    assert!(err.to_string().contains("does not match"), "{err}");
}

#[test]
fn omitted_flags_come_from_the_profile() {
    let conn = conn_with_profile();
    let id = resolve_identity(&conn, None, None).unwrap();
    assert_eq!(
        id,
        Identity {
            label: "alice".into(),
            slot: "/usb/alice=alice".into()
        }
    );
}

#[test]
fn as_alone_borrows_only_the_container_from_the_profile() {
    let conn = conn_with_profile();
    let id = resolve_identity(&conn, Some("alice.2"), None).unwrap();
    assert_eq!(id.label, "alice.2");
    assert_eq!(id.slot, "/usb/alice=alice.2");
}

#[test]
fn no_flags_and_no_profile_is_a_usage_error() {
    let conn = open_in_memory().unwrap();
    let err = resolve_identity(&conn, None, None).unwrap_err();
    assert!(matches!(err, crate::error::Error::Usage(_)), "{err}");
    assert!(resolve_identity(&conn, None, Some("no-equals")).is_err());
}

fn fake_secrets(label: &str) -> device::SlotSecrets {
    device::SlotSecrets {
        label: label.into(),
        encryption_secret: zeroize::Zeroizing::new([1; 32]),
        signing_secret: zeroize::Zeroizing::new([2; 32]),
        encryption_public: [3; 32],
        signing_public: [4; 32],
    }
}

#[test]
fn a_slot_is_opened_once_per_command_and_forgotten_after() {
    let opened = Cell::new(0);
    let open = || {
        opened.set(opened.get() + 1);
        Ok(fake_secrets("alice"))
    };
    {
        let _scope = RunScope::enter(false);
        let first = slot_secrets("/usb/alice=alice", open).unwrap();
        let second = slot_secrets("/usb/alice=alice", open).unwrap();
        assert_eq!(opened.get(), 1, "the second use must not prompt again");
        assert_eq!(*first.signing_secret, *second.signing_secret);
        slot_secrets("/usb/bob=bob", open).unwrap();
        assert_eq!(opened.get(), 2, "another slot is its own prompt");
    }
    let _scope = RunScope::enter(false);
    slot_secrets("/usb/alice=alice", open).unwrap();
    assert_eq!(opened.get(), 3, "nothing survives the command");
}

#[test]
fn a_failed_open_is_not_remembered() {
    let _scope = RunScope::enter(false);
    let failed = slot_secrets("/usb/alice=alice", || {
        Err(crate::error::Error::InvalidPassword)
    });
    assert!(failed.is_err());
    assert!(slot_secrets("/usb/alice=alice", || Ok(fake_secrets("alice"))).is_ok());
}

#[test]
fn relays_proven_in_one_command_are_not_proven_in_the_next() {
    {
        let _scope = RunScope::enter(false);
        assert!(!relay_proven("https://relay.test"));
        mark_relay_proven("https://relay.test");
        assert!(relay_proven("https://relay.test"));
    }
    let _scope = RunScope::enter(false);
    assert!(!relay_proven("https://relay.test"));
}

#[test]
fn recent_values_are_not_filled_in_for_outward_commands() {
    let conn = open_in_memory().unwrap();
    cache::remember(&conn, "send:to", "M.A", "2026-10-02 12:00:00").unwrap();
    let _scope = RunScope::enter(false);
    let found = recent_or(&conn, "send:to", None, true).unwrap();
    assert_eq!(found, None);
}
