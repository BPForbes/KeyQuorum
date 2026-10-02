use super::*;
use crate::db::{open_in_memory, profile};

const T0: &str = "2026-10-02 12:00:00";

#[test]
fn recent_parameter_is_fresh_for_fifteen_minutes_only() {
    let conn = open_in_memory().unwrap();
    remember(&conn, "to", "M.A", T0).unwrap();
    let hit = recall(&conn, "to", "2026-10-02 12:14:00").unwrap().unwrap();
    assert_eq!(hit.value, "M.A");
    assert_eq!(hit.age_minutes, 14);
    assert_eq!(recall(&conn, "to", "2026-10-02 12:15:00").unwrap(), None);
    assert_eq!(recall(&conn, "to", "2026-10-02 12:30:00").unwrap(), None);
    assert_eq!(recall(&conn, "other", T0).unwrap(), None);
}

#[test]
fn remembering_again_replaces_value_and_restarts_the_clock() {
    let conn = open_in_memory().unwrap();
    remember(&conn, "to", "M.A", T0).unwrap();
    remember(&conn, "to", "M.B", "2026-10-02 12:20:00").unwrap();
    let hit = recall(&conn, "to", "2026-10-02 12:30:00").unwrap().unwrap();
    assert_eq!(hit.value, "M.B");
}

fn trust<'a>(not_after: &'a str) -> RelayTrust<'a> {
    RelayTrust {
        relay_url: "https://relay.example.com",
        cert_fingerprint: "fp1",
        krl_digest: "krl1",
        key_hash: "hash1",
        cert_not_after: not_after,
    }
}

fn hit(conn: &Connection, krl: &str, key: &str, now: &str) -> bool {
    relay_trust_hit(conn, "https://relay.example.com", krl, key, now).unwrap()
}

#[test]
fn relay_trust_hits_only_on_an_exact_match_within_the_ttl() {
    let conn = open_in_memory().unwrap();
    store_relay_trust(&conn, &trust("2027-01-01 00:00:00"), T0).unwrap();
    assert!(hit(&conn, "krl1", "hash1", "2026-10-02 12:10:00"));
    assert!(!hit(&conn, "krl1", "hash1", "2026-10-02 12:15:00"));
    assert!(!hit(&conn, "krl2", "hash1", "2026-10-02 12:01:00"));
    assert!(!hit(&conn, "krl1", "hash2", "2026-10-02 12:01:00"));
}

#[test]
fn relay_trust_never_outlives_the_certificate() {
    let conn = open_in_memory().unwrap();
    store_relay_trust(&conn, &trust("2026-10-02 12:05:00"), T0).unwrap();
    assert!(hit(&conn, "krl1", "hash1", "2026-10-02 12:04:00"));
    assert!(!hit(&conn, "krl1", "hash1", "2026-10-02 12:05:00"));
}

#[test]
fn forgetting_relay_trust_forces_a_full_check() {
    let conn = open_in_memory().unwrap();
    store_relay_trust(&conn, &trust("2027-01-01 00:00:00"), T0).unwrap();
    forget_relay_trust(&conn, "https://relay.example.com").unwrap();
    assert!(!hit(&conn, "krl1", "hash1", T0));
}

#[test]
fn verified_fact_is_invalidated_by_a_changed_fingerprint_or_age() {
    let conn = open_in_memory().unwrap();
    store_verified(&conn, "slot", "./usb=M.S", "device-hash-1", T0).unwrap();
    assert!(verified_hit(
        &conn,
        "slot",
        "./usb=M.S",
        "device-hash-1",
        "2026-10-02 12:05:00"
    )
    .unwrap());
    assert!(!verified_hit(
        &conn,
        "slot",
        "./usb=M.S",
        "device-hash-2",
        "2026-10-02 12:05:00"
    )
    .unwrap());
    assert!(!verified_hit(
        &conn,
        "slot",
        "./usb=M.S",
        "device-hash-1",
        "2026-10-02 12:15:00"
    )
    .unwrap());
    assert!(!verified_hit(&conn, "label", "./usb=M.S", "device-hash-1", T0).unwrap());
}

#[test]
fn clear_empties_the_caches_but_keeps_the_profile() {
    let conn = open_in_memory().unwrap();
    profile::set(&conn, profile::DEFAULT_LABEL, "M.S").unwrap();
    remember(&conn, "to", "M.A", T0).unwrap();
    store_relay_trust(&conn, &trust("2027-01-01 00:00:00"), T0).unwrap();
    store_verified(&conn, "slot", "s", "f", T0).unwrap();
    clear(&conn).unwrap();
    assert_eq!(recall(&conn, "to", T0).unwrap(), None);
    assert!(!hit(&conn, "krl1", "hash1", T0));
    assert!(!verified_hit(&conn, "slot", "s", "f", T0).unwrap());
    assert_eq!(
        profile::get(&conn, profile::DEFAULT_LABEL)
            .unwrap()
            .as_deref(),
        Some("M.S")
    );
}

#[test]
fn profile_accepts_only_known_non_secret_keys() {
    let conn = open_in_memory().unwrap();
    assert!(profile::set(&conn, "api_key", "kq_secret").is_err());
    assert!(profile::set(&conn, "passphrase", "x").is_err());
    profile::set(
        &conn,
        profile::DEFAULT_RELAY_URL,
        "https://relay.example.com",
    )
    .unwrap();
    assert!(profile::cache_enabled(&conn).unwrap());
    profile::set(&conn, profile::CACHE_ENABLED, "off").unwrap();
    assert!(!profile::cache_enabled(&conn).unwrap());
    profile::clear(&conn, profile::CACHE_ENABLED).unwrap();
    assert!(profile::cache_enabled(&conn).unwrap());
}
