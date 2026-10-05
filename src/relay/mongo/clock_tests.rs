use super::*;

#[test]
fn text_matches_what_sqlite_writes_for_the_same_instant() {
    // 2026-03-01 12:34:56 UTC.
    let secs = 1_772_368_496;
    assert_eq!(seconds_at(secs), "2026-03-01 12:34:56");
    assert_eq!(iso_millis_at(secs, 7), "2026-03-01T12:34:56.007Z");
    assert_eq!(seconds_at(0), "1970-01-01 00:00:00");
    assert_eq!(seconds_at(-1), "1969-12-31 23:59:59");
}

#[test]
fn cutoffs_round_trip_through_parse() {
    for secs in [0, 951_782_400, 1_772_368_496, 4_102_444_799] {
        assert_eq!(parse_seconds(&seconds_at(secs)), Some(secs));
    }
    assert_eq!(parse_seconds("2026-03-01 12:34"), Some(1_772_368_440));
    assert_eq!(parse_seconds("2026-13-01 00:00"), None);
    assert_eq!(parse_seconds("2026-03-01 24:00"), None);
    assert_eq!(parse_seconds("2026-03-01"), None);
    assert_eq!(parse_seconds("not a time"), None);
}

#[test]
fn a_ttl_sqlite_cannot_represent_is_refused_here_too() {
    assert!(seconds_after(3_600).is_ok());
    assert!(seconds_after(-1).is_ok());
    assert!(matches!(
        seconds_after(i64::MAX),
        Err(Error::InvalidApiKeyRequest)
    ));
    assert!(matches!(
        seconds_after(i64::MIN),
        Err(Error::InvalidApiKeyRequest)
    ));
    assert!(matches!(
        seconds_after(400_000 * 365 * 86_400),
        Err(Error::InvalidApiKeyRequest)
    ));
    let now = now_seconds().expect("clock");
    let later = seconds_after(60).expect("later");
    assert!(later > now);
}
