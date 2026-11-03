use super::*;
use crate::keys;
use sha2::{Digest, Sha256};

const FILE: [u8; 16] = [9; 16];

fn report(object_ref: [u8; 32]) -> Report {
    Report {
        code: ErrorCode::Integrity,
        class: Class::Integrity,
        step: 3,
        object_ref,
        actor_label: "Root.Flinstone.Bob".to_string(),
        occurred_at: "2026-11-03T10:00:00Z".to_string(),
        detail: vec![("shares".to_string(), "2".to_string())],
    }
}

fn artifact_ref() -> [u8; 32] {
    Sha256::digest(b"the failed package").into()
}

fn signed() -> (Vec<u8>, [u8; 32]) {
    let (secret, public) = keys::generate_signing_keypair();
    (
        encode_signed(&report(artifact_ref()), &secret).unwrap(),
        public,
    )
}

#[test]
fn a_signed_report_round_trips_and_names_its_artifact() {
    let (bytes, public) = signed();
    assert_eq!(&bytes[..4], MAGIC);
    let back = verify(&bytes, &public, &artifact_ref()).unwrap();
    assert_eq!(back, report(artifact_ref()));
}

#[test]
fn a_report_for_another_artifact_or_by_another_signer_is_refused() {
    let (bytes, public) = signed();
    let other_ref: [u8; 32] = Sha256::digest(b"another package").into();
    assert!(matches!(
        verify(&bytes, &public, &other_ref),
        Err(Error::IntegrityCheckFailed)
    ));
    let (_, stranger) = keys::generate_signing_keypair();
    assert!(matches!(
        verify(&bytes, &stranger, &artifact_ref()),
        Err(Error::SignatureVerificationFailed)
    ));
}

#[test]
fn every_truncation_and_trailing_byte_is_refused() {
    let (bytes, public) = signed();
    for len in 0..bytes.len() {
        assert!(
            verify(&bytes[..len], &public, &artifact_ref()).is_err(),
            "prefix {len}"
        );
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(verify(&extra, &public, &artifact_ref()).is_err());
}

#[test]
fn any_flipped_byte_is_refused() {
    let (bytes, public) = signed();
    for at in 0..bytes.len() {
        let mut tampered = bytes.clone();
        tampered[at] ^= 0x01;
        assert!(
            verify(&tampered, &public, &artifact_ref()).is_err(),
            "byte {at}"
        );
    }
}

#[test]
fn oversized_input_is_refused_unread() {
    let (_, public) = keys::generate_signing_keypair();
    assert!(matches!(
        verify(&vec![0u8; MAX_ENCODED_LEN + 1], &public, &artifact_ref()),
        Err(Error::InvalidErrorReport)
    ));
}

#[test]
fn free_text_and_unlisted_keys_cannot_be_written() {
    let (secret, _) = keys::generate_signing_keypair();
    let write = |edit: fn(&mut Report)| {
        let mut r = report(artifact_ref());
        edit(&mut r);
        encode_signed(&r, &secret)
    };
    assert!(write(|r| r.detail = vec![("message".into(), "x".into())]).is_err());
    assert!(
        write(|r| r.detail = vec![("shares".into(), "a sentence with spaces".into())]).is_err()
    );
    assert!(write(
        |r| r.detail = vec![("shares".into(), "1".into()), ("shares".into(), "2".into())]
    )
    .is_err());
    assert!(write(|r| r.actor_label = "has a space".into()).is_err());
    assert!(write(|r| r.actor_label = String::new()).is_err());
    assert!(write(|r| r.occurred_at = "yesterday, around noon".into()).is_err());
}

#[test]
fn an_injected_report_lands_in_history_as_derived_values_only() {
    let (bytes, public) = signed();
    let mut file = TrackedFile::new(FILE, "sales-report.xlsx");
    inject(&mut file, &bytes, &public, &artifact_ref()).unwrap();

    let event = &file.events()[0];
    assert_eq!(event.event_type, HistoryEventType::ErrorReported);
    assert_eq!(event.outcome, HistoryOutcome::Failure);
    assert_eq!(event.actor_label.as_deref(), Some("Root.Flinstone.Bob"));
    let detail = |key: &str| {
        event
            .details
            .entries()
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.clone())
    };
    assert_eq!(detail("error_class").as_deref(), Some("integrity"));
    assert_eq!(detail("error_code").as_deref(), Some("3"));
    // error_ref is only ever the hex of the 32-byte reference: 64 hex characters, no text.
    let error_ref = detail("error_ref").unwrap();
    assert_eq!(error_ref, hex::encode(artifact_ref()));
    assert_eq!(error_ref.len(), 64);
    assert!(error_ref.chars().all(|c| c.is_ascii_hexdigit()));
    // The report's own detail entries are not copied into history.
    assert_eq!(event.details.entries().len(), 3);
}

#[test]
fn a_denied_report_is_a_denied_event_and_a_bad_report_appends_nothing() {
    let (secret, public) = keys::generate_signing_keypair();
    let mut denied = report(artifact_ref());
    denied.code = ErrorCode::Denied;
    denied.class = Class::Policy;
    let bytes = encode_signed(&denied, &secret).unwrap();
    let mut file = TrackedFile::new(FILE, "sales-report.xlsx");
    inject(&mut file, &bytes, &public, &artifact_ref()).unwrap();
    assert_eq!(file.events()[0].outcome, HistoryOutcome::Denied);

    let mut tampered = bytes.clone();
    tampered[10] ^= 1;
    assert!(inject(&mut file, &tampered, &public, &artifact_ref()).is_err());
    assert_eq!(file.events().len(), 1);
}

#[test]
fn code_and_class_names_are_closed_sets() {
    for code in 1..=8u16 {
        let name = ErrorCode::name_of(code).unwrap();
        assert_eq!(
            format!("{:?}", ErrorCode::from_u16(code).unwrap()),
            name.to_str().unwrap()
        );
    }
    assert!(ErrorCode::name_of(0).is_none());
    assert!(ErrorCode::name_of(9).is_none());
    assert!(Class::from_u8(0).is_err() && Class::from_u8(9).is_err());
}
