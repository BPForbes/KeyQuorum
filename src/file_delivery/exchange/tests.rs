use super::*;

#[test]
fn every_tracked_file_letter_kind_is_one_step_and_nothing_else_is() {
    let steps = [
        (envelope::KIND_FILE_REQUEST, Step::Request),
        (envelope::KIND_FILE_REQUEST_ANSWER, Step::Answer),
        (envelope::KIND_FILE_HISTORY, Step::File),
        (envelope::KIND_FILE_HISTORY_ACK, Step::Receipt),
        (envelope::KIND_FILE_HISTORY_SNAPSHOT, Step::Snapshot),
    ];
    for (kind, step) in steps {
        assert_eq!(Step::for_kind(kind), Some(step));
    }
    for kind in (0..=u8::MAX).filter(|k| !steps.iter().any(|(s, _)| s == k)) {
        assert_eq!(Step::for_kind(kind), None, "kind {kind}");
    }
}
