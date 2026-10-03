//! The order the letters about one tracked file take between two people.
//!
//! Every step is a sealed, signed [`crate::envelope::PACKAGE`] letter (a
//! `KQPB`, the passport that crosses from one store to another), and each
//! depends on the one before it:
//!
//! 1. **Request** ([`envelope::KIND_FILE_REQUEST`]): the requester asks the
//!    holder for the file. It needs nothing before it; it opens the channel.
//! 2. **Answer** ([`envelope::KIND_FILE_REQUEST_ANSWER`]): the holder's
//!    signed accept or decline, bound to that exact request. An accepted
//!    answer is the agreement to exchange the file.
//! 3. **File** ([`envelope::KIND_FILE_HISTORY`]): the `KQTF` itself, only
//!    the trusted revision and its ancestors, signed by the holder, sent
//!    only after the holder accepted a file request from that person.
//! 4. **Receipt** ([`envelope::KIND_FILE_HISTORY_ACK`]): the requester's
//!    signed accept or reject, only for a file they received from them.
//! 5. **Snapshot** ([`envelope::KIND_FILE_HISTORY_SNAPSHOT`]): a `KQHS`
//!    history snapshot either side sends once a delivery between them has
//!    completed, so both can confirm their histories agree.
//!
//! Nothing new is stored to know where an exchange stands: every step is
//! already recorded, hash-chained, in the sender's own copy of the file
//! (`FILE_REQUESTED`, `REQUEST_ANSWERED`, `SHARE_ATTEMPTED`,
//! `SHARE_DELIVERED`), so [`require_step`] reads that history. An export
//! bundle (`KQXB`) is not a step (it is unsigned and carries every revision,
//! trusted or not), and a device transfer package (`KQTX`) never travels
//! with a file: it moves a person's own identity between their own devices.

use crate::envelope;
use crate::error::{Error, Result};
use crate::file_history::{HistoryEvent, HistoryEventType, HistoryOutcome, TrackedFile};

/// One step of the exchange, named by the letter kind that carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Request,
    Answer,
    File,
    Receipt,
    Snapshot,
}

impl Step {
    /// The step a letter of this kind is, or `None` for a letter that is not
    /// part of a tracked-file exchange.
    pub fn for_kind(kind: u8) -> Option<Self> {
        match kind {
            envelope::KIND_FILE_REQUEST => Some(Self::Request),
            envelope::KIND_FILE_REQUEST_ANSWER => Some(Self::Answer),
            envelope::KIND_FILE_HISTORY => Some(Self::File),
            envelope::KIND_FILE_HISTORY_ACK => Some(Self::Receipt),
            envelope::KIND_FILE_HISTORY_SNAPSHOT => Some(Self::Snapshot),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Answer => "answer",
            Self::File => "tracked file",
            Self::Receipt => "receipt",
            Self::Snapshot => "history snapshot",
        }
    }
}

/// The history events a request is recorded as.
pub const REQUEST_EVENTS: [HistoryEventType; 2] = [
    HistoryEventType::FileRequested,
    HistoryEventType::ChangeRequested,
];

/// The event of one of `kinds` that carries `request_id`, in this copy.
pub fn request_event<'a>(
    file: &'a TrackedFile,
    kinds: &[HistoryEventType],
    request_id: &str,
) -> Option<&'a HistoryEvent> {
    file.events().iter().find(|event| {
        kinds.contains(&event.event_type) && event.details.get("request_id") == Some(request_id)
    })
}

fn by(event: &HistoryEvent, label: &str) -> bool {
    event.actor_label.as_deref() == Some(label)
}

/// Requests `peer` sent `owner` that `owner` has answered, with the
/// position of the answer in the history and its decision.
fn answered_requests<'a>(
    file: &'a TrackedFile,
    owner: &'a str,
    peer: &'a str,
) -> impl Iterator<Item = (&'a HistoryEvent, usize, &'a str)> + 'a {
    file.events()
        .iter()
        .filter(move |event| {
            REQUEST_EVENTS.contains(&event.event_type)
                && by(event, peer)
                && event.details.get("to") == Some(owner)
        })
        .filter_map(move |request| {
            let id = request.details.get("request_id")?;
            let (at, answer) = file.events().iter().enumerate().find(|(_, event)| {
                event.event_type == HistoryEventType::RequestAnswered
                    && by(event, owner)
                    && event.details.get("request_id") == Some(id)
            })?;
            Some((request, at, answer.details.get("decision")?))
        })
}

fn shared_with(event: &HistoryEvent, owner: &str, peer: &str) -> bool {
    event.event_type == HistoryEventType::ShareAttempted
        && event.outcome != HistoryOutcome::Denied
        && by(event, owner)
        && event.details.get("to") == Some(peer)
        && event.details.get("delivery_id").is_some()
}

/// Received from `peer` (recorded by `file receive`).
fn received_from(event: &HistoryEvent, peer: &str) -> bool {
    event.event_type == HistoryEventType::ShareDelivered && event.details.get("from") == Some(peer)
}

/// `peer` accepted a delivery (recorded from their signed receipt).
fn accepted_by(event: &HistoryEvent, peer: &str) -> bool {
    event.event_type == HistoryEventType::ShareDelivered
        && event.details.get("by") == Some(peer)
        && event.details.get("result") == Some("accepted")
}

/// Whether `owner` may send `peer` the letter for `step` now, judged from
/// `owner`'s own copy of the file. Refused with the step that is missing.
pub fn require_step(file: &TrackedFile, owner: &str, peer: &str, step: Step) -> Result<()> {
    let events = file.events();
    let ok = match step {
        Step::Request => true,
        Step::Answer => answered_requests(file, owner, peer).next().is_some(),
        Step::File => answered_requests(file, owner, peer).any(|(request, at, decision)| {
            request.event_type == HistoryEventType::FileRequested
                && decision == "accepted"
                && events[at..].iter().any(|e| shared_with(e, owner, peer))
        }),
        Step::Receipt => events.iter().any(|e| received_from(e, peer)),
        Step::Snapshot => events
            .iter()
            .any(|e| received_from(e, peer) || accepted_by(e, peer)),
    };
    if ok {
        return Ok(());
    }
    let missing = match step {
        Step::Request => unreachable!("a request needs nothing before it"),
        Step::Answer => format!("a request from {peer} that you have answered"),
        Step::File => format!(
            "a file request from {peer} that you accepted, followed by `file share` to {peer}"
        ),
        Step::Receipt => format!("a tracked file received from {peer}"),
        Step::Snapshot => format!("a completed delivery between you and {peer}"),
    };
    Err(Error::ExchangeOutOfOrder(missing))
}

#[cfg(test)]
#[path = "exchange/tests.rs"]
mod tests;
