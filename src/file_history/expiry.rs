//! Expiry of a tracked file. An expiry time is scheduled as an event in the
//! chain; when it passes, every retained revision's payload is destroyed at
//! once, and the container stays behind as a tombstone: the revision graph,
//! every proof and the whole history still verify, and later attempts to use
//! the content are recorded as `EXPIRED_ACCESS_ATTEMPT`. `verify_structure`
//! enforces that destruction is all-or-nothing and always recorded. This
//! covers this container only: copies someone already holds elsewhere are
//! their own files.

use super::container::TrackedFile;
use super::event::{EventDetails, HistoryEvent, HistoryEventType, HistoryOutcome, NewEvent};
use crate::error::{Error, Result};

/// Who is acting, and when, for the events recorded here.
#[derive(Clone, Debug)]
pub struct ExpiryContext {
    pub actor_identity: Option<[u8; 16]>,
    pub actor_label: Option<String>,
    /// `YYYY-MM-DDTHH:MM:SSZ`, the same form every event uses.
    pub occurred_at: String,
    pub topology_generation: Option<u64>,
}

impl ExpiryContext {
    fn event(
        &self,
        kind: HistoryEventType,
        outcome: HistoryOutcome,
        details: EventDetails,
    ) -> NewEvent {
        NewEvent {
            revision_id: None,
            occurred_at: self.occurred_at.clone(),
            actor_identity: self.actor_identity,
            actor_label: self.actor_label.clone(),
            topology_generation: self.topology_generation,
            event_type: kind,
            outcome,
            details,
        }
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` with plausible ranges, so plain string order is
/// time order.
fn is_instant(value: &str) -> bool {
    let b = value.as_bytes();
    let digits = |r: std::ops::Range<usize>| b[r].iter().all(u8::is_ascii_digit);
    let num = |r: std::ops::Range<usize>| value[r].parse::<u32>().unwrap_or(u32::MAX);
    b.len() == 20
        && digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
        && b[10] == b'T'
        && digits(11..13)
        && b[13] == b':'
        && digits(14..16)
        && b[16] == b':'
        && digits(17..19)
        && b[19] == b'Z'
        && (1..=12).contains(&num(5..7))
        && (1..=31).contains(&num(8..10))
        && num(11..13) < 24
        && num(14..16) < 60
        && num(17..19) < 60
}

/// Whether `event` records this container's own content being destroyed.
/// A `CONTENT_DESTROYED` carrying a `gate` detail is a linked quorum or
/// password file's ciphertext being purged (`cli::gate_link`), which leaves
/// this container's revisions untouched.
pub(super) fn destroys_this_content(event: &HistoryEvent) -> bool {
    event.event_type == HistoryEventType::ContentDestroyed
        && !event.details.entries().iter().any(|(key, _)| key == "gate")
}

impl TrackedFile {
    /// Whether the content was destroyed at expiry.
    pub fn is_destroyed(&self) -> bool {
        self.events.iter().any(destroys_this_content)
    }

    /// The expiry most recently scheduled, if any.
    pub fn expires_at(&self) -> Option<String> {
        self.events
            .iter()
            .rev()
            .find(|event| event.event_type == HistoryEventType::ExpiryScheduled)
            .and_then(|event| {
                event
                    .details
                    .entries()
                    .iter()
                    .find(|(key, _)| key == "expires_at")
                    .map(|(_, value)| value.clone())
            })
    }

    /// Whether the scheduled expiry has passed at `now`.
    pub fn is_expired_at(&self, now: &str) -> bool {
        self.expires_at().is_some_and(|at| at.as_str() <= now)
    }

    /// Schedule (or move) the expiry. Refused once the content is gone, or
    /// for a malformed time.
    pub fn schedule_expiry(&mut self, at: &str, context: &ExpiryContext) -> Result<()> {
        if self.is_destroyed() || !is_instant(at) {
            return Err(Error::InvalidTrackedFile);
        }
        self.append(context.event(
            HistoryEventType::ExpiryScheduled,
            HistoryOutcome::Info,
            EventDetails::new().with("expires_at", at),
        ))?;
        Ok(())
    }

    /// Destroy every retained payload now and record why. Returns how many
    /// payloads were destroyed. Atomic: on any failure nothing changes.
    pub fn destroy_content(&mut self, reason: &str, context: &ExpiryContext) -> Result<usize> {
        if self.is_destroyed() {
            return Err(Error::FileExpired);
        }
        let payloads: Vec<Option<Vec<u8>>> = self
            .revisions
            .iter()
            .map(|stored| stored.payload.clone())
            .collect();
        let destroyed = payloads.iter().filter(|p| p.is_some()).count();
        for stored in &mut self.revisions {
            stored.payload = None;
        }
        let recorded = self.atomically(|file| {
            let mut expired = EventDetails::new().with("reason", reason);
            if let Some(at) = file.expires_at() {
                expired = expired.with("expires_at", &at);
            }
            file.append(context.event(
                HistoryEventType::FileExpired,
                HistoryOutcome::Info,
                expired,
            ))?;
            file.append(context.event(
                HistoryEventType::ContentDestroyed,
                HistoryOutcome::Success,
                EventDetails::new().with("revisions_destroyed", &destroyed.to_string()),
            ))?;
            super::verify::verify_structure(file).map(|_| ())
        });
        if let Err(error) = recorded {
            for (stored, payload) in self.revisions.iter_mut().zip(payloads) {
                stored.payload = payload;
            }
            return Err(error);
        }
        Ok(destroyed)
    }

    /// If the scheduled expiry has passed, destroy the content now. Returns
    /// whether it did.
    pub fn expire_if_due(&mut self, now: &str, context: &ExpiryContext) -> Result<bool> {
        if self.is_destroyed() || !self.is_expired_at(now) {
            return Ok(false);
        }
        self.destroy_content("scheduled expiry passed", context)?;
        Ok(true)
    }

    /// Record an attempt to use content that was destroyed.
    pub fn record_expired_access(&mut self, action: &str, context: &ExpiryContext) -> Result<()> {
        self.append(context.event(
            HistoryEventType::ExpiredAccessAttempt,
            HistoryOutcome::Denied,
            EventDetails::new().with("action", action),
        ))?;
        Ok(())
    }
}
