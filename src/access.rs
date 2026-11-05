//! The login / `su` / `sudo` access policy as one function: what a switch from
//! the account `current` to the account `target` demands. It is pure (no
//! database, no clock, `no_std`) so the hosted shell, the browser lab and a
//! freestanding kernel ask the same rule.
//!
//! The rule, in the order it is applied:
//!
//! - the same account (no `sudo`) needs nothing;
//! - `sudo`, or any switch to `Root`, needs the target's own slot token and
//!   password (`KqstAndPassword`): Root's key is sealed under Root's password,
//!   so the invoker's password cannot open it;
//! - the same branch (the target is below or above the current account) needs
//!   the target's password;
//! - another branch needs the target's password plus the slot token of a
//!   member of a LIVE private bridge that connects the two accounts
//!   (`PasswordAndBridgeKqst`), and without such a bridge the target's own
//!   slot token and password;
//! - labels that are not well formed are refused.
//!
//! "Connects" is `authority::bridge_connects`, the test
//! `private_bridge::revision_approved` applies to a bridge's members: some
//! pair of its Member labels has one end on the actor's line and the other on
//! the target's. Supervisors never count, so the caller passes Member labels
//! only. The caller passes only bridges it has checked live; the proof that
//! the presenter really is a member is `bridge_proof::prove` / `verify` (a
//! slot token alone is only a file). Which factor is asked is this module's
//! answer; checking it is not.
//!
//! `needs_parent_grant` is the opt-in `UnlockApproval::Parent` policy: a
//! parent's signature on top of the factor, for any switch that asks for a
//! factor at all. Collecting that signature at login is not designed here.

use crate::authority::{self, RevisionAuthority};
#[allow(unused_imports)]
use crate::nostd::*;

/// What a switch demands. The numbers are the C values (`KQ_ACCESS_*`): append
/// only, never renumber.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Factor {
    /// Nothing: the same account.
    None = 0,
    /// The target's password.
    Password = 1,
    /// The target's slot token (`KQST`) and password.
    KqstAndPassword = 2,
    /// The target's password and the slot token of a member of the bridge
    /// being crossed.
    PasswordAndBridgeKqst = 3,
    /// The switch is not allowed.
    Refused = 4,
}

/// A LIVE private bridge: its Member labels only (supervisors never make a
/// bridge connect).
#[derive(Clone, Copy, Debug)]
pub struct BridgeFact<'a> {
    pub uid: &'a str,
    pub members: &'a [&'a str],
}

/// The custody policy that bears on a switch.
#[derive(Clone, Copy, Debug, Default)]
pub struct AccessPolicy {
    /// `CustodyPolicy.unlock_approval == Parent`.
    pub parent_approval: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Requirement {
    pub factor: Factor,
    /// Which of the `bridges` to cross, when `factor` is
    /// `PasswordAndBridgeKqst`: the caller asks for the slot token of one of
    /// its members. The first connecting bridge.
    pub bridge_index: Option<usize>,
    pub needs_parent_grant: bool,
}

const fn plain(factor: Factor) -> Requirement {
    Requirement {
        factor,
        bridge_index: None,
        needs_parent_grant: false,
    }
}

fn granted(policy: &AccessPolicy, factor: Factor, bridge_index: Option<usize>) -> Requirement {
    Requirement {
        factor,
        bridge_index,
        needs_parent_grant: policy.parent_approval && factor != Factor::None,
    }
}

/// The first bridge in which some pair of Member labels connects `current` to
/// `target`.
fn first_connecting_bridge(
    bridges: &[BridgeFact<'_>],
    current: &str,
    target: &str,
) -> Option<usize> {
    bridges.iter().position(|bridge| {
        bridge.members.iter().enumerate().any(|(i, x)| {
            bridge
                .members
                .iter()
                .skip(i + 1)
                .any(|y| authority::bridge_connects(x, y, current, target))
        })
    })
}

/// What `current` must present to become `target`. `sudo` is a switch to
/// Root's key whoever asks. An empty label, or a malformed one, is refused.
pub fn requirement(
    current: &str,
    target: &str,
    sudo: bool,
    bridges: &[BridgeFact<'_>],
    policy: &AccessPolicy,
) -> Requirement {
    if current.is_empty() || target.is_empty() {
        return plain(Factor::Refused);
    }
    let relationship = authority::relationship(current, target);
    if !sudo && current == target && relationship == RevisionAuthority::ScopeOwner {
        return plain(Factor::None);
    }
    if sudo || target == "Root" {
        // Well-formedness of the invoker still matters: an unknown caller is
        // refused.
        return match relationship {
            RevisionAuthority::Unrelated => plain(Factor::Refused),
            _ => plain(Factor::KqstAndPassword),
        };
    }
    match relationship {
        RevisionAuthority::ScopeOwner => plain(Factor::None),
        RevisionAuthority::Descendant { .. } | RevisionAuthority::Ancestor { .. } => {
            granted(policy, Factor::Password, None)
        }
        RevisionAuthority::CrossBranch { .. } => {
            match first_connecting_bridge(bridges, current, target) {
                Some(i) => granted(policy, Factor::PasswordAndBridgeKqst, Some(i)),
                None => granted(policy, Factor::KqstAndPassword, None),
            }
        }
        RevisionAuthority::Unrelated => plain(Factor::Refused),
    }
}

#[cfg(all(test, feature = "host"))]
#[path = "access/tests.rs"]
mod tests;
