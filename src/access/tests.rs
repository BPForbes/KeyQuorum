use super::*;

const NO_POLICY: AccessPolicy = AccessPolicy {
    parent_approval: false,
};
const PARENT: AccessPolicy = AccessPolicy {
    parent_approval: true,
};

fn ask(current: &str, target: &str, sudo: bool, bridges: &[BridgeFact<'_>]) -> Requirement {
    requirement(current, target, sudo, bridges, &NO_POLICY)
}

fn factor(current: &str, target: &str) -> Factor {
    ask(current, target, false, &[]).factor
}

#[test]
fn the_same_account_needs_nothing() {
    assert_eq!(
        ask("Root.Flinstone.Bob", "Root.Flinstone.Bob", false, &[]),
        plain(Factor::None)
    );
    assert_eq!(factor("Root", "Root"), Factor::None);
    // Even with the parent-approval policy on: nothing to approve.
    let own = requirement("Root.A", "Root.A", false, &[], &PARENT);
    assert_eq!(own, plain(Factor::None));
}

#[test]
fn the_same_branch_needs_the_targets_password_up_or_down() {
    assert_eq!(
        factor("Root.Flinstone", "Root.Flinstone.Bob"),
        Factor::Password
    );
    assert_eq!(
        factor("Root.Flinstone.Bob", "Root.Flinstone"),
        Factor::Password
    );
    assert_eq!(
        factor("Root.Flinstone.Bob", "Root.Flinstone.Ann.Kid"),
        Factor::KqstAndPassword
    );
}

#[test]
fn root_and_sudo_need_the_targets_own_token_and_password() {
    assert_eq!(
        factor("Root.Flinstone.Bob", "Root"),
        Factor::KqstAndPassword
    );
    assert_eq!(factor("Root.Alternative", "Root"), Factor::KqstAndPassword);
    // sudo is Root's key whoever asks, on every branch, and no bridge changes it.
    let live = [BridgeFact {
        uid: "b",
        members: &["Root.Flinstone", "Root.Alternative"],
    }];
    for who in ["Root.Flinstone.Bob", "Root.Alternative.Ann", "Root"] {
        assert_eq!(
            ask(who, "Root", true, &live),
            plain(Factor::KqstAndPassword),
            "{who}"
        );
    }
    // sudo never carries a parent grant (Root has no parent).
    assert!(!requirement("Root.Flinstone.Bob", "Root", true, &[], &PARENT).needs_parent_grant);
}

#[test]
fn another_branch_needs_the_targets_token_unless_a_live_bridge_connects_the_two() {
    assert_eq!(factor("M.A.1", "M.S.1"), Factor::KqstAndPassword);
    let bridge = BridgeFact {
        uid: "ab",
        members: &["M.A", "M.S"],
    };
    let crossed = ask("M.A.1", "M.S.1", false, &[bridge]);
    assert_eq!(crossed.factor, Factor::PasswordAndBridgeKqst);
    assert_eq!(crossed.bridge_index, Some(0));
    // Either direction, and a bridge that does not cover the target does not count.
    assert_eq!(
        ask("M.S.1", "M.A.1", false, &[bridge]).factor,
        Factor::PasswordAndBridgeKqst
    );
    assert_eq!(
        ask("M.A.1", "M.X.1", false, &[bridge]).factor,
        Factor::KqstAndPassword
    );
    assert_eq!(ask("M.A.1", "M.X.1", false, &[bridge]).bridge_index, None);
}

#[test]
fn the_first_connecting_bridge_is_named_and_a_second_hop_does_not_chain() {
    let unrelated = BridgeFact {
        uid: "xy",
        members: &["M.X", "M.Y"],
    };
    let connecting = BridgeFact {
        uid: "ab",
        members: &["M.A", "M.S", "M.Z"],
    };
    let also = BridgeFact {
        uid: "as",
        members: &["M.A.1", "M.S.1"],
    };
    let live = [unrelated, connecting, also];
    assert_eq!(ask("M.A.1", "M.S.1", false, &live).bridge_index, Some(1));
    // A needs a bridge to B and B a bridge to C: A does not reach C.
    let chain = [
        BridgeFact {
            uid: "1",
            members: &["M.A", "M.B"],
        },
        BridgeFact {
            uid: "2",
            members: &["M.B", "M.C"],
        },
    ];
    assert_eq!(
        ask("M.A.1", "M.C.1", false, &chain).factor,
        Factor::KqstAndPassword
    );
    // A bridge with one member, or none, connects nothing.
    let lone = [
        BridgeFact {
            uid: "l",
            members: &["M.A"],
        },
        BridgeFact {
            uid: "e",
            members: &[],
        },
    ];
    assert_eq!(
        ask("M.A.1", "M.S.1", false, &lone).factor,
        Factor::KqstAndPassword
    );
    // A bridge between two nodes of the same branch makes no crossing: the ends must differ in branch.
    let same = [BridgeFact {
        uid: "s",
        members: &["M.A", "M.A"],
    }];
    assert_eq!(
        ask("M.A.1", "M.S.1", false, &same).factor,
        Factor::KqstAndPassword
    );
}

#[test]
fn malformed_or_empty_labels_are_refused() {
    for (current, target) in [
        ("", "Root.A"),
        ("Root.A", ""),
        (".A", "Root.A"),
        ("Root..A", "Root.A"),
        ("Root.A", "Root."),
    ] {
        for sudo in [false, true] {
            assert_eq!(
                ask(current, target, sudo, &[]),
                plain(Factor::Refused),
                "{current:?} -> {target:?} sudo={sudo}"
            );
        }
    }
}

#[test]
fn the_parent_approval_policy_adds_a_grant_to_every_switch_that_asks_for_a_factor() {
    let bridge = BridgeFact {
        uid: "ab",
        members: &["M.A", "M.S"],
    };
    let granted = |current: &str, target: &str, bridges: &[BridgeFact<'_>]| {
        requirement(current, target, false, bridges, &PARENT)
    };
    assert!(granted("M", "M.A", &[]).needs_parent_grant);
    assert!(granted("M.A.1", "M.S.1", &[bridge]).needs_parent_grant);
    assert!(granted("M.A.1", "M.S.1", &[]).needs_parent_grant);
    assert!(!granted("M.A", "M.A", &[]).needs_parent_grant);
    assert!(!ask("M", "M.A", false, &[]).needs_parent_grant);
}

#[test]
fn factor_values_are_the_published_c_numbers() {
    assert_eq!(
        [
            Factor::None,
            Factor::Password,
            Factor::KqstAndPassword,
            Factor::PasswordAndBridgeKqst,
            Factor::Refused
        ]
        .map(|f| f as u8),
        [0, 1, 2, 3, 4]
    );
}
