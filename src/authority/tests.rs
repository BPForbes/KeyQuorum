use super::*;

#[test]
fn root_restructure_needs_no_countersigner() {
    assert_eq!(restructure_countersigner("M"), None);
}

#[test]
fn department_restructure_needs_the_parent() {
    assert_eq!(restructure_countersigner("M.S"), Some("M"));
    assert_eq!(restructure_countersigner("M.S.1"), Some("M.S"));
}

#[test]
fn a_supervisor_reissue_of_an_employee_is_routine() {
    assert!(is_routine_employee_reissue("M.S", "M.S.1"));
    assert!(is_routine_employee_reissue("M.S", "M.S.3"));
    assert!(!is_routine_employee_reissue("M.S", "M.S"));
    assert!(!is_routine_employee_reissue("M.A", "M.S.1"));
    assert!(!is_routine_employee_reissue("M", "M.S"));
}

#[test]
fn ancestry_is_segment_wise() {
    assert!(is_ancestor_or_self("M.S", "M.S.2"));
    assert!(is_ancestor_or_self("M.S", "M.S"));
    assert!(!is_ancestor_or_self("M.S", "M.SALES.1"));
    assert!(!is_ancestor_or_self("M.A", "M.S.3"));
    assert!(!is_ancestor_or_self("", "M"));
    assert!(!is_ancestor_or_self("M", ""));
}

#[test]
fn parent_and_direct_parent() {
    assert_eq!(parent_node_label("M.S.2"), Some("M.S"));
    assert_eq!(parent_node_label("M"), None);
    assert!(direct_parent("M.S", "M.S.2"));
    assert!(!direct_parent("M", "M.S.2"));
}

#[test]
fn distance_counts_steps() {
    assert_eq!(ancestry_distance("M", "M"), Some(0));
    assert_eq!(ancestry_distance("M", "M.S.1"), Some(2));
    assert_eq!(ancestry_distance("M.S.1", "M"), None);
    assert_eq!(ancestry_distance("M.S", "M.SALES.1"), None);
}

#[test]
fn lowest_common_ancestor_cases() {
    assert_eq!(
        lowest_common_ancestor("M.A.1", "M.S.1").as_deref(),
        Some("M")
    );
    assert_eq!(
        lowest_common_ancestor("M.A", "M.A.2").as_deref(),
        Some("M.A")
    );
    assert_eq!(lowest_common_ancestor("M.A", "M.A").as_deref(), Some("M.A"));
    assert_eq!(
        lowest_common_ancestor("M.SALES", "M.S").as_deref(),
        Some("M")
    );
    assert_eq!(lowest_common_ancestor("M", "X"), None);
    assert_eq!(lowest_common_ancestor("", "M"), None);
}

#[test]
fn relationship_classifies_against_scope() {
    assert_eq!(relationship("M.A", "M.A"), RevisionAuthority::ScopeOwner);
    assert_eq!(
        relationship("M.A", "M.A.1"),
        RevisionAuthority::Descendant {
            ancestor: "M.A".into(),
            depth: 1
        }
    );
    assert_eq!(
        relationship("M.A", "M"),
        RevisionAuthority::Ancestor { depth: 1 }
    );
    assert_eq!(
        relationship("M.A", "M.S.1"),
        RevisionAuthority::CrossBranch {
            common_ancestor: "M".into()
        }
    );
    assert_eq!(relationship("M.A", "X.1"), RevisionAuthority::Unrelated);
    assert_eq!(relationship("M.A", ""), RevisionAuthority::Unrelated);
}
