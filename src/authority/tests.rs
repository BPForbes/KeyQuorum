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
