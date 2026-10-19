use super::*;

fn long_segment() -> String {
    "a".repeat(SEGMENT_MAX_CHARS)
}

#[test]
fn segments_follow_the_account_name_rules() {
    assert!(segment_valid("Bob"));
    assert!(segment_valid("a_b-9"));
    assert!(segment_valid(&long_segment()));
    assert!(!segment_valid(""));
    assert!(!segment_valid(&"a".repeat(SEGMENT_MAX_CHARS + 1)));
    assert!(!segment_valid("Bo b"));
    assert!(!segment_valid("a.b"));
    assert!(!segment_valid("a/b"));
}

#[test]
fn root_is_reserved_in_any_case() {
    assert!(!name_available("Root"));
    assert!(!name_available("root"));
    assert!(!name_available("ROOT"));
    assert!(name_available("Rooted"));
}

#[test]
fn key_ids_must_start_at_root_and_stay_valid() {
    assert!(key_valid("Root"));
    assert!(key_valid("Root.Flinstone.Bob"));
    assert!(!key_valid("root"));
    assert!(!key_valid("Flinstone"));
    assert!(!key_valid("Root."));
    assert!(!key_valid("Root..Bob"));
    assert!(!key_valid("Root.root"));
    assert!(!key_valid("Root.Bo b"));
    assert!(!key_valid(""));
}

#[test]
fn depth_is_capped_and_counts_root() {
    assert_eq!(depth("Root"), 1);
    assert_eq!(depth("Root.Flinstone.Bob"), 3);
    let eight = "Root.a.b.c.d.e.f.g";
    assert_eq!(depth(eight), MAX_DEPTH);
    assert_eq!(depth("Root.a.b.c.d.e.f.g.h"), 0);
}

#[test]
fn child_appends_a_name_within_the_limits() {
    assert_eq!(
        child("Root.Flinstone", "Bob").unwrap(),
        "Root.Flinstone.Bob"
    );
    assert_eq!(child("Root", "Root"), Err(ChildError::Invalid));
    assert_eq!(child("Root", "a.b"), Err(ChildError::Invalid));
    assert_eq!(child("Nope", "Bob"), Err(ChildError::Invalid));
    assert_eq!(child("Root.a.b.c.d.e.f.g", "h"), Err(ChildError::TooDeep));
}

#[test]
fn parent_steps_up_and_stops_at_root() {
    assert_eq!(
        parent("Root.Flinstone.Bob").as_deref(),
        Some("Root.Flinstone")
    );
    assert_eq!(parent("Root"), None);
    assert_eq!(parent("Flinstone"), None);
}

#[test]
fn relations_match_the_heritage_tree() {
    assert_eq!(
        relation("Root.Flinstone", "Root.Flinstone"),
        Relation::SelfAccount
    );
    assert_eq!(relation("Root", "Root.Flinstone.Bob"), Relation::Descendant);
    assert_eq!(
        relation("Root.Flinstone.Bob", "Root.Flinstone"),
        Relation::Ancestor
    );
    assert_eq!(
        relation("Root.Flinstone", "Root.Alternative"),
        Relation::Sibling
    );
    assert_eq!(
        relation("Root.Flinstone.Bob", "Root.Alternative.Ann"),
        Relation::OtherBranch
    );
    assert_eq!(relation("Root.Flin", "Root.Flinstone"), Relation::Sibling);
    assert_eq!(relation("Root", "nope"), Relation::Invalid);
}

#[test]
fn ancestry_is_segment_wise() {
    assert!(is_ancestor_or_self("Root.Flinstone", "Root.Flinstone.Bob"));
    assert!(is_ancestor_or_self("Root.Flinstone", "Root.Flinstone"));
    assert!(!is_ancestor_or_self("Root.Flin", "Root.Flinstone"));
    assert!(!is_ancestor_or_self("Root.Flinstone.Bob", "Root.Flinstone"));
}

#[test]
fn home_mirrors_the_key_id() {
    assert_eq!(home_rel("Root").as_deref(), Some("home"));
    assert_eq!(
        home_rel("Root.Flinstone.Bob").as_deref(),
        Some("home/Flinstone/Bob")
    );
    assert_eq!(home_rel("nope"), None);
}
