//! Account heritage policy over KeyQuorum's dotted-label topology.

use keyquorum::authority;

/// The master account, and the first segment of every key id.
pub const ROOT: &str = "Root";
/// Longest account name (one segment).
pub const SEGMENT_MAX_CHARS: usize = 31;
/// Deepest heritage line, `Root` included.
pub const MAX_DEPTH: usize = 8;
/// Key id buffer size in bytes: every segment at its longest, separators
/// and the terminator. A key id must be shorter than this.
pub const KEY_ID_MAX: usize = MAX_DEPTH * (SEGMENT_MAX_CHARS + 1);
/// Directory under the jail root that holds every account home.
pub const HOME_DIR: &str = "home";

/// How `b` stands relative to `a`, numbered as `fl_heritage_relation_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Relation {
    Invalid = 0,
    SelfAccount = 1,
    Ancestor = 2,
    Descendant = 3,
    Sibling = 4,
    OtherBranch = 5,
}

/// One account name is a usable segment: `[A-Za-z0-9_-]`, 1 to 31 characters.
pub fn segment_valid(name: &str) -> bool {
    let len = name.len();
    (1..=SEGMENT_MAX_CHARS).contains(&len)
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A name a new account may take: a valid segment that is not `Root`
/// in any case.
pub fn name_available(name: &str) -> bool {
    segment_valid(name) && !name.eq_ignore_ascii_case(ROOT)
}

/// `Root`, or `Root` followed by valid, non-root segments, at most
/// [`MAX_DEPTH`] deep and shorter than [`KEY_ID_MAX`].
pub fn key_valid(key: &str) -> bool {
    depth(key) > 0
}

/// Number of segments (`Root` is 1); 0 for an invalid key id.
pub fn depth(key: &str) -> usize {
    if key.len() >= KEY_ID_MAX {
        return 0;
    }
    let mut parts = key.split('.');
    if parts.next() != Some(ROOT) {
        return 0;
    }
    let mut count = 1;
    for segment in parts {
        if !segment_valid(segment) || segment.eq_ignore_ascii_case(ROOT) {
            return 0;
        }
        count += 1;
    }
    if count > MAX_DEPTH {
        0
    } else {
        count
    }
}

/// Outcome of building a key id from a parent and a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildError {
    Invalid,
    TooDeep,
}

/// `parent` + `.` + `name`, when both are well formed and the result stays
/// within the depth limit.
pub fn child(parent: &str, name: &str) -> Result<String, ChildError> {
    if !key_valid(parent) || !name_available(name) {
        return Err(ChildError::Invalid);
    }
    if depth(parent) >= MAX_DEPTH {
        return Err(ChildError::TooDeep);
    }
    let key = format!("{parent}.{name}");
    if key.len() >= KEY_ID_MAX {
        return Err(ChildError::TooDeep);
    }
    Ok(key)
}

/// The key id one level up. `None` for `Root` or an invalid key id.
pub fn parent(key: &str) -> Option<String> {
    if !key_valid(key) {
        return None;
    }
    authority::parent_node_label(key).map(str::to_string)
}

/// True when `a` is `b` or an ancestor of `b`. Both must be valid.
pub fn is_ancestor_or_self(a: &str, b: &str) -> bool {
    key_valid(a) && key_valid(b) && authority::is_ancestor_or_self(a, b)
}

/// How `b` stands relative to `a`, using KeyQuorum's `relationship`.
pub fn relation(a: &str, b: &str) -> Relation {
    if !key_valid(a) || !key_valid(b) {
        return Relation::Invalid;
    }
    match authority::relationship(a, b) {
        authority::RevisionAuthority::ScopeOwner => Relation::SelfAccount,
        authority::RevisionAuthority::Descendant { .. } => Relation::Descendant,
        authority::RevisionAuthority::Ancestor { .. } => Relation::Ancestor,
        authority::RevisionAuthority::CrossBranch { .. } => {
            if authority::are_siblings(a, b) {
                Relation::Sibling
            } else {
                Relation::OtherBranch
            }
        }
        authority::RevisionAuthority::Unrelated => Relation::Invalid,
    }
}

/// `home/<segments after Root>`, for example `home/Flinstone/Bob`.
pub fn home_rel(key: &str) -> Option<String> {
    if !key_valid(key) {
        return None;
    }
    let rest = &key[ROOT.len()..];
    Some(format!("{HOME_DIR}{}", rest.replace('.', "/")))
}

#[cfg(test)]
#[path = "heritage/tests.rs"]
mod tests;
