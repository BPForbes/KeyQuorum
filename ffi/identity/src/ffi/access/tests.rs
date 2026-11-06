use super::*;
use std::ffi::CString;

fn s(text: &str) -> CString {
    CString::new(text).unwrap()
}

/// Owns the strings a `KqBridge` array points into.
struct Bridges {
    _uids: Vec<CString>,
    _labels: Vec<Vec<CString>>,
    _pointers: Vec<Vec<*const c_char>>,
    list: Vec<KqBridge>,
}

fn bridges(spec: &[(&str, &[&str])]) -> Bridges {
    let uids: Vec<CString> = spec.iter().map(|(uid, _)| s(uid)).collect();
    let labels: Vec<Vec<CString>> = spec
        .iter()
        .map(|(_, members)| members.iter().map(|m| s(m)).collect())
        .collect();
    let pointers: Vec<Vec<*const c_char>> = labels
        .iter()
        .map(|l| l.iter().map(|c| c.as_ptr()).collect())
        .collect();
    let list = uids
        .iter()
        .zip(&pointers)
        .map(|(uid, members)| KqBridge {
            uid: uid.as_ptr(),
            members: members.as_ptr(),
            nmembers: members.len(),
        })
        .collect();
    Bridges {
        _uids: uids,
        _labels: labels,
        _pointers: pointers,
        list,
    }
}

fn ask(
    current: &str,
    target: &str,
    sudo: c_int,
    live: &Bridges,
    parent: c_int,
) -> (c_int, c_int, c_int) {
    let (current, target) = (s(current), s(target));
    let (mut index, mut grant) = (99, 99);
    let factor = unsafe {
        kq_access_requirement(
            current.as_ptr(),
            target.as_ptr(),
            sudo,
            if live.list.is_empty() {
                core::ptr::null()
            } else {
                live.list.as_ptr()
            },
            live.list.len(),
            parent,
            &mut index,
            &mut grant,
        )
    };
    (factor, index, grant)
}

#[test]
fn the_factor_table_crosses_the_boundary() {
    let none = bridges(&[]);
    assert_eq!(
        ask("Root.A.Bob", "Root.A.Bob", 0, &none, 0),
        (KQ_ACCESS_NONE, -1, 0)
    );
    assert_eq!(
        ask("Root.A", "Root.A.Bob", 0, &none, 0),
        (KQ_ACCESS_PASSWORD, -1, 0)
    );
    assert_eq!(
        ask("Root.A.Bob", "Root", 0, &none, 0),
        (KQ_ACCESS_KQST_PASSWORD, -1, 0)
    );
    assert_eq!(
        ask("Root.A.Bob", "Root", 1, &none, 1),
        (KQ_ACCESS_KQST_PASSWORD, -1, 0)
    );
    assert_eq!(
        ask("M.A.1", "M.S.1", 0, &none, 0),
        (KQ_ACCESS_KQST_PASSWORD, -1, 0)
    );
    assert_eq!(
        ask("M.A.1", "bad..label", 0, &none, 0),
        (KQ_ACCESS_REFUSED, -1, 0)
    );
    assert_eq!(
        [
            KQ_ACCESS_NONE,
            KQ_ACCESS_PASSWORD,
            KQ_ACCESS_KQST_PASSWORD,
            KQ_ACCESS_PASSWORD_BRIDGE_KQST,
            KQ_ACCESS_REFUSED
        ],
        [0, 1, 2, 3, 4]
    );
}

#[test]
fn a_live_bridge_is_named_by_index_and_the_parent_grant_follows_the_policy() {
    let live = bridges(&[("xy", &["M.X", "M.Y"]), ("as", &["M.A", "M.S"])]);
    assert_eq!(
        ask("M.A.1", "M.S.1", 0, &live, 0),
        (KQ_ACCESS_PASSWORD_BRIDGE_KQST, 1, 0)
    );
    assert_eq!(
        ask("M.A.1", "M.S.1", 0, &live, 1),
        (KQ_ACCESS_PASSWORD_BRIDGE_KQST, 1, 1)
    );
    assert_eq!(
        ask("M.A.1", "M.Z.1", 0, &live, 1),
        (KQ_ACCESS_KQST_PASSWORD, -1, 1)
    );
}

#[test]
fn a_bad_argument_is_invalid_and_grants_nothing() {
    let none = bridges(&[]);
    let target = s("Root.A");
    let (mut index, mut grant) = (99, 99);
    let rc = unsafe {
        kq_access_requirement(
            core::ptr::null(),
            target.as_ptr(),
            0,
            core::ptr::null(),
            0,
            0,
            &mut index,
            &mut grant,
        )
    };
    assert_eq!((rc, index, grant), (KQ_ACCESS_INVALID, -1, 0));
    // A bridge list that claims entries but is null, too many bridges, or a null member.
    let current = s("Root.A");
    let rc = unsafe {
        kq_access_requirement(
            current.as_ptr(),
            target.as_ptr(),
            0,
            core::ptr::null(),
            3,
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(rc, KQ_ACCESS_INVALID);
    let many: Vec<KqBridge> = (0..65)
        .map(|_| KqBridge {
            uid: current.as_ptr(),
            members: core::ptr::null(),
            nmembers: 0,
        })
        .collect();
    let rc = unsafe {
        kq_access_requirement(
            current.as_ptr(),
            target.as_ptr(),
            0,
            many.as_ptr(),
            many.len(),
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(rc, KQ_ACCESS_INVALID);
    let nulls = [core::ptr::null::<c_char>()];
    let one = [KqBridge {
        uid: current.as_ptr(),
        members: nulls.as_ptr(),
        nmembers: 1,
    }];
    let rc = unsafe {
        kq_access_requirement(
            current.as_ptr(),
            target.as_ptr(),
            0,
            one.as_ptr(),
            1,
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(rc, KQ_ACCESS_INVALID);
    // 256 valid members are accepted; 257 are refused at the FFI bound.
    let label = s("Root.Bob");
    let members_256: Vec<*const c_char> = (0..256).map(|_| label.as_ptr()).collect();
    let ok_roster = [KqBridge {
        uid: current.as_ptr(),
        members: members_256.as_ptr(),
        nmembers: 256,
    }];
    let rc = unsafe {
        kq_access_requirement(
            current.as_ptr(),
            target.as_ptr(),
            0,
            ok_roster.as_ptr(),
            1,
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_ne!(rc, KQ_ACCESS_INVALID);
    let members_257: Vec<*const c_char> = (0..257).map(|_| label.as_ptr()).collect();
    let over = [KqBridge {
        uid: current.as_ptr(),
        members: members_257.as_ptr(),
        nmembers: 257,
    }];
    let rc = unsafe {
        kq_access_requirement(
            current.as_ptr(),
            target.as_ptr(),
            0,
            over.as_ptr(),
            1,
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    assert_eq!(rc, KQ_ACCESS_INVALID);
    let _ = none;
}
