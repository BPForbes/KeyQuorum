use super::*;
use std::ffi::CString;

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

#[test]
fn null_and_bad_utf8_are_invalid() {
    unsafe {
        assert_eq!(kq_heritage_key_valid(std::ptr::null()), 0);
        assert_eq!(kq_heritage_depth(std::ptr::null()), 0);
        assert_eq!(kq_heritage_relation(std::ptr::null(), std::ptr::null()), 0);
        let bad = [0xffu8, 0];
        assert_eq!(kq_heritage_key_valid(bad.as_ptr().cast()), 0);
    }
}

#[test]
fn child_and_parent_write_into_caller_buffers() {
    let root = c("Root.Flinstone");
    let bob = c("Bob");
    let mut out = [0 as c_char; 64];
    unsafe {
        assert_eq!(
            kq_heritage_child(root.as_ptr(), bob.as_ptr(), out.as_mut_ptr(), out.len()),
            KQ_HERITAGE_OK
        );
        assert_eq!(
            CStr::from_ptr(out.as_ptr()).to_str().unwrap(),
            "Root.Flinstone.Bob"
        );
        assert_eq!(
            kq_heritage_parent(out.as_ptr(), out.as_mut_ptr(), out.len()),
            KQ_HERITAGE_OK
        );
        assert_eq!(
            CStr::from_ptr(out.as_ptr()).to_str().unwrap(),
            "Root.Flinstone"
        );
    }
}

#[test]
fn a_small_buffer_is_refused_and_cleared() {
    let root = c("Root");
    let name = c("Flinstone");
    let mut out = [7 as c_char; 8];
    unsafe {
        assert_eq!(
            kq_heritage_child(root.as_ptr(), name.as_ptr(), out.as_mut_ptr(), out.len()),
            KQ_HERITAGE_NO_ROOM
        );
        assert_eq!(out[0], 0);
        assert_eq!(
            kq_heritage_child(root.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0),
            KQ_HERITAGE_NO_ROOM
        );
    }
}

#[test]
fn child_reports_invalid_and_too_deep() {
    let parent = c("Root.a.b.c.d.e.f.g");
    let name = c("h");
    let mut out = [0 as c_char; 128];
    unsafe {
        assert_eq!(
            kq_heritage_child(parent.as_ptr(), name.as_ptr(), out.as_mut_ptr(), out.len()),
            KQ_HERITAGE_TOO_DEEP
        );
        let bad = c("Root");
        let root_name = c("root");
        assert_eq!(
            kq_heritage_child(
                bad.as_ptr(),
                root_name.as_ptr(),
                out.as_mut_ptr(),
                out.len()
            ),
            KQ_HERITAGE_INVALID
        );
    }
}

#[test]
fn relation_codes_match_the_c_enum() {
    let a = c("Root.Flinstone");
    let b = c("Root.Flinstone.Bob");
    unsafe {
        assert_eq!(kq_heritage_relation(a.as_ptr(), b.as_ptr()), 3);
        assert_eq!(kq_heritage_relation(b.as_ptr(), a.as_ptr()), 2);
        assert_eq!(kq_heritage_relation(a.as_ptr(), a.as_ptr()), 1);
    }
}
