use super::*;
use crate::ffi::files::{KQ_FILE_NO_ROOM, KQ_FILE_OK};
use keyquorum::file_history::{HistoryEventType, TrackedFile};
use std::ffi::CString;

fn s(text: &str) -> CString {
    CString::new(text).unwrap()
}

fn text(p: *const c_char) -> String {
    unsafe { core::ffi::CStr::from_ptr(p) }
        .to_str()
        .unwrap()
        .to_owned()
}

const PKG: [u8; 32] = [0x42; 32];

fn container() -> Vec<u8> {
    TrackedFile::new([5; 16], "report.xlsx").encode().unwrap()
}

fn sidecar(secret: &[u8; 32], pkg: &[u8; 32]) -> Vec<u8> {
    let (label, time) = (s("Root.Flinstone.Bob"), s("2026-11-03T10:00:00Z"));
    let (key, value) = (s("shares"), s("2"));
    let mut out = vec![0u8; 512];
    let mut len = 0usize;
    let status = unsafe {
        kq_error_sign(
            3,
            3,
            1,
            pkg.as_ptr(),
            label.as_ptr(),
            time.as_ptr(),
            key.as_ptr(),
            value.as_ptr(),
            secret.as_ptr(),
            out.as_mut_ptr(),
            out.len(),
            &mut len,
        )
    };
    assert_eq!(status, KQ_FILE_OK);
    out.truncate(len);
    out
}

#[test]
fn names_cross_the_boundary_and_unknown_codes_are_null() {
    assert_eq!(text(kq_error_name(3)), "Integrity");
    assert_eq!(text(kq_error_name(8)), "Denied");
    assert!(kq_error_name(0).is_null());
    assert!(kq_error_name(9).is_null());
    assert_eq!(kq_error_name(3), kq_error_name(3));
    assert_eq!(text(kq_error_class_name(3)), "integrity");
    assert!(kq_error_class_name(0).is_null());
    assert!(kq_error_class_name(9).is_null());
}

#[test]
fn a_signed_sidecar_is_verified_and_appended_as_an_error_reported_event() {
    let (secret, public) = keyquorum::keys::generate_signing_keypair();
    let report = sidecar(&secret, &PKG);
    let tf = container();
    let mut out = vec![0u8; 4096];
    let mut len = 0usize;
    let status = unsafe {
        kq_error_inject(
            tf.as_ptr(),
            tf.len(),
            report.as_ptr(),
            report.len(),
            public.as_ptr(),
            PKG.as_ptr(),
            out.as_mut_ptr(),
            out.len(),
            &mut len,
        )
    };
    assert_eq!(status, KQ_FILE_OK);
    let file = TrackedFile::decode(&out[..len]).unwrap();
    assert_eq!(file.events().len(), 1);
    assert_eq!(file.events()[0].event_type, HistoryEventType::ErrorReported);
}

#[test]
fn a_wrong_signer_or_package_or_tampered_sidecar_writes_nothing() {
    let (secret, public) = keyquorum::keys::generate_signing_keypair();
    let (_, stranger) = keyquorum::keys::generate_signing_keypair();
    let report = sidecar(&secret, &PKG);
    let tf = container();
    let inject = |report: &[u8], public: &[u8; 32], pkg: &[u8; 32]| {
        // Sentinel fill: a rejected inject must leave every out byte untouched.
        let mut out = vec![0xA5u8; 4096];
        let before = out.clone();
        let mut len = 7usize;
        let status = unsafe {
            kq_error_inject(
                tf.as_ptr(),
                tf.len(),
                report.as_ptr(),
                report.len(),
                public.as_ptr(),
                pkg.as_ptr(),
                out.as_mut_ptr(),
                out.len(),
                &mut len,
            )
        };
        assert_eq!(out, before, "rejected inject must not write the buffer");
        (status, len)
    };
    assert_eq!(inject(&report, &stranger, &PKG), (KQ_FILE_INVALID, 7));
    assert_eq!(inject(&report, &public, &[0x43; 32]), (KQ_FILE_INVALID, 7));
    let mut tampered = report.clone();
    tampered[12] ^= 1;
    assert_eq!(inject(&tampered, &public, &PKG), (KQ_FILE_INVALID, 7));
    assert_eq!(
        inject(&report[..report.len() - 1], &public, &PKG).0,
        KQ_FILE_INVALID
    );
}

#[test]
fn inject_reports_the_room_it_needs() {
    let (secret, public) = keyquorum::keys::generate_signing_keypair();
    let report = sidecar(&secret, &PKG);
    let tf = container();
    let mut len = 0usize;
    let status = unsafe {
        kq_error_inject(
            tf.as_ptr(),
            tf.len(),
            report.as_ptr(),
            report.len(),
            public.as_ptr(),
            PKG.as_ptr(),
            core::ptr::null_mut(),
            0,
            &mut len,
        )
    };
    assert_eq!(status, KQ_FILE_NO_ROOM);
    assert!(len > tf.len());
}

#[test]
fn signing_refuses_free_text_and_unknown_codes() {
    let (secret, _) = keyquorum::keys::generate_signing_keypair();
    let (label, time) = (s("Root.Bob"), s("2026-11-03T10:00:00Z"));
    let (key, sentence) = (s("shares"), s("a whole sentence"));
    let mut out = [0u8; 512];
    let mut len = 0usize;
    let mut sign = |code: u16, value: *const c_char| unsafe {
        kq_error_sign(
            code,
            3,
            1,
            PKG.as_ptr(),
            label.as_ptr(),
            time.as_ptr(),
            if value.is_null() {
                core::ptr::null()
            } else {
                key.as_ptr()
            },
            value,
            secret.as_ptr(),
            out.as_mut_ptr(),
            out.len(),
            &mut len,
        )
    };
    assert_eq!(sign(3, sentence.as_ptr()), KQ_FILE_INVALID);
    assert_eq!(sign(99, core::ptr::null()), KQ_FILE_INVALID);
    assert_eq!(sign(3, core::ptr::null()), KQ_FILE_OK);
}
