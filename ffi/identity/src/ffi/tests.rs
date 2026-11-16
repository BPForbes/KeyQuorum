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

fn password() -> CString {
    let bytes = keyquorum::crypto::random_salt();
    c(&bytes.iter().map(|b| format!("{b:02x}")).collect::<String>())
}

#[test]
fn account_key_seals_opens_and_signs_a_bridge() {
    let mut secret = [0u8; 32];
    let mut public = [0u8; 32];
    let mut sealed = [0u8; account::SEALED_LEN];
    let mut sealed_len = 0usize;
    let mut opened = [0u8; 32];
    let mut derived = [0u8; 32];
    let mut sig = [0u8; 64];
    let nonce = keyquorum::crypto::random_salt();
    let pw = password();
    let (from, to) = (c("Root.Alternative"), c("Root.Flinstone.Bob"));
    unsafe {
        assert_eq!(
            kq_account_keygen(secret.as_mut_ptr(), public.as_mut_ptr()),
            KQ_ACCOUNT_OK
        );
        assert_eq!(
            kq_account_public(secret.as_ptr(), derived.as_mut_ptr()),
            KQ_ACCOUNT_OK
        );
        assert_eq!(derived, public);
        assert_eq!(
            kq_account_seal(
                pw.as_ptr(),
                secret.as_ptr(),
                sealed.as_mut_ptr(),
                10,
                &mut sealed_len
            ),
            KQ_ACCOUNT_NO_ROOM
        );
        assert_eq!(
            kq_account_seal(
                pw.as_ptr(),
                secret.as_ptr(),
                sealed.as_mut_ptr(),
                sealed.len(),
                &mut sealed_len
            ),
            KQ_ACCOUNT_OK
        );
        assert_eq!(sealed_len, account::SEALED_LEN);
        assert_eq!(
            kq_account_open(
                pw.as_ptr(),
                sealed.as_ptr(),
                sealed_len,
                opened.as_mut_ptr()
            ),
            KQ_ACCOUNT_OK
        );
        assert_eq!(opened, secret);
        assert_eq!(
            kq_account_open(
                password().as_ptr(),
                sealed.as_ptr(),
                sealed_len,
                opened.as_mut_ptr()
            ),
            KQ_ACCOUNT_WRONG_PASSWORD
        );
        assert_eq!(
            kq_account_bridge_sign(
                KQ_ACCOUNT_BRIDGE_REQUEST,
                from.as_ptr(),
                to.as_ptr(),
                from.as_ptr(),
                nonce.as_ptr(),
                secret.as_ptr(),
                sig.as_mut_ptr()
            ),
            KQ_ACCOUNT_OK
        );
        let verify = |role| {
            kq_account_bridge_verify(
                role,
                from.as_ptr(),
                to.as_ptr(),
                from.as_ptr(),
                nonce.as_ptr(),
                public.as_ptr(),
                sig.as_ptr(),
            )
        };
        assert_eq!(verify(KQ_ACCOUNT_BRIDGE_REQUEST), 1);
        assert_eq!(verify(KQ_ACCOUNT_BRIDGE_ACCEPT), 0);
        assert_eq!(verify(3), 0);
    }
}

#[test]
fn account_calls_refuse_null_pointers() {
    let mut buf = [0u8; 64];
    unsafe {
        assert_eq!(
            kq_account_keygen(std::ptr::null_mut(), buf.as_mut_ptr()),
            KQ_ACCOUNT_INVALID
        );
        assert_eq!(
            kq_account_public(std::ptr::null(), buf.as_mut_ptr()),
            KQ_ACCOUNT_INVALID
        );
        assert_eq!(
            kq_account_open(password().as_ptr(), std::ptr::null(), 0, buf.as_mut_ptr()),
            KQ_ACCOUNT_INVALID
        );
        assert_eq!(
            kq_account_bridge_verify(
                KQ_ACCOUNT_BRIDGE_REQUEST,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null()
            ),
            0
        );
    }
}

#[test]
fn bounded_input_reads_an_exactly_sized_short_string() {
    // The CString allocation ends at its NUL. The scan must stop there, so
    // a read of `max + 1` bytes (past the allocation) is never made.
    let root = c("Root");
    assert_eq!(unsafe { input_bounded(root.as_ptr(), 64) }, Some("Root"));
}

#[test]
fn bounded_input_accepts_up_to_max_bytes_and_refuses_longer() {
    let at_max = c("abcd");
    let over = c("abcde");
    unsafe {
        assert_eq!(input_bounded(at_max.as_ptr(), 4), Some("abcd"));
        assert_eq!(input_bounded(over.as_ptr(), 4), None);
    }
}

#[test]
fn bounded_input_refuses_empty_missing_terminator_and_bad_utf8() {
    let empty = c("");
    let bad = [0xffu8, 0];
    // Four bytes, no NUL: the scan covers indices 0..=3 and then gives up.
    let unterminated = [b'a'; 4];
    unsafe {
        assert_eq!(input_bounded(empty.as_ptr(), 4), None);
        assert_eq!(input_bounded(bad.as_ptr().cast(), 4), None);
        assert_eq!(input_bounded(unterminated.as_ptr().cast(), 3), None);
    }
}

fn keypair() -> ([u8; 32], [u8; 32]) {
    let (mut secret, mut public) = ([0u8; 32], [0u8; 32]);
    assert_eq!(
        unsafe { kq_account_keygen(secret.as_mut_ptr(), public.as_mut_ptr()) },
        KQ_ACCOUNT_OK
    );
    (secret, public)
}

unsafe fn sudo_sign(
    role: c_int,
    invoker: &CString,
    authority: &CString,
    action: &[u8],
    nonce: &[u8; 16],
    secret: &[u8; 32],
) -> (c_int, [u8; 64]) {
    let mut sig = [0u8; 64];
    let rc = kq_sudo_sign(
        role,
        invoker.as_ptr(),
        authority.as_ptr(),
        action.as_ptr(),
        action.len(),
        nonce.as_ptr(),
        secret.as_ptr(),
        sig.as_mut_ptr(),
    );
    (rc, sig)
}

#[allow(clippy::too_many_arguments)]
unsafe fn sudo_verify(
    invoker: &CString,
    authority: &CString,
    action: &[u8],
    nonce: &[u8; 16],
    invoker_public: &[u8; 32],
    invoker_sig: &[u8; 64],
    authority_public: &[u8; 32],
    authority_sig: &[u8; 64],
) -> c_int {
    kq_sudo_verify(
        invoker.as_ptr(),
        authority.as_ptr(),
        action.as_ptr(),
        action.len(),
        nonce.as_ptr(),
        invoker_public.as_ptr(),
        invoker_sig.as_ptr(),
        authority_public.as_ptr(),
        authority_sig.as_ptr(),
    )
}

#[test]
fn sudo_is_co_signed_through_the_c_abi() {
    let (mine, mine_public) = keypair();
    let (root, root_public) = keypair();
    let nonce: [u8; 16] = keyquorum::crypto::random_salt();
    let (invoker, authority) = (c("Root.Flinstone"), c("Root"));
    let action = b"sudo -i";
    unsafe {
        let (rc, mine_sig) =
            sudo_sign(KQ_SUDO_INVOKER, &invoker, &authority, action, &nonce, &mine);
        assert_eq!(rc, KQ_ACCOUNT_OK);
        let (rc, root_sig) = sudo_sign(
            KQ_SUDO_AUTHORITY,
            &invoker,
            &authority,
            action,
            &nonce,
            &root,
        );
        assert_eq!(rc, KQ_ACCOUNT_OK);
        assert_eq!(
            sudo_verify(
                &invoker,
                &authority,
                action,
                &nonce,
                &mine_public,
                &mine_sig,
                &root_public,
                &root_sig
            ),
            1
        );
        // The invoker's key cannot stand in for the authority's.
        let (rc, forged) = sudo_sign(
            KQ_SUDO_AUTHORITY,
            &invoker,
            &authority,
            action,
            &nonce,
            &mine,
        );
        assert_eq!(rc, KQ_ACCOUNT_OK);
        assert_eq!(
            sudo_verify(
                &invoker,
                &authority,
                action,
                &nonce,
                &mine_public,
                &mine_sig,
                &root_public,
                &forged
            ),
            0
        );
        // An unknown role, an authority that is not an ancestor, and an empty action.
        assert_eq!(
            sudo_sign(3, &invoker, &authority, action, &nonce, &mine).0,
            KQ_ACCOUNT_INVALID
        );
        assert_eq!(
            sudo_sign(KQ_SUDO_INVOKER, &authority, &invoker, action, &nonce, &mine).0,
            KQ_ACCOUNT_INVALID
        );
        assert_eq!(
            sudo_sign(KQ_SUDO_INVOKER, &invoker, &authority, b"", &nonce, &mine).0,
            KQ_ACCOUNT_INVALID
        );
        assert_eq!(
            kq_sudo_sign(
                KQ_SUDO_INVOKER,
                invoker.as_ptr(),
                authority.as_ptr(),
                action.as_ptr(),
                account::SUDO_ACTION_MAX + 1,
                nonce.as_ptr(),
                mine.as_ptr(),
                [0u8; 64].as_mut_ptr(),
            ),
            KQ_ACCOUNT_INVALID
        );
        assert_eq!(
            kq_sudo_verify(
                invoker.as_ptr(),
                authority.as_ptr(),
                core::ptr::null(),
                action.len(),
                nonce.as_ptr(),
                mine_public.as_ptr(),
                mine_sig.as_ptr(),
                root_public.as_ptr(),
                root_sig.as_ptr(),
            ),
            0
        );
    }
}
