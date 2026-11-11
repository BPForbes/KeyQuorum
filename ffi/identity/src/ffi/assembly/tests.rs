use super::*;
use keyquorum::{keys, signing};
use std::ffi::CString;

struct Child {
    label: CString,
    public: [u8; 32],
    secret: [u8; 32],
    device: [u8; 16],
}

fn children(n: usize) -> Vec<Child> {
    (0..n)
        .map(|i| {
            let (secret, public) = keys::generate_encryption_keypair();
            Child {
                label: CString::new(format!("Root.M.A.{i}")).unwrap(),
                public,
                secret: *secret,
                device: [i as u8 + 1; 16],
            }
        })
        .collect()
}

fn seed() -> [u8; 32] {
    *keys::generate_signing_keypair().0
}

fn split(seed: &[u8; 32], gen: u32, ch: &[Child]) -> (c_int, Vec<u8>) {
    let labels: Vec<*const c_char> = ch.iter().map(|c| c.label.as_ptr()).collect();
    let publics: Vec<[u8; 32]> = ch.iter().map(|c| c.public).collect();
    let mut out = vec![0u8; 4096];
    let mut len = 0usize;
    let rc = unsafe {
        kq_assembly_split(
            seed.as_ptr(),
            gen,
            labels.as_ptr(),
            publics.as_ptr(),
            ch.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut len,
        )
    };
    out.truncate(len);
    (rc, out)
}

fn assemble(
    a: &[u8],
    parent_public: &[u8; 32],
    ch: &[&Child],
    min_devices: usize,
) -> (c_int, [u8; 32]) {
    let labels: Vec<*const c_char> = ch.iter().map(|c| c.label.as_ptr()).collect();
    let secrets: Vec<[u8; 32]> = ch.iter().map(|c| c.secret).collect();
    let devices: Vec<[u8; 16]> = ch.iter().map(|c| c.device).collect();
    // A non-zero sentinel: a failure path that clears the output would still pass on zeroes.
    let mut out = [0x5Au8; 32];
    let rc = unsafe {
        kq_assembly_assemble(
            a.as_ptr(),
            a.len(),
            parent_public.as_ptr(),
            labels.as_ptr(),
            secrets.as_ptr(),
            devices.as_ptr(),
            ch.len(),
            min_devices,
            out.as_mut_ptr(),
        )
    };
    (rc, out)
}

#[test]
fn threshold_follows_the_rule() {
    let got: Vec<c_uint> = (0..=10).map(|h| kq_assembly_threshold(h)).collect();
    assert_eq!(got, [0, 1, 2, 2, 3, 3, 4, 5, 5, 6, 7]);
    assert_eq!(kq_assembly_threshold(255), 170);
    assert_eq!(kq_assembly_threshold(256), 0);
}

#[test]
fn split_then_assemble_round_trips() {
    let s = seed();
    let public = signing::public_key(&s);
    let ch = children(3);
    let (rc, a) = split(&s, 7, &ch);
    assert_eq!(rc, KQ_ASSEMBLY_OK);
    let mut generation = 0;
    assert_eq!(
        unsafe { kq_assembly_generation(a.as_ptr(), a.len(), &mut generation) },
        KQ_ASSEMBLY_OK
    );
    assert_eq!(generation, 7);
    // 3 holders need 2.
    let (rc, out) = assemble(&a, &public, &[&ch[0], &ch[2]], 0);
    assert_eq!(rc, KQ_ASSEMBLY_OK);
    assert_eq!(out, s);
    let (rc, out) = assemble(&a, &public, &[&ch[0], &ch[1], &ch[2]], 3);
    assert_eq!((rc, out), (KQ_ASSEMBLY_OK, s));
}

#[test]
fn one_child_is_a_one_of_one_assembly() {
    let s = seed();
    let ch = children(1);
    let (rc, a) = split(&s, 0, &ch);
    assert_eq!(rc, KQ_ASSEMBLY_OK);
    assert_eq!(assemble(&a, &signing::public_key(&s), &[&ch[0]], 0), (0, s));
}

#[test]
fn no_children_is_none_and_writes_nothing() {
    let s = seed();
    let mut len = 99usize;
    let mut out = [0x5Au8; 8];
    let rc = unsafe {
        kq_assembly_split(
            s.as_ptr(),
            0,
            core::ptr::null(),
            core::ptr::null(),
            0,
            out.as_mut_ptr(),
            out.len(),
            &mut len,
        )
    };
    assert_eq!(rc, KQ_ASSEMBLY_NONE);
    assert_eq!((len, out), (99, [0x5A; 8]));
}

#[test]
fn quorum_not_met_and_too_few_devices() {
    let s = seed();
    let public = signing::public_key(&s);
    let ch = children(2);
    let (_, a) = split(&s, 0, &ch);
    let (rc, out) = assemble(&a, &public, &[&ch[0]], 0);
    assert_eq!((rc, out), (KQ_ASSEMBLY_QUORUM, [0x5A; 32]));
    // Two shares, one device, two required.
    let mut same = children(2);
    same[1].device = same[0].device;
    let (_, b) = split(&s, 0, &same);
    let (rc, out) = assemble(&b, &public, &[&same[0], &same[1]], 2);
    assert_eq!((rc, out), (KQ_ASSEMBLY_QUORUM, [0x5A; 32]));
    assert_eq!(assemble(&b, &public, &[&same[0], &same[1]], 1).0, 0);
}

#[test]
fn another_parents_key_is_a_mismatch() {
    let s = seed();
    let ch = children(2);
    let (_, a) = split(&s, 0, &ch);
    let other = signing::public_key(&seed());
    let (rc, out) = assemble(&a, &other, &[&ch[0], &ch[1]], 0);
    assert_eq!((rc, out), (KQ_ASSEMBLY_MISMATCH, [0x5A; 32]));
}

#[test]
fn a_small_buffer_gets_no_room_and_the_size() {
    let s = seed();
    let ch = children(2);
    let (_, full) = split(&s, 0, &ch);
    let labels: Vec<*const c_char> = ch.iter().map(|c| c.label.as_ptr()).collect();
    let publics: Vec<[u8; 32]> = ch.iter().map(|c| c.public).collect();
    let mut out = [0u8; 4];
    let mut len = 0usize;
    let rc = unsafe {
        kq_assembly_split(
            s.as_ptr(),
            0,
            labels.as_ptr(),
            publics.as_ptr(),
            2,
            out.as_mut_ptr(),
            out.len(),
            &mut len,
        )
    };
    assert_eq!((rc, len), (KQ_ASSEMBLY_NO_ROOM, full.len()));
    assert_eq!(out, [0; 4]);
}

#[test]
fn null_and_overlapping_pointers_are_invalid() {
    let s = seed();
    let ch = children(2);
    let labels: Vec<*const c_char> = ch.iter().map(|c| c.label.as_ptr()).collect();
    let publics: Vec<[u8; 32]> = ch.iter().map(|c| c.public).collect();
    let mut out = vec![0u8; 4096];
    let mut len = 0usize;
    let call =
        |seed: *const u8,
         l: *const *const c_char,
         p: *const [u8; 32],
         o: *mut u8,
         ol: *mut usize| unsafe { kq_assembly_split(seed, 0, l, p, 2, o, 4096, ol) };
    assert_eq!(
        call(
            core::ptr::null(),
            labels.as_ptr(),
            publics.as_ptr(),
            out.as_mut_ptr(),
            &mut len
        ),
        KQ_ASSEMBLY_INVALID
    );
    assert_eq!(
        call(
            s.as_ptr(),
            core::ptr::null(),
            publics.as_ptr(),
            out.as_mut_ptr(),
            &mut len
        ),
        KQ_ASSEMBLY_INVALID
    );
    assert_eq!(
        call(
            s.as_ptr(),
            labels.as_ptr(),
            core::ptr::null(),
            out.as_mut_ptr(),
            &mut len
        ),
        KQ_ASSEMBLY_INVALID
    );
    assert_eq!(
        call(
            s.as_ptr(),
            labels.as_ptr(),
            publics.as_ptr(),
            out.as_mut_ptr(),
            core::ptr::null_mut()
        ),
        KQ_ASSEMBLY_INVALID
    );
    // The output overlaps the seed.
    let mut buf = vec![0u8; 4096];
    buf[..32].copy_from_slice(&s);
    let ptr = buf.as_mut_ptr();
    assert_eq!(
        call(ptr, labels.as_ptr(), publics.as_ptr(), ptr, &mut len),
        KQ_ASSEMBLY_INVALID
    );
    // A null label, and a repeated label.
    let bad = [core::ptr::null(), labels[1]];
    assert_eq!(
        call(
            s.as_ptr(),
            bad.as_ptr(),
            publics.as_ptr(),
            out.as_mut_ptr(),
            &mut len
        ),
        KQ_ASSEMBLY_INVALID
    );
    let dup = [labels[0], labels[0]];
    assert_eq!(
        call(
            s.as_ptr(),
            dup.as_ptr(),
            publics.as_ptr(),
            out.as_mut_ptr(),
            &mut len
        ),
        KQ_ASSEMBLY_INVALID
    );

    // Assemble: null seed_out, null assembly, overlap of seed_out with the secrets.
    let public = signing::public_key(&s);
    let (_, a) = split(&s, 0, &ch);
    let secrets: Vec<[u8; 32]> = ch.iter().map(|c| c.secret).collect();
    let devices: Vec<[u8; 16]> = ch.iter().map(|c| c.device).collect();
    let mut seed_out = [0u8; 32];
    let run = |a_ptr: *const u8, alen: usize, o: *mut u8, sec: *const [u8; 32]| unsafe {
        kq_assembly_assemble(
            a_ptr,
            alen,
            public.as_ptr(),
            labels.as_ptr(),
            sec,
            devices.as_ptr(),
            2,
            0,
            o,
        )
    };
    assert_eq!(
        run(a.as_ptr(), a.len(), core::ptr::null_mut(), secrets.as_ptr()),
        KQ_ASSEMBLY_INVALID
    );
    assert_eq!(
        run(
            core::ptr::null(),
            a.len(),
            seed_out.as_mut_ptr(),
            secrets.as_ptr()
        ),
        KQ_ASSEMBLY_INVALID
    );
    assert_eq!(
        run(
            a.as_ptr(),
            a.len(),
            seed_out.as_mut_ptr(),
            core::ptr::null()
        ),
        KQ_ASSEMBLY_INVALID
    );
    let mut sec_mut = secrets.clone();
    let sec_ptr = sec_mut.as_mut_ptr();
    assert_eq!(
        run(a.as_ptr(), a.len(), sec_ptr.cast(), sec_ptr),
        KQ_ASSEMBLY_INVALID
    );
    assert_eq!(seed_out, [0; 32]);
}

#[test]
fn bounds_and_damaged_assemblies_are_invalid() {
    let s = seed();
    let public = signing::public_key(&s);
    let ch = children(2);
    let (_, a) = split(&s, 0, &ch);
    // Too many children, too many unlocked, an oversized or truncated assembly.
    let labels: Vec<*const c_char> = ch.iter().map(|c| c.label.as_ptr()).collect();
    let publics: Vec<[u8; 32]> = ch.iter().map(|c| c.public).collect();
    let mut out = [0u8; 16];
    let mut len = 0usize;
    let rc = unsafe {
        kq_assembly_split(
            s.as_ptr(),
            0,
            labels.as_ptr(),
            publics.as_ptr(),
            256,
            out.as_mut_ptr(),
            16,
            &mut len,
        )
    };
    assert_eq!(rc, KQ_ASSEMBLY_INVALID);
    let secrets: Vec<[u8; 32]> = ch.iter().map(|c| c.secret).collect();
    let devices: Vec<[u8; 16]> = ch.iter().map(|c| c.device).collect();
    let mut seed_out = [0u8; 32];
    let mut go = |bytes: &[u8], n: usize| unsafe {
        kq_assembly_assemble(
            bytes.as_ptr(),
            bytes.len(),
            public.as_ptr(),
            labels.as_ptr(),
            secrets.as_ptr(),
            devices.as_ptr(),
            n,
            0,
            seed_out.as_mut_ptr(),
        )
    };
    assert_eq!(go(&a, 256), KQ_ASSEMBLY_INVALID);
    assert_eq!(go(&a[..a.len() - 1], 2), KQ_ASSEMBLY_INVALID);
    assert_eq!(go(&vec![0u8; 1 << 20], 2), KQ_ASSEMBLY_INVALID);
    assert_eq!(go(&[], 2), KQ_ASSEMBLY_INVALID);
    let mut gen = 0;
    assert_eq!(
        unsafe { kq_assembly_generation(a.as_ptr(), 3, &mut gen) },
        KQ_ASSEMBLY_INVALID
    );
    assert_eq!(
        unsafe { kq_assembly_generation(a.as_ptr(), a.len(), core::ptr::null_mut()) },
        KQ_ASSEMBLY_INVALID
    );
    assert_eq!(seed_out, [0; 32]);
}
