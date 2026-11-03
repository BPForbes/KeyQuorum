/*
 * keyquorum_identity.h - C ABI for KeyQuorum's account heritage (ffi/identity).
 *
 * Link against libkeyquorum_identity.a. Buffers are caller-owned, and a key
 * id written into `out` is NUL terminated. Nothing is stored and no clock is
 * read; the account key functions take their randomness from the operating
 * system in the hosted ("std") build and from the embedder's
 * kq_platform_random() in the freestanding build (see the section at the end).
 * Keep in step with ffi/identity/src/ffi/mod.rs.
 */
#ifndef KEYQUORUM_IDENTITY_H
#define KEYQUORUM_IDENTITY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KQ_HERITAGE_OK          0
#define KQ_HERITAGE_INVALID    (-1)
#define KQ_HERITAGE_TOO_DEEP   (-2)
#define KQ_HERITAGE_NO_ROOM    (-3)

#define KQ_HERITAGE_ROOT       "Root"
#define KQ_HERITAGE_MAX_DEPTH  8u
#define KQ_HERITAGE_KEY_ID_MAX 256u

int kq_heritage_segment_valid(const char *name);
int kq_heritage_name_available(const char *name);
int kq_heritage_key_valid(const char *key);
size_t kq_heritage_depth(const char *key);
int kq_heritage_child(const char *parent, const char *name, char *out, size_t cap);
int kq_heritage_parent(const char *key, char *out, size_t cap);
int kq_heritage_is_ancestor_or_self(const char *a, const char *b);
int kq_heritage_relation(const char *a, const char *b);

/* 1 when a bridge between end_a and end_b connects actor to scope (one end holds the
 * actor or an ancestor of it, the other sits on the scope's line: the scope, an
 * ancestor of it, or a node inside it), else 0. Judges only the shape of the
 * hierarchy, one hop (bridges do not chain); that the bridge exists and is live is the
 * caller's check (kq_bridge_verify, keyquorum_bridge.h). */
int kq_bridge_connects(const char *end_a, const char *end_b, const char *actor,
                       const char *scope);
int kq_heritage_home_rel(const char *key, char *out, size_t cap);

/*
 * Account keys: one Ed25519 signing key per account, sealed under the
 * account's password (KQAK v1, KQ_ACCOUNT_SEALED_LEN bytes), and the
 * signatures on account bridges. Secrets are 32 bytes, public keys 32,
 * signatures 64, bridge nonces 16. The caller wipes every secret buffer.
 *
 * Bridge halves are refused unless the signer may sign them: from and to are
 * valid key ids on different branches, a request is signed by from, and an
 * acceptance by to or an ancestor of it (sign returns KQ_ACCOUNT_INVALID,
 * verify returns 0).
 */
#define KQ_ACCOUNT_OK              0
#define KQ_ACCOUNT_INVALID        (-1)
#define KQ_ACCOUNT_NO_ROOM        (-3)
#define KQ_ACCOUNT_WRONG_PASSWORD (-4)

#define KQ_ACCOUNT_SECRET_LEN      32u
#define KQ_ACCOUNT_PUBLIC_LEN      32u
#define KQ_ACCOUNT_SIGNATURE_LEN   64u
#define KQ_ACCOUNT_NONCE_LEN       16u
#define KQ_ACCOUNT_SEALED_LEN      81u

#define KQ_ACCOUNT_BRIDGE_REQUEST  1
#define KQ_ACCOUNT_BRIDGE_ACCEPT   2

int kq_account_keygen(unsigned char *secret_out, unsigned char *public_out);
int kq_account_public(const unsigned char *secret, unsigned char *public_out);
/* Box key (X25519): what file letters are sealed to. Seal its secret with
 * kq_account_seal like the signing key; the caller wipes secret_out. */
int kq_account_box_keygen(unsigned char secret_out[32], unsigned char public_out[32]);
int kq_account_box_public(const unsigned char secret[32], unsigned char public_out[32]);
int kq_account_seal(const char *password, const unsigned char *secret,
                    unsigned char *out, size_t cap, size_t *out_len);
int kq_account_open(const char *password, const unsigned char *sealed, size_t len,
                    unsigned char *secret_out);
int kq_account_bridge_sign(int role, const char *from, const char *to, const char *signer,
                           const unsigned char *nonce, const unsigned char *secret,
                           unsigned char *sig_out);
int kq_account_bridge_verify(int role, const char *from, const char *to, const char *signer,
                             const unsigned char *nonce, const unsigned char *public_key,
                             const unsigned char *sig);

/*
 * Embedder must provide (freestanding build, `--no-default-features`)
 *
 * Without the "std" feature libkeyquorum_identity.a leaves exactly these four
 * symbols undefined (on x86_64-unknown-none that is all; on thumbv7em-none-eabi also
 * the libc routines fma, fmaximum_num, fminimum_num, memcmp and strlen; see
 * docs/operator/embedding-no-std.md). The hosted build defines none of them and
 * does not need them.
 *
 * None of them may be called back into KeyQuorum, and all must be safe to call
 * from any thread the embedder runs KeyQuorum on.
 */

/*
 * Fill buf[0..len) with cryptographically secure random bytes and return 0.
 * Return non-zero if that cannot be done (entropy not yet seeded, device
 * error): the library then panics, so the check fails closed. Never write
 * predictable bytes and return 0. len is never 0 (an empty request makes no
 * call). Seeds salts, nonces, data keys and key pairs.
 */
int kq_platform_random(uint8_t *buf, size_t len);

/*
 * Return len bytes of heap aligned to `align` (a power of two), or NULL when
 * none is available (the library then panics through kq_platform_panic). The
 * memory need not be zeroed.
 */
uint8_t *kq_platform_alloc(size_t len, size_t align);

/*
 * Release memory obtained from kq_platform_alloc with the same len and align.
 * Secrets the library owns are held in zeroizing buffers and wiped before this
 * call, but copies can pass through other allocations; the embedder should zero
 * freed memory (or return it to a pool that is zeroed on reuse).
 */
void kq_platform_free(uint8_t *ptr, size_t len, size_t align);

/*
 * A panic inside the library (an allocation failure, a failed
 * kq_platform_random, a broken invariant) calls this. It must never return:
 * fail the check closed (deny the login or access in progress, halt, or
 * reset). Spinning silently on a login path is a denial of service. The
 * library is built with panic=abort and never unwinds through C.
 */
#ifdef __cplusplus
[[noreturn]] void kq_platform_panic(void);
#else
_Noreturn void kq_platform_panic(void);
#endif

#ifdef __cplusplus
}
#endif

#endif /* KEYQUORUM_IDENTITY_H */
