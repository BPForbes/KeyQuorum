/*
 * keyquorum_identity.h - C ABI for KeyQuorum's account heritage (ffi/identity).
 *
 * Link against libkeyquorum_identity.a. Buffers are caller-owned, and a key
 * id written into `out` is NUL terminated. Nothing is stored and no clock is
 * read; the account key functions read the operating system's random source.
 * Keep in step with ffi/identity/src/ffi/mod.rs.
 */
#ifndef KEYQUORUM_IDENTITY_H
#define KEYQUORUM_IDENTITY_H

#include <stddef.h>

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

#ifdef __cplusplus
}
#endif

#endif /* KEYQUORUM_IDENTITY_H */
