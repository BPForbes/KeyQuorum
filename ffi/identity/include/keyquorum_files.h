/*
 * keyquorum_files.h - C ABI for KeyQuorum tracked files and co-signed delivery
 * (ffi/identity, the same libkeyquorum_identity.a as keyquorum_identity.h).
 *
 * A container is the encoded KQTF bytes. Functions decode it, work in memory
 * and write any changed container into a caller buffer: `out` (cap bytes)
 * receives it and `*out_len` its size; when `out` is null or too small the
 * call returns KQ_FILE_NO_ROOM with `*out_len` set to the size needed, so a
 * caller can ask once to size and again to fill. Nothing is stored and no
 * clock is read: times are UTC text such as "2026-10-20T13:00:00.000Z".
 *
 * Trust is never taken from a container: the caller passes the signing keys
 * its own registry holds for each label (kq_file_trust_t). A label's 16-byte
 * identity is kq_file_label_identity.
 *
 * Co-signed delivery (author A, recipient B):
 *   A: kq_file_check_in (signs) -> kq_file_offer (public part, no content)
 *      -> kq_file_seal_letter (content sealed to B's box key)
 *   host: kq_file_offer_verify (A) and kq_file_coauthor_verify (B) over the
 *      offer; it never holds the content or a decryption key
 *   B: kq_file_coauthor_sign (before release) -> kq_file_open_letter
 *      -> kq_file_attach_coauthor -> kq_file_readiness == KQ_FILE_OK
 *
 * Keep in step with ffi/identity/src/ffi/files.rs.
 */
#ifndef KEYQUORUM_FILES_H
#define KEYQUORUM_FILES_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KQ_FILE_OK               0
#define KQ_FILE_INVALID        (-1)
#define KQ_FILE_NO_ROOM        (-3)
#define KQ_FILE_UNTRUSTED      (-5)
#define KQ_FILE_FORKED         (-6)
#define KQ_FILE_NOT_NEWER      (-7)
#define KQ_FILE_REPLAYED       (-8)
#define KQ_FILE_NO_REVISION    (-10)
#define KQ_FILE_BELOW_THRESHOLD (-11)
#define KQ_FILE_FIRST            1
#define KQ_FILE_NEWER            2

#define KQ_FILE_ABI_VERSION      1
#define KQ_FILE_ID_LEN          16u
#define KQ_FILE_REV_LEN         32u
#define KQ_FILE_DELIVERY_ID_LEN 16u
#define KQ_FILE_SIG_LEN         64u

/* A signing key the caller's registry holds for a label. */
typedef struct {
    const char *label;
    unsigned char signing_public[32];
} kq_file_key_t;

typedef struct {
    const kq_file_key_t *keys;
    size_t nkeys;
} kq_file_trust_t;

/* The public part of an author-signed revision: what the author's signature
 * covers, with no content. Safe to give the host. */
typedef struct {
    unsigned char file_id[16];
    unsigned char revision_id[32];
    unsigned char content_commitment[32];
    unsigned char author_identity[16];
    unsigned char author_signature[64];
    uint64_t topology_generation;
    unsigned char policy_hash[32];
} kq_file_offer_t;

int kq_file_abi_version(void);
int kq_file_label_identity(const char *label, unsigned char id_out[16]);

/* A new file with no revisions, owned by scope_root under the standard policy. */
int kq_file_new(const unsigned char file_id[16], const char *name, const char *scope_root,
                unsigned char *out, size_t cap, size_t *out_len);
/* Check in payload by author on the current head and sign it. KQ_FILE_FORKED
 * on two heads. */
int kq_file_check_in(const unsigned char *c, size_t clen, const char *author,
                     const char *created_at_utc, const unsigned char *payload, size_t plen,
                     const unsigned char secret[32], unsigned char *out, size_t cap,
                     size_t *out_len, unsigned char rev_out[32]);
int kq_file_verify(const unsigned char *c, size_t clen, unsigned char root_out[32]);
int kq_file_head(const unsigned char *c, size_t clen, unsigned char rev_out[32]);
int kq_file_payload(const unsigned char *c, size_t clen, const unsigned char rev[32],
                    unsigned char *out, size_t cap, size_t *out_len);
/* Only rev, its ancestors and their proofs. */
int kq_file_extract(const unsigned char *c, size_t clen, const unsigned char rev[32],
                    unsigned char *out, size_t cap, size_t *out_len);
/* Import incoming into local (llen 0: incoming itself). */
int kq_file_merge(const unsigned char *local, size_t llen, const unsigned char *incoming,
                  size_t ilen, const char *actor, const char *occurred_at_utc,
                  unsigned char *out, size_t cap, size_t *out_len);
/* Every author and signer label, NUL-separated: the keys trust needs. */
int kq_file_signers(const unsigned char *c, size_t clen, unsigned char *out, size_t cap,
                    size_t *out_len);

/* Co-signed delivery. */
int kq_file_offer(const unsigned char *c, size_t clen, const unsigned char rev[32],
                  kq_file_offer_t *offer_out);
int kq_file_offer_verify(const kq_file_offer_t *offer, const char *author_label,
                         const unsigned char author_public[32]);
int kq_file_coauthor_sign(const kq_file_offer_t *offer, const char *coauthor,
                          const unsigned char secret[32], unsigned char sig_out[64]);
int kq_file_coauthor_verify(const kq_file_offer_t *offer, const char *coauthor,
                            const unsigned char public_key[32], const unsigned char sig[64]);
int kq_file_attach_coauthor(const unsigned char *c, size_t clen, const kq_file_offer_t *offer,
                            const char *coauthor, const unsigned char sig[64],
                            unsigned char *out, size_t cap, size_t *out_len);
/* KQ_FILE_OK when it may fire; KQ_FILE_FORKED; KQ_FILE_BELOW_THRESHOLD. */
int kq_file_readiness(const unsigned char *c, size_t clen, const unsigned char rev[32],
                      const char *recipient, const kq_file_trust_t *trust,
                      uint32_t *potential, uint32_t *threshold);

/* Newest trusted revision among those the host accepted by the request time
 * (its own clock). KQ_FILE_FORKED; KQ_FILE_NO_REVISION. */
int kq_file_select_read(const unsigned char *c, size_t clen, const kq_file_trust_t *trust,
                        const unsigned char (*accepted)[32], size_t naccepted,
                        unsigned char rev_out[32]);

/* Seal rev to the recipient's box key, signed by sender. KQ_FILE_UNTRUSTED
 * unless rev is trusted. */
int kq_file_seal_letter(const unsigned char *c, size_t clen, const unsigned char rev[32],
                        const kq_file_trust_t *trust, const char *sender,
                        const unsigned char sender_secret[32],
                        const unsigned char sender_box_public[32], const char *recipient,
                        const unsigned char recipient_box_public[32], unsigned char *out,
                        size_t cap, size_t *out_len, unsigned char delivery_id_out[16]);
/* Open with the recipient's box secret; signed by expected_sender under
 * sender_public and addressed to expected_recipient, or KQ_FILE_UNTRUSTED. */
int kq_file_open_letter(const unsigned char *letter, size_t llen,
                        const unsigned char box_secret[32], const char *expected_sender,
                        const char *expected_recipient, const unsigned char sender_public[32],
                        unsigned char *out, size_t cap, size_t *out_len,
                        unsigned char rev_out[32], unsigned char root_out[32]);
/* Against nseen (revision, root) pairs accepted before: KQ_FILE_FIRST,
 * KQ_FILE_NEWER, KQ_FILE_REPLAYED or KQ_FILE_NOT_NEWER. */
int kq_file_freshness(const unsigned char (*seen)[64], size_t nseen, const unsigned char *c,
                      size_t clen, const unsigned char rev[32], const unsigned char root[32]);

/* The history of the container, oldest first, one line per event, tab-separated:
 *   sequence, time, type code, outcome code, actor, revision (hex or empty),
 *   details as key=value pairs joined by ';'.
 * Needs only the container, so it works offline. KQ_FILE_NO_ROOM when out is too
 * small (*out_len gets the size); KQ_FILE_INVALID for a container it cannot read. */
int kq_file_events(const unsigned char *c, size_t clen, unsigned char *out, size_t cap,
                   size_t *out_len);

/* Adds supervisor's countersignature over rev into out (the container with it).
 * KQ_FILE_INVALID when rev is unknown or has no author signature that verifies under
 * trust; KQ_FILE_NO_ROOM when out is too small (*out_len gets the size). */
int kq_file_countersign(const unsigned char *c, size_t clen, const unsigned char rev[32],
                        const char *supervisor, const unsigned char secret[32],
                        const kq_file_trust_t *trust, unsigned char *out, size_t cap,
                        size_t *out_len);

/* KQ_FILE_OK when a supervisor of the file's scope countersigned rev over the
 * author's verified signature; KQ_FILE_UNTRUSTED when none has. A checkpoint
 * requires this before it accepts a newer copy of a file it already holds. */
int kq_file_permits_newer(const unsigned char *c, size_t clen, const unsigned char rev[32],
                          const kq_file_trust_t *trust);

#ifdef __cplusplus
}
#endif

#endif /* KEYQUORUM_FILES_H */
