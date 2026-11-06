/*
 * keyquorum_bridge.h - C ABI for a private-bridge proof without a database
 * (ffi/identity, the same libkeyquorum_identity.a as keyquorum_identity.h).
 * Added in KQ_FILE_ABI_VERSION 4. The KQ_BRIDGE_* codes below are proof statuses; the factor
 * a login demands (KQ_ACCESS_*, which of them needs a bridge proof) is keyquorum_access.h.
 *
 * A private bridge is a roster of member accounts, each with a personal signing key
 * and a sealed copy of the bridge's secret key. To cross it a member proves who they
 * are: the caller issues a fresh challenge, the member opens their slot token
 * (kq_slot_open, keyquorum_slots.h), kq_bridge_prove signs the challenge with the
 * bridge secret and the member's own signing key from caller-supplied facts (it does
 * not establish that those facts are a trusted live roster), and kq_bridge_verify
 * checks the artifact against the live bridge's facts the caller holds. A copied
 * token without its passphrase cannot produce a proof. Only a local member, whose
 * sealed bridge key this store holds, can prove.
 *
 * Liveness is in the facts: kq_bridge_verify refuses an artifact from another
 * generation, salt or bridge, a destroyed bridge, a signer or verifier that is not a
 * member, and a key that disagrees with the roster. Removing a member bumps the
 * generation, so crossing ends at once with no revocation list. Whether the bridge's
 * ends reach an actor and a scope is kq_bridge_connects (keyquorum_identity.h).
 * Creating or removing a bridge is KeyQuorum's own tooling and is not exported here.
 *
 * Keep in step with ffi/identity/src/ffi/bridge.rs.
 */
#ifndef KEYQUORUM_BRIDGE_H
#define KEYQUORUM_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KQ_BRIDGE_OK        0
#define KQ_BRIDGE_INVALID (-1)  /* a bad argument, or an artifact that does not decode */
#define KQ_BRIDGE_NO_ROOM (-3)  /* *artifact_len is the size needed */
#define KQ_BRIDGE_REFUSED (-5)  /* not a member, or a key or signature does not match */
#define KQ_BRIDGE_STALE   (-6)  /* another generation, salt or bridge, or destroyed */

/* Sign `challenge` as bridge member local_label. sealed_bridge_key and wrap_salt are the
 * member's sealed copy of the bridge secret and the salt stored with it. The artifact is
 * written to artifact_out (cap bytes; *artifact_len is its size). */
int kq_bridge_prove(const char *uid, uint32_t generation, const unsigned char salt[16],
                    const unsigned char bridge_public[32], const char *local_label,
                    const unsigned char *sealed_bridge_key, size_t slen,
                    const unsigned char wrap_salt[16],
                    const unsigned char encryption_sk[32], const unsigned char signing_sk[32],
                    const unsigned char *challenge, size_t clen,
                    unsigned char *artifact_out, size_t cap, size_t *artifact_len);

/* Verify an artifact against the live bridge: uid, generation, salt, bridge_public and
 * destroyed (non-zero when gone), and its Member roster as nmembers labels
 * (member_labels, NUL-terminated) with their signing keys (member_signing_pubs,
 * 32 bytes each, same order; at most 256 members). verifier_label must be a member. */
int kq_bridge_verify(const char *uid, uint32_t generation, const unsigned char salt[16],
                     const unsigned char bridge_public[32], int destroyed,
                     const char *const *member_labels,
                     const unsigned char *member_signing_pubs, size_t nmembers,
                     const char *verifier_label,
                     const unsigned char *challenge, size_t clen,
                     const unsigned char *artifact, size_t alen);

#ifdef __cplusplus
}
#endif

#endif /* KEYQUORUM_BRIDGE_H */
