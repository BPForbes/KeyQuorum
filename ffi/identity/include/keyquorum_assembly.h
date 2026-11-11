/*
 * keyquorum_assembly.h - C ABI for parent-key assembly (ffi/identity, the same
 * libkeyquorum_identity.a as keyquorum_identity.h). Added in KQ_FILE_ABI_VERSION 6
 * ("6 added kq_assembly_*").
 *
 * HOSTED BUILD ONLY. The assembly uses the Shamir library (blahaj), which the
 * freestanding (no_std) build does not link: these functions exist only in the
 * archive built with the default `std` feature. The freestanding archive is unchanged
 * and does not export them.
 *
 * A parent account's 32-byte signing seed is split among its children (M.A.1 and
 * M.A.2 assemble M.A). Each child holds one share sealed to its own X25519 box key.
 * The threshold is fixed by the number of holders, never chosen: 1 for one holder,
 * 2 for two, then round(2x/3). The assembly is the KQAS record `kq_assembly_split`
 * writes; it is safe to store (every share is sealed). No database is involved: the
 * caller passes the facts its own registry holds.
 *
 * Assembly accepts the recovered seed only if it derives the parent's signing public
 * key the caller passes (sealed shares are anonymous, so this stops a planted share).
 * When a child is revoked the parent reissues: rotate its signing key and split the
 * new seed at generation + 1 (re-splitting the old seed would leave the revoked
 * child's share valid).
 *
 * Keep in step with ffi/identity/src/ffi/assembly.rs.
 */
#ifndef KEYQUORUM_ASSEMBLY_H
#define KEYQUORUM_ASSEMBLY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KQ_ASSEMBLY_OK 0
#define KQ_ASSEMBLY_INVALID -1
#define KQ_ASSEMBLY_NO_ROOM -3
#define KQ_ASSEMBLY_QUORUM -5      /* too few usable shares or too few devices */
#define KQ_ASSEMBLY_MISMATCH -6    /* recovered seed is not the parent's */
#define KQ_ASSEMBLY_NONE 1         /* split: no children, no assembly (nothing written) */

/* The threshold for `holders` children: 1, 2, 2, 3, 3, 4, 5, 5, 6, 7 ... for 1, 2, 3 ...
 * holders (170 at 255). 0 = none (no holders, or more than 255). */
unsigned kq_assembly_threshold(unsigned holders);

/* Deal `seed` among `nchildren` (at most 255) children at `generation`, sealing one share
 * to each child_box_public[i] under child_labels[i] (distinct, 1 to 255 bytes). Writes the
 * KQAS bytes to `out` if `cap` suffices; *out_len always gets the size (KQ_ASSEMBLY_NO_ROOM
 * if cap is too small). KQ_ASSEMBLY_NONE for nchildren == 0 (nothing written).
 * KQ_ASSEMBLY_INVALID for a null or overlapping pointer or a bad label or key. */
int kq_assembly_split(const unsigned char seed[32], unsigned generation,
                      const char *const *child_labels,
                      const unsigned char (*child_box_public)[32], size_t nchildren,
                      unsigned char *out, size_t cap, size_t *out_len);

/* The generation of an encoded assembly. KQ_ASSEMBLY_INVALID if it does not decode. */
int kq_assembly_generation(const unsigned char *assembly, size_t alen,
                           unsigned *generation_out);

/* Assemble the parent's seed from the unlocked children (label, X25519 secret that opens
 * its share, 16-byte id of its device; at most 255). The threshold must be met from at
 * least minimum_devices distinct devices (0 or 1 adds no rule) and the seed must derive
 * parent_signing_public. KQ_ASSEMBLY_QUORUM for too few usable shares or devices,
 * KQ_ASSEMBLY_MISMATCH for a seed that is not the parent's, KQ_ASSEMBLY_INVALID for a bad
 * argument or an assembly that does not decode. Writes seed_out (32 bytes; the caller
 * wipes it) and nothing unless KQ_ASSEMBLY_OK. */
int kq_assembly_assemble(const unsigned char *assembly, size_t alen,
                         const unsigned char parent_signing_public[32],
                         const char *const *unlocked_labels,
                         const unsigned char (*unlocked_box_secret)[32],
                         const unsigned char (*unlocked_device_id)[16], size_t nunlocked,
                         size_t minimum_devices, unsigned char seed_out[32]);

#ifdef __cplusplus
}
#endif

#endif /* KEYQUORUM_ASSEMBLY_H */
