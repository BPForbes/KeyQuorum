/*
 * keyquorum_error.h - C ABI for KQER error reports (ffi/identity, the same
 * libkeyquorum_identity.a as keyquorum_identity.h and keyquorum_files.h).
 * Added in KQ_FILE_ABI_VERSION 3. Return codes are the KQ_FILE_* codes of
 * keyquorum_files.h.
 *
 * A KQER is a signed report about one artifact (a delivered package) that was
 * refused or failed, written next to it as a sidecar named by the artifact's
 * SHA-256. It holds no free text: a code and a class from closed sets, the
 * artifact's SHA-256, the reporter's label, a UTC time and optionally one
 * count or policy word (shares, threshold, devices, minimum_devices). A report
 * is a claim by its signer: kq_error_inject checks the signature and that it
 * names the artifact the caller holds, then records an ErrorReported event
 * (history event 48) in the tracked file. It decides no trust.
 *
 * Keep in step with ffi/identity/src/ffi/error.rs.
 */
#ifndef KEYQUORUM_ERROR_H
#define KEYQUORUM_ERROR_H

#include <stddef.h>
#include <stdint.h>

#include "keyquorum_files.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Error codes (append only): 1 Framing, 2 Untrusted, 3 Integrity, 4 Replayed,
 * 5 NotNewer, 6 Forked, 7 BelowThreshold, 8 Denied. Classes (append only):
 * 1 framing, 2 auth, 3 integrity, 4 freshness, 5 policy, 6 storage,
 * 7 resource, 8 internal. */

/* The static name of an error code ("Integrity"), or NULL if unknown. */
const char *kq_error_name(uint16_t code);

/* The fixed word of an error class ("integrity"), or NULL if unknown. */
const char *kq_error_class_name(uint8_t class_code);

/* Write a signed KQER to out (cap bytes; *out_len is its size, KQ_FILE_NO_ROOM
 * when out is NULL or too small). object_ref is the 32-byte SHA-256 of the
 * failed artifact, never its content. actor_label is the reporter's label
 * ([A-Za-z0-9._-], at most 64), occurred_at UTC text such as
 * "2026-11-03T10:00:00Z". detail_key and detail_value are one optional pair,
 * both NULL for none: the key one of shares, threshold, devices,
 * minimum_devices, the value at most 16 characters of [a-z0-9_-].
 * KQ_FILE_INVALID for anything else (free text, an unknown code or class). */
int kq_error_sign(uint16_t code, uint8_t class_code, uint8_t step,
                  const unsigned char object_ref[32],
                  const char *actor_label, const char *occurred_at,
                  const char *detail_key, const char *detail_value,
                  const unsigned char signing_secret[32],
                  unsigned char *out, size_t cap, size_t *out_len);

/* Verify a sidecar and append an ErrorReported event (48) to the KQTF, writing
 * the changed container to out. KQ_FILE_OK, or KQ_FILE_INVALID when the
 * container or sidecar is malformed, the signature does not verify under
 * reporter_public, or the report does not name pkg_sha256 (nothing is
 * written then). */
int kq_error_inject(const unsigned char *kqtf, size_t klen,
                    const unsigned char *kqer, size_t elen,
                    const unsigned char reporter_public[32],
                    const unsigned char pkg_sha256[32],
                    unsigned char *out, size_t cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* KEYQUORUM_ERROR_H */
