/*
 * keyquorum_slots.h - C ABI for opening a slot token (KQST) with only its passphrase
 * and the facts the caller's own registry holds (ffi/identity, the same
 * libkeyquorum_identity.a as keyquorum_identity.h). Added in KQ_FILE_ABI_VERSION 4. Return codes are the
 * KQ_ACCOUNT_* codes of keyquorum_identity.h.
 *
 * A KQST holds one identity's secret keys wrapped under a passphrase and sealed to
 * the id of the device (USB) it lives on. This needs no device.kq, directory or
 * database: the caller passes the device id and the two public keys it expects for
 * the slot, from its own record of the account, never from the token.
 *
 * kq_slot_seal (KQ_FILE_ABI_VERSION 7) makes a token from an account's own keys, so
 * an embedder can enrol an account without the keyquorum-device CLI and without
 * changing the account's keys.
 *
 * Keep in step with ffi/identity/src/ffi/slot.rs.
 */
#ifndef KEYQUORUM_SLOTS_H
#define KEYQUORUM_SLOTS_H

#include <stddef.h>
#include <stdint.h>

#include "keyquorum_identity.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Open the token: KQ_ACCOUNT_OK and the 32-byte signing and encryption secrets in the
 * two outputs (the caller wipes them); KQ_ACCOUNT_WRONG_PASSWORD for a wrong
 * passphrase; KQ_ACCOUNT_INVALID for a malformed token, or a label, device id or
 * public key that does not match. Nothing is written unless OK. */
int kq_slot_open(const unsigned char *kqst, size_t klen, const char *label,
                 const char *passphrase,
                 const unsigned char expected_device_id[16],
                 const unsigned char expected_signing_pub[32],
                 const unsigned char expected_encryption_pub[32],
                 unsigned char signing_secret_out[32],
                 unsigned char encryption_secret_out[32]);

/* Size of the token kq_slot_seal makes for a label of label_len bytes. */
#define KQ_SLOT_TOKEN_LEN(label_len) ((size_t)(4 + 1 + 16 + 12 + 16 + 2 + 16 + 32 + 32) + (size_t)(label_len))

/* Seal the account label's own keys (a valid key id; its 32-byte Ed25519 signing secret
 * and X25519 encryption secret) with passphrase to the device device_id, into a KQST
 * written to token_out (length in *token_len), with the two public keys derived from the
 * secrets, which the caller records in its own registry and passes to kq_slot_open later.
 * KQ_ACCOUNT_OK; KQ_ACCOUNT_NO_ROOM when cap is too small (*token_len then holds the size
 * needed, KQ_SLOT_TOKEN_LEN(strlen(label))); KQ_ACCOUNT_INVALID for an invalid label, an
 * empty passphrase or a null pointer. Nothing but *token_len is written unless OK. The
 * caller wipes the secrets it passed. The salt and nonce come from the operating system
 * (hosted) or kq_platform_random (freestanding). */
int kq_slot_seal(const char *label, const char *passphrase, const unsigned char device_id[16],
                 const unsigned char signing_secret[32],
                 const unsigned char encryption_secret[32], unsigned char *token_out,
                 size_t cap, size_t *token_len, unsigned char signing_public_out[32],
                 unsigned char encryption_public_out[32]);

#ifdef __cplusplus
}
#endif

#endif /* KEYQUORUM_SLOTS_H */
