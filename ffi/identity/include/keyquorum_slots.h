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

#ifdef __cplusplus
}
#endif

#endif /* KEYQUORUM_SLOTS_H */
