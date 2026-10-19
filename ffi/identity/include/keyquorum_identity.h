/*
 * keyquorum_identity.h - C ABI for KeyQuorum's account heritage (ffi/identity).
 *
 * Link against libkeyquorum_identity.a. Every function is pure: buffers are
 * caller-owned, and a key id written into `out` is NUL terminated.
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

#ifdef __cplusplus
}
#endif

#endif /* KEYQUORUM_IDENTITY_H */
