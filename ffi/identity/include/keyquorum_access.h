/*
 * keyquorum_access.h - C ABI for the login / su / sudo access policy
 * (ffi/identity, the same libkeyquorum_identity.a as keyquorum_identity.h).
 * Added in KQ_FILE_ABI_VERSION 4.
 *
 * One function answers what a switch from the account `current` to the account
 * `target` demands. The rule is keyquorum::access::requirement, so the hosted
 * shell, the browser lab and a freestanding kernel cannot differ:
 *
 *   same account, without sudo          KQ_ACCESS_NONE
 *   sudo, or the target is "Root"       KQ_ACCESS_KQST_PASSWORD (Root's own token + password)
 *   same branch (above or below)        KQ_ACCESS_PASSWORD (the target's)
 *   another branch, a live private
 *     bridge connects the two           KQ_ACCESS_PASSWORD_BRIDGE_KQST (the target's password
 *                                       + the slot token of one member of that bridge)
 *   another branch, no such bridge      KQ_ACCESS_KQST_PASSWORD (the target's token + password)
 *   a malformed or empty label          KQ_ACCESS_REFUSED
 *
 * Labels are heritage key ids ("Root", "Root.Flinstone.Bob"), case sensitive: pass "Root",
 * not "root". "Connects" is kq_bridge_connects on some pair of the bridge's Member
 * labels; supervisors are not listed. The caller passes only bridges it has checked
 * live. This function says which factor to ask for, it checks none: opening the token is
 * kq_slot_open (keyquorum_slots.h), and showing a presenter really is a bridge member is
 * kq_bridge_prove + kq_bridge_verify (keyquorum_bridge.h, whose KQ_BRIDGE_* codes are
 * proof statuses, a different namespace from the KQ_ACCESS_* factors here).
 *
 * Keep in step with ffi/identity/src/ffi/access.rs.
 */
#ifndef KEYQUORUM_ACCESS_H
#define KEYQUORUM_ACCESS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The factors (append only; never renumber). */
#define KQ_ACCESS_NONE                  0
#define KQ_ACCESS_PASSWORD              1
#define KQ_ACCESS_KQST_PASSWORD         2
#define KQ_ACCESS_PASSWORD_BRIDGE_KQST  3
#define KQ_ACCESS_REFUSED               4
/* A bad argument: null, not UTF-8, more than 64 bridges or 256 members. Treat as refused. */
#define KQ_ACCESS_INVALID             (-1)

/* A live private bridge: its uid and its Member labels. */
typedef struct {
    const char *uid;
    const char *const *members;
    size_t nmembers;
} kq_bridge_t;

/* Returns a KQ_ACCESS_* factor, or KQ_ACCESS_INVALID. sudo non-zero asks for Root's key.
 * parent_approval non-zero is CustodyPolicy.unlock_approval == Parent.
 * *bridge_index_out is the index into live_bridges of the bridge to cross when the factor
 * is KQ_ACCESS_PASSWORD_BRIDGE_KQST (the first that connects), else -1.
 * *needs_parent_grant_out is 1 when parent_approval is on and the switch asks for a
 * same-branch or cross-branch factor (never for NONE, REFUSED, Root or sudo), else 0.
 * Both outputs are optional (NULL), and set to -1 and 0 on KQ_ACCESS_INVALID. */
int kq_access_requirement(const char *current, const char *target, int sudo,
                          const kq_bridge_t *live_bridges, size_t nbridges,
                          int parent_approval,
                          int *bridge_index_out, int *needs_parent_grant_out);

#ifdef __cplusplus
}
#endif

#endif /* KEYQUORUM_ACCESS_H */
