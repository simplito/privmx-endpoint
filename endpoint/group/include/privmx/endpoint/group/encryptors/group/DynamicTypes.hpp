#ifndef _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_DYNAMICTYPES_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_DYNAMICTYPES_HPP_

#include <optional>
#include <string>
#include <vector>

#include <privmx/endpoint/core/DynamicTypes.hpp>
#include <privmx/utils/JsonHelper.hpp>

namespace privmx {
namespace endpoint {
namespace group {
namespace dynamic {

/**
 * The roster/tree plane's entry. Carries no metadata: a membership change must not rewrite what it did not
 * change, and re-signing metadata is what used to couple the two planes into one racy write.
 */
#define ENCRYPTED_GROUP_ROSTER_V5_FIELDS(F)                                                                            \
    F(internalMeta, std::string)                                                                                       \
    F(membership, std::string)                                                                                         \
    F(authorPubKey, std::string)                                                                                       \
    F(dio, std::string)
JSON_STRUCT_EXT(EncryptedGroupRosterV5, core::dynamic::VersionedData, ENCRYPTED_GROUP_ROSTER_V5_FIELDS);

/**
 * The public metadata plane's entry, written only by `updateGroupPublicMeta`.
 *
 * Its DIO checksums cover `publicMeta` and `meta` and nothing else, so this plane can neither be validated
 * against nor invalidated by a field the private plane owns — which is what makes the two separately writable,
 * and what makes the bridge's per-plane grant an enforceable one rather than a declarative one.
 *
 * Sits at the epoch it was written under and stays there; a later reader descends the Epoch Ladder to its key
 * rather than having it rewritten on every removal. The two planes therefore may sit at different epochs.
 */
#define ENCRYPTED_GROUP_PUBLIC_META_V5_FIELDS(F)                                                                       \
    F(publicMeta, std::string)                                                                                         \
    F(publicMetaObject, Poco::Dynamic::Var)                                                                            \
    F(meta, std::string)                                                                                               \
    F(authorPubKey, std::string)                                                                                       \
    F(dio, std::string)
JSON_STRUCT_EXT(EncryptedGroupPublicMetaV5, core::dynamic::VersionedData, ENCRYPTED_GROUP_PUBLIC_META_V5_FIELDS);

/**
 * The private metadata plane's entry, written only by `updateGroupPrivateMeta`.
 *
 * The mirror of the public plane: its DIO checksums cover `privateMeta` and `meta` only. Carries no
 * `internalMeta` — the module's own identity is read from the roster head, the only place anything reads it.
 */
#define ENCRYPTED_GROUP_PRIVATE_META_V5_FIELDS(F)                                                                      \
    F(privateMeta, std::string)                                                                                        \
    F(meta, std::string)                                                                                               \
    F(authorPubKey, std::string)                                                                                       \
    F(dio, std::string)
JSON_STRUCT_EXT(EncryptedGroupPrivateMetaV5, core::dynamic::VersionedData, ENCRYPTED_GROUP_PRIVATE_META_V5_FIELDS);

// Parses the roster envelope for `internalMeta`, the only plane that carries it — `JSON_STRUCT` ignores the rest.
#define ENCRYPTED_GROUP_INTERNAL_META_VIEW_V5_FIELDS(F)                                                                \
    F(internalMeta, std::string)                                                                                       \
    F(authorPubKey, std::string)                                                                                       \
    F(dio, std::string)
JSON_STRUCT_EXT(
    EncryptedGroupInternalMetaViewV5,
    core::dynamic::VersionedData,
    ENCRYPTED_GROUP_INTERNAL_META_VIEW_V5_FIELDS
);

/**
 * The roster, attested by a key only members hold.
 *
 * Not a history: `rosterTag` is `HMAC(content key of the epoch, epoch | rosterVersion | roster)`, so a reader
 * recomputes it from what the bridge served and compares. A bridge cannot forge it — it never holds the key —
 * and a member verifies it with the key they had to recover anyway to read anything. Constant cost, whatever
 * the group's age.
 *
 * The group id is not in the preimage: the key is what binds a tag to its group. `rosterVersion` is, and has
 * to be. Without it the counter is a number the bridge may state freely, so it could pair the current version
 * with any earlier roster from the same epoch — every one of which carries a genuine tag, because within an
 * epoch the roster only grows — and the monotone pin would see nothing wrong. The metadata plane commits its
 * counter for exactly this reason; the roster plane can, because `expectedRosterVersion` is now part of the
 * bridge's compare-and-swap, so the version the caller predicts is the version the entry lands at.
 *
 * What this deliberately does not carry: who made the change, and whether they were a manager rather than an
 * ordinary member. Holding the key is the authority, so the guarantee is "a member with access did this, not the
 * bridge". Attribution and manager-only proof would need per-entry signatures chained back to genesis, which is
 * what this replaced.
 *
 * The counters are not optional. This is the endpoint's own sealed block, so a missing one is a malformed
 * envelope, not an old one — and `JsonHelper` throws on absence, where an optional would have compared as 0
 * against a real counter and passed the tag check on a group at epoch 0, which no group is.
 */
#define MEMBERSHIP_BLOCK_FIELDS(F)                                                                                     \
    F(rosterTag, std::string)                                                                                          \
    F(groupPubKey, std::string)                                                                                        \
    F(keyId, std::string)                                                                                              \
    F(keyVersion, int64_t)                                                                                             \
    F(rosterVersion, int64_t)
JSON_STRUCT(MembershipBlock, MEMBERSHIP_BLOCK_FIELDS);

/**
 * One metadata plane's entry pinned to the version it landed at, under a key only members of that epoch hold.
 *
 * `metaTag` is `HMAC(content key of keyVersion, "publicMeta" or "privateMeta" | keyVersion | metaVersion)`.
 * Key-bound rather than merely signed, because a bridge with a keypair of its own could otherwise re-author a
 * whole envelope and forge it — the public plane is signed and not encrypted at all. The domain prefix is what
 * stops one plane's entry being served as the other's, since both planes carry this same block shape.
 *
 * A metadata write may commit `metaVersion` because it is CAS-guarded on exactly its own counter, so the
 * version it predicts is the version it lands at.
 */
#define META_BLOCK_FIELDS(F)                                                                                           \
    F(metaTag, std::string)                                                                                            \
    F(keyId, std::string)                                                                                              \
    F(keyVersion, int64_t)                                                                                             \
    F(metaVersion, int64_t)
JSON_STRUCT(MetaBlock, META_BLOCK_FIELDS);

} // namespace dynamic
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_DYNAMICTYPES_HPP_
