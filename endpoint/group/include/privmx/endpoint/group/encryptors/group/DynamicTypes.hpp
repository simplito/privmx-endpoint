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
 * The metadata plane's entry, written only by `updateGroup`. Sits at the epoch it was written under and stays
 * there — a later reader descends the Epoch Ladder to its key rather than having it rewritten on every removal.
 */
#define ENCRYPTED_GROUP_META_V5_FIELDS(F)                                                                              \
    F(publicMeta, std::string)                                                                                         \
    F(publicMetaObject, Poco::Dynamic::Var)                                                                            \
    F(privateMeta, std::string)                                                                                        \
    F(internalMeta, std::string)                                                                                       \
    F(meta, std::string)                                                                                               \
    F(authorPubKey, std::string)                                                                                       \
    F(dio, std::string)
JSON_STRUCT_EXT(EncryptedGroupMetaV5, core::dynamic::VersionedData, ENCRYPTED_GROUP_META_V5_FIELDS);

// Parses either envelope for the one field both carry — `JSON_STRUCT` ignores the rest.
#define ENCRYPTED_GROUP_INTERNAL_META_VIEW_V5_FIELDS(F)                                                                \
    F(internalMeta, std::string)                                                                                       \
    F(authorPubKey, std::string)
JSON_STRUCT_EXT(
    EncryptedGroupInternalMetaViewV5,
    core::dynamic::VersionedData,
    ENCRYPTED_GROUP_INTERNAL_META_VIEW_V5_FIELDS
);

/**
 * The roster, attested by a key only members hold.
 *
 * Not a history: `rosterTag` is `HMAC(content key of the epoch, epoch | roster)`, so a reader recomputes it from
 * what the bridge served and compares. A bridge cannot forge it — it never holds the key — and a member verifies
 * it with the key they had to recover anyway to read anything. Constant cost, whatever the group's age.
 *
 * The group id is not in the preimage: the key is what binds a tag to its group. Nor is the version — that
 * belongs to the metadata plane, and committing a counter this plane's preconditions do not guard is what let a
 * concurrent `updateGroup` strand a membership change at a version it never landed at.
 *
 * What this deliberately does not carry: who made the change, and whether they were a manager rather than an
 * ordinary member. Holding the key is the authority, so the guarantee is "a member with access did this, not the
 * bridge". Attribution and manager-only proof would need per-entry signatures chained back to genesis, which is
 * what this replaced.
 */
#define MEMBERSHIP_BLOCK_FIELDS(F)                                                                                     \
    F(rosterTag, std::string)                                                                                          \
    F(groupPubKey, std::string)                                                                                        \
    F(keyId, std::string)                                                                                              \
    F(keyVersion, std::optional<int64_t>)
JSON_STRUCT(MembershipBlock, MEMBERSHIP_BLOCK_FIELDS);

/**
 * The metadata entry pinned to the version it landed at, under a key only members of that epoch hold.
 *
 * `metaTag` is `HMAC(content key of keyVersion, "meta" | keyVersion | metaVersion)`. Key-bound rather than
 * merely signed, because `publicMeta` is signed but not encrypted: a bridge with a keypair of its own could
 * otherwise re-author the whole envelope and forge it. `updateGroup` may commit `metaVersion` because it is
 * CAS-guarded on exactly that counter, so the version it predicts is the version it lands at.
 */
#define META_BLOCK_FIELDS(F)                                                                                           \
    F(metaTag, std::string)                                                                                            \
    F(keyId, std::string)                                                                                              \
    F(keyVersion, std::optional<int64_t>)                                                                              \
    F(metaVersion, std::optional<int64_t>)
JSON_STRUCT(MetaBlock, META_BLOCK_FIELDS);

} // namespace dynamic
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_DYNAMICTYPES_HPP_
