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

// The roster/tree plane's entry. Carries no metadata: a membership change must not rewrite what it did not
// change, and re-signing metadata is what used to couple the two planes into one racy write.
#define ENCRYPTED_GROUP_ROSTER_V5_FIELDS(F)                                                                            \
    F(internalMeta, std::string)                                                                                       \
    F(membership, std::string)                                                                                         \
    F(authorPubKey, std::string)                                                                                       \
    F(dio, std::string)
JSON_STRUCT_EXT(EncryptedGroupRosterV5, core::dynamic::VersionedData, ENCRYPTED_GROUP_ROSTER_V5_FIELDS);

// Written only by `updateGroupPublicMeta`; its DIO checksums cover `publicMeta` and `meta` and nothing else,
// which is what makes the two planes separately writable and lets them sit at different epochs.
#define ENCRYPTED_GROUP_PUBLIC_META_V5_FIELDS(F)                                                                       \
    F(publicMeta, std::string)                                                                                         \
    F(publicMetaObject, Poco::Dynamic::Var)                                                                            \
    F(meta, std::string)                                                                                               \
    F(authorPubKey, std::string)                                                                                       \
    F(dio, std::string)
JSON_STRUCT_EXT(EncryptedGroupPublicMetaV5, core::dynamic::VersionedData, ENCRYPTED_GROUP_PUBLIC_META_V5_FIELDS);

// The mirror of the public plane: DIO checksums cover `privateMeta` and `meta` only. Carries no
// `internalMeta` — the module's own identity is read from the roster head, the only place anything reads it.
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

// `rosterTag` is `HMAC(content key of the epoch, epoch | rosterVersion | roster)`; the key binds a tag to its
// group, and `rosterVersion` stops the bridge pairing the current version with an earlier roster of that epoch.
#define MEMBERSHIP_BLOCK_FIELDS(F)                                                                                     \
    F(rosterTag, std::string)                                                                                          \
    F(groupPubKey, std::string)                                                                                        \
    F(keyId, std::string)                                                                                              \
    F(keyVersion, int64_t)                                                                                             \
    F(rosterVersion, int64_t)
JSON_STRUCT(MembershipBlock, MEMBERSHIP_BLOCK_FIELDS);

// `metaTag` is `HMAC(content key of keyVersion, "publicMeta" or "privateMeta" | keyVersion | metaVersion)`.
// Key-bound, not merely signed; the domain prefix stops one plane's entry being served as the other's.
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
