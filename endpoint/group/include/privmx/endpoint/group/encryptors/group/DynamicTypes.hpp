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

#define ENCRYPTED_GROUP_DATA_V5_FIELDS(F)                                                                              \
    F(publicMeta, std::string)                                                                                         \
    F(publicMetaObject, Poco::Dynamic::Var)                                                                            \
    F(privateMeta, std::string)                                                                                        \
    F(internalMeta, std::string)                                                                                       \
    F(groupPrivKey, std::string)                                                                                       \
    F(membership, std::string)                                                                                         \
    F(authorPubKey, std::string)                                                                                       \
    F(dio, std::string)
JSON_STRUCT_EXT(EncryptedGroupDataV5, core::dynamic::VersionedData, ENCRYPTED_GROUP_DATA_V5_FIELDS);

/**
 * The roster, attested by a key only members hold.
 *
 * Not a history: `rosterTag` is `HMAC(metadata key, groupId | epoch | version | roster)`, so a reader recomputes
 * it from what the bridge served and compares. A bridge cannot forge it — it never holds the key — and a member
 * verifies it with the key they had to recover anyway to read anything. Constant cost, whatever the group's age.
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

} // namespace dynamic
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_DYNAMICTYPES_HPP_
