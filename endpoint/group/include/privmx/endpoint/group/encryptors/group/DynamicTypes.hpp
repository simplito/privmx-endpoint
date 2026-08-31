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

#define MEMBERSHIP_BLOCK_FIELDS(F)                                                                                     \
    F(users, std::vector<std::string>)                                                                                 \
    F(managers, std::vector<std::string>)                                                                              \
    F(groupPubKey, std::string)                                                                                        \
    F(keyId, std::string)                                                                                              \
    F(keyVersion, std::optional<int64_t>)                                                                              \
    F(prevEntryHash, std::optional<std::string>)
JSON_STRUCT(MembershipBlock, MEMBERSHIP_BLOCK_FIELDS);

} // namespace dynamic
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_DYNAMICTYPES_HPP_
