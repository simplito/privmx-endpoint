#ifndef _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_GROUPDATASCHEMASTRATEGYV5_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_GROUPDATASCHEMASTRATEGYV5_HPP_

#include <tuple>

#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/DynamicTypes.hpp>
#include <privmx/endpoint/core/encryptors/TypedDataSchemaStrategyV5.hpp>

#include "privmx/endpoint/group/ServerTypes.hpp"
#include "privmx/endpoint/group/Types.hpp"
#include "privmx/endpoint/group/encryptors/group/GroupDataEncryptorV5.hpp"
#include "privmx/endpoint/group/encryptors/group/Types.hpp"

namespace privmx {
namespace endpoint {
namespace group {

// Bound to the metadata plane: that is what carries `publicMeta`/`privateMeta` into the lib object. The
// roster plane has no lib-object fields of its own and is verified directly by `GroupDataSchemaMapper`.
// clang-format off
class GroupDataSchemaStrategyV5 : public core::TypedDataSchemaStrategyV5<
    GroupDataEncryptorV5,
    dynamic::EncryptedGroupMetaV5,
    DecryptedGroupMetaV5,
    server::GroupInfo,
    Group
> {
    // clang-format on
public:
    dynamic::EncryptedGroupMetaV5 encryptMeta(
        const GroupMetaToEncryptV5& data,
        const privmx::crypto::PrivateKey& userPrivKey,
        const std::string& key
    ) const;
    dynamic::EncryptedGroupRosterV5 encryptRoster(
        const GroupRosterToEncryptV5& data,
        const privmx::crypto::PrivateKey& userPrivKey,
        const std::string& key
    ) const;
    DecryptedGroupRosterV5 decryptRoster(
        const dynamic::EncryptedGroupRosterV5& encryptedData,
        const std::string& key
    ) const;
    core::DataIntegrityObject getRosterDIOAndAssertIntegrity(
        const dynamic::EncryptedGroupRosterV5& encryptedData
    ) const;
    std::tuple<Group, core::DataIntegrityObject> convert(
        const server::GroupInfo& groupInfo,
        const DecryptedGroupMetaV5& raw
    ) const override;
    Group toLibError(const server::GroupInfo& groupInfo, int64_t errorCode) const override;

protected:
    dynamic::EncryptedGroupMetaV5 getEncryptedData(const server::GroupInfo& model) const override;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_GROUPDATASCHEMASTRATEGYV5_HPP_
