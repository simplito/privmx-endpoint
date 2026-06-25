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

// clang-format off
class GroupDataSchemaStrategyV5 : public core::TypedDataSchemaStrategyV5<
    GroupDataEncryptorV5,
    dynamic::EncryptedGroupDataV5,
    DecryptedGroupDataV5,
    server::GroupInfo,
    Group
> {
    // clang-format on
public:
    dynamic::EncryptedGroupDataV5 encrypt(
        const GroupDataToEncryptV5& data,
        const privmx::crypto::PrivateKey& userPrivKey,
        const std::string& key
    ) const;
    std::tuple<Group, core::DataIntegrityObject> convert(
        const server::GroupInfo& groupInfo,
        const DecryptedGroupDataV5& raw
    ) const override;
    Group toLibError(const server::GroupInfo& groupInfo, int64_t errorCode) const override;

protected:
    dynamic::EncryptedGroupDataV5 getEncryptedData(const server::GroupInfo& model) const override;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_GROUPDATASCHEMASTRATEGYV5_HPP_
