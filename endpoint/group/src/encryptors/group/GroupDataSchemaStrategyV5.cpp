#include "privmx/endpoint/group/encryptors/group/GroupDataSchemaStrategyV5.hpp"
#include "privmx/endpoint/group/encryptors/group/GroupDataSchemaMapper.hpp"

#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/encryptors/module/Constants.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::group;

dynamic::EncryptedGroupDataV5 GroupDataSchemaStrategyV5::encrypt(
    const GroupDataToEncryptV5& data,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::string& key
) const {
    return _encryptor.encrypt(data, userPrivKey, key);
}

dynamic::EncryptedGroupDataV5 GroupDataSchemaStrategyV5::getEncryptedData(
    const server::GroupInfo& model
) const {
    return dynamic::EncryptedGroupDataV5::fromJSON(model.data.back().data);
}

std::tuple<Group, core::DataIntegrityObject> GroupDataSchemaStrategyV5::convert(
    const server::GroupInfo& groupInfo,
    const DecryptedGroupDataV5& raw
) const {
    return {
        GroupDataSchemaMapper::toLibGroup(
            groupInfo, raw.publicMeta, raw.privateMeta, raw.statusCode, core::ModuleDataSchema::Version::VERSION_5
        ),
        raw.dio
    };
}

Group GroupDataSchemaStrategyV5::toLibError(const server::GroupInfo& groupInfo, int64_t errorCode) const {
    return GroupDataSchemaMapper::toLibGroup(
        groupInfo, {}, {}, errorCode, core::ModuleDataSchema::Version::VERSION_5
    );
}
