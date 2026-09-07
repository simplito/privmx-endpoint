#include "privmx/endpoint/group/encryptors/group/GroupDataSchemaStrategyV5.hpp"
#include "privmx/endpoint/group/encryptors/group/GroupDataSchemaMapper.hpp"

#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/encryptors/module/Constants.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::group;

dynamic::EncryptedGroupMetaV5 GroupDataSchemaStrategyV5::encryptMeta(
    const GroupMetaToEncryptV5& data,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::string& key
) const {
    return _encryptor.encrypt(data, userPrivKey, key);
}

dynamic::EncryptedGroupRosterV5 GroupDataSchemaStrategyV5::encryptRoster(
    const GroupRosterToEncryptV5& data,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::string& key
) const {
    return _encryptor.encryptRoster(data, userPrivKey, key);
}

DecryptedGroupRosterV5 GroupDataSchemaStrategyV5::decryptRoster(
    const dynamic::EncryptedGroupRosterV5& encryptedData,
    const std::string& key
) const {
    return _encryptor.decryptRoster(encryptedData, key);
}

core::DataIntegrityObject GroupDataSchemaStrategyV5::getRosterDIOAndAssertIntegrity(
    const dynamic::EncryptedGroupRosterV5& encryptedData
) const {
    return _encryptor.getRosterDIOAndAssertIntegrity(encryptedData);
}

dynamic::EncryptedGroupMetaV5 GroupDataSchemaStrategyV5::getEncryptedData(const server::GroupInfo& model) const {
    return dynamic::EncryptedGroupMetaV5::fromJSON(model.meta.data);
}

std::tuple<Group, core::DataIntegrityObject> GroupDataSchemaStrategyV5::convert(
    const server::GroupInfo& groupInfo,
    const DecryptedGroupMetaV5& raw
) const {
    return {
        GroupDataSchemaMapper::toLibGroup(
            groupInfo, raw.publicMeta, raw.privateMeta, raw.statusCode, core::ModuleDataSchema::Version::VERSION_5
        ),
        raw.dio
    };
}

Group GroupDataSchemaStrategyV5::toLibError(const server::GroupInfo& groupInfo, int64_t errorCode) const {
    return GroupDataSchemaMapper::toLibGroup(groupInfo, {}, {}, errorCode, core::ModuleDataSchema::Version::VERSION_5);
}
