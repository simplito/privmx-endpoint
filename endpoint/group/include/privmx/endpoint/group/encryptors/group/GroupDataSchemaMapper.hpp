#ifndef _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_GROUPDATASCHEMAMAPPER_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_GROUPDATASCHEMAMAPPER_HPP_

#include <cstdint>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include <Poco/Dynamic/Var.h>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/BaseModuleDataSchemaMapper.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/DynamicTypes.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptorV4.hpp>
#include <privmx/endpoint/core/encryptors/VersionStrategyMapper.hpp>

#include "privmx/endpoint/group/ServerTypes.hpp"
#include "privmx/endpoint/group/Types.hpp"
#include "privmx/endpoint/group/checkpoint/ChainCheckpoint.hpp"
#include "privmx/endpoint/group/checkpoint/ChainCheckpointRegistry.hpp"
#include "privmx/endpoint/group/encryptors/group/GroupDataEncryptorV5.hpp"
#include "privmx/endpoint/group/encryptors/group/GroupDataSchemaStrategyV5.hpp"

namespace privmx {
namespace endpoint {
namespace group {

class GroupDataSchemaMapper : public core::BaseModuleDataSchemaMapper {
public:
    GroupDataSchemaMapper(const privmx::crypto::PrivateKey& userPrivKey, const core::Connection& connection);

    Poco::Dynamic::Var encrypt(const GroupDataToEncryptV5& data, const std::string& key);

    std::tuple<Group, core::DataIntegrityObject> decrypt(
        const server::GroupInfo& groupInfo,
        const core::DecryptedEncKey& encKey
    );

    void assertDataIntegrity(const server::GroupInfo& groupInfo);

    uint32_t validateDataIntegrity(const server::GroupInfo& groupInfo);

    /** Drops one group's chain checkpoint. Call when the group is gone or the session was reset. */
    void dropChainCheckpoint(const std::string& groupId);

    /** Drops every group's chain checkpoint. Call on connect/disconnect, mirroring the tree-key cache. */
    void dropAllChainCheckpoints();

    /** The stored checkpoint for one group, if any. For tests and diagnostics. */
    std::optional<checkpoint::ChainCheckpoint::Snapshot> peekChainCheckpoint(const std::string& groupId) const;

    std::vector<Group> validateDecryptAndConvertGroups(
        const std::vector<server::GroupInfo>& groups,
        const std::shared_ptr<core::KeyProvider>& keyProvider,
        const core::KeyProvider::GroupPrivKeyResolver& groupPrivKeyResolver = nullptr
    );

    Group validateDecryptAndConvertGroup(
        const server::GroupInfo& groupInfo,
        const std::shared_ptr<core::KeyProvider>& keyProvider,
        const core::KeyProvider::GroupPrivKeyResolver& groupPrivKeyResolver = nullptr
    );

    static Group toLibGroup(
        const server::GroupInfo& info,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        int64_t statusCode,
        int64_t schemaVersion
    );

    // Returns the decrypted group private key from the head data entry.
    // Caller must hold the group data key (encKey.key).
    std::string getGroupPrivKey(const server::GroupInfo& groupInfo, const core::DecryptedEncKey& encKey);

    // Overrides base to parse EncryptedGroupDataV5 instead of EncryptedModuleDataV5.
    core::ModuleInternalMetaV5 decryptInternalMeta(
        const Poco::Dynamic::Var& data,
        const core::DecryptedEncKey& encKey
    ) override;

private:
    core::VersionStrategyMapper<server::GroupInfo, std::tuple<Group, core::DataIntegrityObject>> _strategyMapper;
    std::shared_ptr<GroupDataSchemaStrategyV5> _strategyV5;
    core::DataEncryptorV4 _dataEncryptor;
    GroupDataEncryptorV5 _groupEncryptor;
    /** Per-group chain-verification checkpoints, so a warm `assertDataIntegrity` skips already-verified
     *  entries instead of re-proving the whole history from genesis on every call. */
    checkpoint::ChainCheckpointRegistry _chainCheckpoints;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_GROUPDATASCHEMAMAPPER_HPP_
