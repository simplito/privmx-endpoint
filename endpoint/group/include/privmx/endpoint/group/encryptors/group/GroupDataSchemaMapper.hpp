#ifndef _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_GROUPDATASCHEMAMAPPER_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_GROUPDATASCHEMAMAPPER_HPP_

#include <cstdint>
#include <memory>
#include <set>
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

    void assertRosterIsAttested(const server::GroupInfo& groupInfo, const core::DecryptedEncKey& encKey);

    /**
     * `HMAC(key, epoch | version | roster)` — what a membership change commits to and a reader checks.
     *
     * Both sides call this, so the canonical form cannot drift between them. Lists are sorted and length-prefixed:
     * an unprefixed join would let one roster's tag match another's under a different split of the same names.
     * No group id in the payload: the key is this group's own, so a tag made elsewhere cannot verify here anyway
     * — and leaving it out is what lets `createGroup` tag a group whose id the bridge has not assigned yet.
     */
    static std::string rosterTag(
        const std::string& key,
        int64_t keyVersion,
        int64_t version,
        const std::vector<std::string>& users,
        const std::vector<std::string>& managers
    );

    uint32_t validateDataIntegrity(const server::GroupInfo& groupInfo);

    // Call when the group is gone or the session was reset.
    void dropChainCheckpoint(const std::string& groupId);

    // Call on connect/disconnect, mirroring the tree-key cache.
    void dropAllChainCheckpoints();

    // For tests and diagnostics.
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

    // Straight across: a summary carries no encrypted data, no key entries and no history, so there is nothing
    // to decrypt, verify or checkpoint here.
    static GroupSummary toLibGroupSummary(const server::GroupSummary& info);

    // Returns the decrypted group private key from the head data entry.
    // Caller must hold the group data key (encKey.key).
    std::string getGroupPrivKey(const server::GroupInfo& groupInfo, const core::DecryptedEncKey& encKey);

    // Overrides base to parse EncryptedGroupDataV5 instead of EncryptedModuleDataV5.
    core::ModuleInternalMetaV5 decryptInternalMeta(
        const Poco::Dynamic::Var& data,
        const core::DecryptedEncKey& encKey
    ) override;

private:
    // Head fields against state this call actually verified — see the definition for why not against `history`.

    core::VersionStrategyMapper<server::GroupInfo, std::tuple<Group, core::DataIntegrityObject>> _strategyMapper;
    std::shared_ptr<GroupDataSchemaStrategyV5> _strategyV5;
    core::DataEncryptorV4 _dataEncryptor;
    GroupDataEncryptorV5 _groupEncryptor;
    // So a warm `assertDataIntegrity` skips already-verified entries instead of re-proving history from genesis.
    checkpoint::ChainCheckpointRegistry _chainCheckpoints;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_GROUPDATASCHEMAMAPPER_HPP_
