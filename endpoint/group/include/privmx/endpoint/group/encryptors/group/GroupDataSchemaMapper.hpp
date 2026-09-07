#ifndef _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_GROUPDATASCHEMAMAPPER_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_GROUPDATASCHEMAMAPPER_HPP_

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
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
#include "privmx/endpoint/group/encryptors/group/GroupDataEncryptorV5.hpp"
#include "privmx/endpoint/group/encryptors/group/GroupDataSchemaStrategyV5.hpp"

namespace privmx {
namespace endpoint {
namespace group {

class GroupDataSchemaMapper : public core::BaseModuleDataSchemaMapper {
public:
    GroupDataSchemaMapper(const privmx::crypto::PrivateKey& userPrivKey, const core::Connection& connection);

    Poco::Dynamic::Var encryptMeta(const GroupMetaToEncryptV5& data, const std::string& key);

    Poco::Dynamic::Var encryptRoster(const GroupRosterToEncryptV5& data, const std::string& key);

    void assertDataIntegrity(const server::GroupInfo& groupInfo);

    void assertRosterIsAttested(const server::GroupInfo& groupInfo, const core::DecryptedEncKey& rosterKey);

    void assertMetaIsAttested(const server::GroupInfo& groupInfo, const core::DecryptedEncKey& metaKey);

    /**
     * `HMAC(key, epoch | roster)` — what a membership change commits to and a reader checks.
     *
     * Both sides call this, so the canonical form cannot drift between them. Lists are sorted and length-prefixed:
     * an unprefixed join would let one roster's tag match another's under a different split of the same names.
     * No group id in the payload: the key is this group's own, so a tag made elsewhere cannot verify here anyway
     * — and leaving it out is what lets `createGroup` tag a group whose id the bridge has not assigned yet.
     *
     * No version either. This plane's preconditions — the epoch CAS and the tree's per-node generations — guard
     * the epoch and the roster, not the metadata counter, and committing a counter they do not guard is what let
     * a concurrent `updateGroup` strand a membership change at a version it never landed at. Within one epoch the
     * roster only grows, so `(epoch, roster)` is unambiguous without one.
     */
    static std::string rosterTag(
        const std::string& key,
        int64_t keyVersion,
        const std::vector<std::string>& users,
        const std::vector<std::string>& managers
    );

    /**
     * `HMAC(key, "meta" | epoch | metaVersion)` — what a metadata write commits to and a reader checks.
     *
     * Key-bound rather than merely signed: `publicMeta` is signed but not encrypted, so a bridge holding a keypair
     * of its own could otherwise re-author the envelope and forge it. `updateGroup` may commit `metaVersion`
     * because it is CAS-guarded on exactly that counter, so the version it predicts is the version it lands at.
     */
    static std::string metaTag(const std::string& key, int64_t keyVersion, int64_t metaVersion);

    uint32_t validateDataIntegrity(const server::GroupInfo& groupInfo);

    // Call when the group is gone or the session was reset.
    void dropVersionPin(const std::string& groupId);

    // Call on connect/disconnect, mirroring the tree-key cache.
    void dropAllVersionPins();

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

    /**
     * The attested roster and nothing else — what a tree operation needs before planning against it.
     *
     * Deliberately does not open the metadata entry. A membership change must not depend on a plane it does not
     * write: the metadata may sit at an older epoch, and making a removal wait on that descent would put the two
     * planes back together on the write path, which is the coupling this split exists to remove.
     *
     * Throws rather than reporting a status: a caller about to re-key a tree has no use for a roster it cannot
     * trust.
     */
    std::pair<std::vector<std::string>, std::vector<std::string>> validateAndGetAttestedRoster(
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

    // Overrides base to parse either group envelope instead of EncryptedModuleDataV5.
    core::ModuleInternalMetaV5 decryptInternalMeta(
        const Poco::Dynamic::Var& data,
        const core::DecryptedEncKey& encKey
    ) override;

private:
    std::tuple<Group, core::DataIntegrityObject> decryptMetaPlane(
        const server::GroupInfo& groupInfo,
        const core::DecryptedEncKey& metaKey
    );

    core::VersionStrategyMapper<server::GroupInfo, std::tuple<Group, core::DataIntegrityObject>> _strategyMapper;
    std::shared_ptr<GroupDataSchemaStrategyV5> _strategyV5;
    core::DataEncryptorV4 _dataEncryptor;
    GroupDataEncryptorV5 _groupEncryptor;
    // Monotone pins, one per plane. A tag stays valid forever, so an older but genuinely tagged state is a
    // rollback that only a pin can refuse — and the two counters move independently, so one pin over both would
    // reject legitimate states.
    std::mutex _pinMutex;
    std::map<std::string, int64_t> _verifiedRosterVersions;
    std::map<std::string, int64_t> _verifiedMetaVersions;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_GROUPDATASCHEMAMAPPER_HPP_
