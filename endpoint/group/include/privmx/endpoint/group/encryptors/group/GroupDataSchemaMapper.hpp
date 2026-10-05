#ifndef _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_GROUPDATASCHEMAMAPPER_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_GROUPDATASCHEMAMAPPER_HPP_

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include <Poco/Dynamic/Var.h>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/BaseModuleDataSchemaMapper.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/DynamicTypes.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>
#include <privmx/endpoint/core/encryptors/DIO/DIOEncryptorV1.hpp>
#include <privmx/endpoint/core/encryptors/DataEncryptorV4.hpp>

#include "privmx/endpoint/group/ServerTypes.hpp"
#include "privmx/endpoint/group/Types.hpp"
#include "privmx/endpoint/group/encryptors/group/GroupDataEncryptorV5.hpp"

namespace privmx {
namespace endpoint {
namespace group {

class GroupDataSchemaMapper : public core::BaseModuleDataSchemaMapper {
public:
    GroupDataSchemaMapper(const privmx::crypto::PrivateKey& userPrivKey, const core::Connection& connection);

    // Takes no key: every field of the public plane is signed and none is encrypted. The content key is still
    // what binds the entry to its epoch and version, through the `publicMetaTag` the caller puts in `data.meta`.
    Poco::Dynamic::Var encryptPublicMeta(const GroupPublicMetaToEncryptV5& data);

    Poco::Dynamic::Var encryptPrivateMeta(const GroupPrivateMetaToEncryptV5& data, const std::string& key);

    Poco::Dynamic::Var encryptRoster(const GroupRosterToEncryptV5& data, const std::string& key);

    // Returns the roster head's DIO it had to decode anyway, so a caller that needs it does not verify twice.
    core::DataIntegrityObject assertDataIntegrity(const server::GroupInfo& groupInfo);

    void assertRosterIsAttested(const server::GroupInfo& groupInfo, const core::DecryptedEncKey& rosterKey);

    void assertPublicMetaIsAttested(const server::GroupInfo& groupInfo, const core::DecryptedEncKey& publicMetaKey);

    void assertPrivateMetaIsAttested(const server::GroupInfo& groupInfo, const core::DecryptedEncKey& privateMetaKey);

    // `HMAC(subkey, epoch | rosterVersion | roster)`. Lists are sorted and length-prefixed so one roster's tag
    // cannot match another's under a different split; `rosterVersion` binds the counter the monotone pin checks.
    static std::string rosterTag(
        const std::string& key,
        int64_t keyVersion,
        int64_t rosterVersion,
        const std::vector<std::string>& users,
        const std::vector<std::string>& managers
    );

    // `HMAC(subkey, "publicMeta" | epoch | publicMetaVersion)`. Key-bound rather than merely signed: nothing in
    // this plane is encrypted, so a bridge with a keypair of its own could otherwise re-author the envelope.
    static std::string publicMetaTag(const std::string& key, int64_t keyVersion, int64_t metaVersion);

    // `HMAC(subkey, "privateMeta" | epoch | privateMetaVersion)`. This plane also sign-and-encrypts under the
    // content key, with every field verified against the one `authorPubKey` the DIO pins.
    static std::string privateMetaTag(const std::string& key, int64_t keyVersion, int64_t metaVersion);

    // One subkey per tag purpose, derived from the epoch's content key, which is also the AES key for the meta
    // planes. `Crypto::kdf` gives distinct purposes independent keys, so preimages cannot collide by prefix.
    static std::string tagSubkey(const std::string& contentKey, const std::string& purpose);

    // The status code, plus the roster head's DIO when that code is 0.
    std::pair<uint32_t, core::DataIntegrityObject> validateDataIntegrity(const server::GroupInfo& groupInfo);

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

    // Deliberately does not open the metadata entry: that plane may sit at an older epoch, and waiting on its
    // descent would recouple the two planes on the write path. Throws rather than reporting a status.
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

    // Overrides base to parse the group's roster envelope instead of EncryptedModuleDataV5.
    core::ModuleInternalMetaV5 decryptInternalMeta(
        const Poco::Dynamic::Var& data,
        const core::DecryptedEncKey& encKey
    ) override;

private:
    // One preimage builder for both metadata planes, so the canonical form cannot drift between them. `domain`
    // names the plane in both the subkey label and the payload.
    static std::string metaPlaneTag(
        const char* domain,
        const std::string& key,
        int64_t keyVersion,
        int64_t metaVersion
    );

    // Both metadata planes at once. Only the private plane needs a key; the public plane's key is what attests
    // it, and that already ran. Returns the lib object plus each plane's DIO, for the duplicate-randomId sweep.
    std::tuple<Group, core::DataIntegrityObject, core::DataIntegrityObject> decryptMetaPlanes(
        const server::GroupInfo& groupInfo,
        const core::DecryptedEncKey& privateMetaKey
    );

    core::DataEncryptorV4 _dataEncryptor;
    // Own DIO encryptor, for the one envelope `GroupDataEncryptorV5` has no method for: the internal-meta view.
    core::DIOEncryptorV1 _DIOEncryptor;
    GroupDataEncryptorV5 _groupEncryptor;
    // Monotone pins, one per plane: a tag stays valid forever, so only a pin refuses a genuinely tagged
    // rollback. The counters move independently, so one pin over all three would reject legitimate states.
    std::mutex _pinMutex;
    std::map<std::string, int64_t> _verifiedRosterVersions;
    std::map<std::string, int64_t> _verifiedPublicMetaVersions;
    std::map<std::string, int64_t> _verifiedPrivateMetaVersions;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_GROUPDATASCHEMAMAPPER_HPP_
