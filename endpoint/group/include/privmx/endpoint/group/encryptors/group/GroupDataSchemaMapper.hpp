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

    void assertDataIntegrity(const server::GroupInfo& groupInfo);

    void assertRosterIsAttested(const server::GroupInfo& groupInfo, const core::DecryptedEncKey& rosterKey);

    void assertPublicMetaIsAttested(const server::GroupInfo& groupInfo, const core::DecryptedEncKey& publicMetaKey);

    void assertPrivateMetaIsAttested(const server::GroupInfo& groupInfo, const core::DecryptedEncKey& privateMetaKey);

    /**
     * `HMAC(subkey, epoch | rosterVersion | roster)` — what a membership change commits to and a reader checks.
     *
     * Both sides call this, so the canonical form cannot drift between them. Lists are sorted and length-prefixed:
     * an unprefixed join would let one roster's tag match another's under a different split of the same names.
     * No group id in the payload: the key is this group's own, so a tag made elsewhere cannot verify here anyway
     * — and leaving it out is what lets `createGroup` tag a group whose id the bridge has not assigned yet.
     *
     * `rosterVersion` is in, and load-bearing. `(epoch, roster)` alone is unambiguous but leaves the counter
     * unbound, and the counter is what the monotone pin checks — so a bridge could serve the current version
     * beside any earlier roster from the same epoch and pass both tests. The caller may commit it because the
     * bridge's compare-and-swap now pins `expectedRosterVersion` as well as the epoch, so the entry lands at
     * the version this tag names or not at all.
     */
    static std::string rosterTag(
        const std::string& key,
        int64_t keyVersion,
        int64_t rosterVersion,
        const std::vector<std::string>& users,
        const std::vector<std::string>& managers
    );

    /**
     * `HMAC(subkey, "publicMeta" | epoch | publicMetaVersion)` — what a public-metadata write commits to and a
     * reader checks.
     *
     * Key-bound rather than merely signed: nothing in this plane is encrypted, so a bridge holding a keypair of
     * its own could otherwise re-author the whole envelope and forge it. `updateGroupPublicMeta` may commit
     * `publicMetaVersion` because it is CAS-guarded on exactly that counter, so the version it predicts is the
     * version it lands at.
     *
     * Each plane derives its own subkey, so one plane's entry cannot verify in the other's position even though
     * both carry the same `MetaBlock` shape. The domain prefix in the preimage says the same thing and is kept
     * anyway: it makes the payload legible without having to know which key signed it.
     */
    static std::string publicMetaTag(const std::string& key, int64_t keyVersion, int64_t metaVersion);

    /**
     * `HMAC(subkey, "privateMeta" | epoch | privateMetaVersion)` — the private plane's counterpart.
     *
     * This plane has a second line of defence the public one lacks: `privateMeta` is sign-and-encrypt under the
     * content key and every field verifies against the one `authorPubKey` the DIO pins, so a bridge can neither
     * swap that key (the copied fields stop verifying) nor keep it (it cannot sign what it wants to replace).
     */
    static std::string privateMetaTag(const std::string& key, int64_t keyVersion, int64_t metaVersion);

    /**
     * One subkey per tag purpose, derived from the epoch's content key.
     *
     * That key is also the AES key for `publicMeta`/`privateMeta`/`internalMeta` and the HMAC key behind three
     * separate tags. The preimages happen to be prefix-disjoint today, so nothing collides — but that is a naming
     * convention, and the next purpose added has to re-derive the argument by hand or fail silently. `Crypto::kdf`
     * is HMAC-SHA256 in feedback mode over a NUL-separated, length-bound label, so distinct purposes get
     * independent keys by construction and the labels cannot collide by prefix either.
     */
    static std::string tagSubkey(const std::string& contentKey, const std::string& purpose);

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
    // Monotone pins, one per plane. A tag stays valid forever, so an older but genuinely tagged state is a
    // rollback that only a pin can refuse — and the three counters move independently, so one pin over all of
    // them would reject legitimate states.
    std::mutex _pinMutex;
    std::map<std::string, int64_t> _verifiedRosterVersions;
    std::map<std::string, int64_t> _verifiedPublicMetaVersions;
    std::map<std::string, int64_t> _verifiedPrivateMetaVersions;
};

} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_ENCRYPTORS_GROUP_GROUPDATASCHEMAMAPPER_HPP_
