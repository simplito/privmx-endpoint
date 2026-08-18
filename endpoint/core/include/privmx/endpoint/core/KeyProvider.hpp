/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_KEYPROVIDER_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_KEYPROVIDER_HPP_

#include <functional>
#include <map>
#include <memory>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <vector>

#include "privmx/endpoint/core/CoreTypes.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/core/UserVerifier.hpp"
#include "privmx/endpoint/core/encryptors/EncKey/EncKeyEncryptorV1.hpp"
#include "privmx/endpoint/core/encryptors/EncKey/EncKeyEncryptorV2.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class KeyDecryptionAndVerificationRequest {
public:
    KeyDecryptionAndVerificationRequest() = default;
    void addOne(const std::vector<server::KeyEntry>& keys, const std::string& keyId, const EncKeyLocation& location);
    void addMany(
        const std::vector<server::KeyEntry>& keys,
        std::set<std::string> keyIds,
        const EncKeyLocation& location
    );
    void addAll(const std::vector<server::KeyEntry>& keys, const EncKeyLocation& location);
    void addGroupKeys(const std::vector<server::GroupKeysEntry>& groupKeys, const EncKeyLocation& location);
    /**
     * Convenience for a module whose wire field is optional.
     *
     * It has to be optional on any field added to an existing struct: a missing JSON array is a parse *error*,
     * not an empty list, so a non-optional field would make every read fail against a server that predates it.
     */
    void addGroupKeys(
        const std::optional<std::vector<server::GroupKeysEntry>>& groupKeys,
        const EncKeyLocation& location
    );
    void markAsCompleted();
    std::unordered_map<EncKeyLocation, std::unordered_map<std::string, server::KeyEntry>> requestData;
    // maps location -> keyId -> (KeyEntry, groupId, groupEpoch)
    std::unordered_map<
        EncKeyLocation,
        std::unordered_map<std::string, std::tuple<server::KeyEntry, std::string, int64_t>>>
        groupRequestData;

private:
    bool _completed = false;
};

class KeyProvider {
public:
    /**
     * Resolves a group's grant private key for a given epoch, on demand, for a single decrypt call.
     *
     * `KeyProvider` does not cache group keys itself — the resolver is supplied fresh by the caller each time,
     * so any caching belongs to whoever owns the resolution logic (e.g. `GroupApiImpl`).
     */
    using GroupPrivKeyResolver = std::function<
        std::optional<privmx::crypto::PrivateKey>(const std::string& groupId, int64_t epoch)>;

    KeyProvider(const privmx::crypto::PrivateKey& key, std::function<std::shared_ptr<UserVerifier>()> getUserVerifier);
    EncKey generateKey();
    std::string generateSecret();
    std::unordered_map<EncKeyLocation, std::unordered_map<std::string, DecryptedEncKeyV2>> getKeysAndVerify(
        const KeyDecryptionAndVerificationRequest& request,
        const GroupPrivKeyResolver& groupPrivKeyResolver = nullptr
    );
    std::vector<server::KeyEntrySet> prepareKeysList(
        const std::vector<UserWithPubKey>& users,
        const EncKey& key,
        const DataIntegrityObject& dio,
        const EncKeyLocation& location,
        const std::string& containerSecret
    );
    std::vector<server::KeyEntrySet> prepareMissingKeysForNewUsers(
        const std::unordered_map<std::string, DecryptedEncKeyV2>& missingKeys,
        const std::vector<UserWithPubKey>& users,
        const DataIntegrityObject& dio,
        const EncKeyLocation& location,
        const std::string& containerSecret
    );
    bool verifyKeysSecret(
        const std::unordered_map<std::string, DecryptedEncKeyV2>& decryptedKeys,
        const EncKeyLocation& location,
        const std::string& containerSecret
    );

private:
    DecryptedEncKeyV2 decryptKeyEntry(const server::KeyEntry& keyEntry, const privmx::crypto::PrivateKey& privKey);
    std::unordered_map<std::string, DecryptedEncKeyV2> decryptAndVerifyKeys(
        std::unordered_map<std::string, server::KeyEntry> keys,
        const EncKeyLocation& location
    );
    std::unordered_map<std::string, DecryptedEncKeyV2> decryptAndVerifyGroupKeys(
        const std::unordered_map<std::string, std::tuple<server::KeyEntry, std::string, int64_t>>& groupKeyMap,
        const EncKeyLocation& location,
        const GroupPrivKeyResolver& groupPrivKeyResolver
    );
    server::KeyEntrySet createKeyEntrySet(
        const UserWithPubKey& user,
        const EncKey& key,
        const DataIntegrityObject& dio,
        const EncKeyLocation& location,
        const std::string& containerSecret
    );
    void verifyForDuplication(std::unordered_map<std::string, DecryptedEncKeyV2>& keys);
    void verifyData(std::unordered_map<std::string, DecryptedEncKeyV2>& decryptedKeys, const EncKeyLocation& location);
    void verifyUserData(
        std::unordered_map<EncKeyLocation, std::unordered_map<std::string, DecryptedEncKeyV2>>& decryptedKeys
    );
    privmx::crypto::PrivateKey _key;
    std::function<std::shared_ptr<UserVerifier>()> _getUserVerifier;
    EncKeyEncryptorV1 _encKeyEncryptorV1;
    EncKeyEncryptorV2 _encKeyEncryptorV2;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_KEYPROVIDER_HPP_
