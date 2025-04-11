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

#include <memory>
#include <functional>
#include <vector>
#include <map>
#include <privmx/crypto/ecc/PrivateKey.hpp>

#include "privmx/endpoint/core/CoreTypes.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/core/encryptors/EncKey/EncKeyEncryptorV1.hpp"
#include "privmx/endpoint/core/encryptors/EncKey/EncKeyEncryptorV2.hpp"
#include "privmx/endpoint/core/UserVerifierInterface.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class KeyDecryptionAndVerificationRequest {
public:
    KeyDecryptionAndVerificationRequest() = default;
    void addOne(const utils::List<server::KeyEntry>& keys, const std::string& keyId, const EncKeyLocation& location);
    void addMany(const utils::List<server::KeyEntry>& keys, const std::set<std::string>& keyIds, const EncKeyLocation& location);
    void addAll(const utils::List<server::KeyEntry>& keys, const EncKeyLocation& location);
    void markAsCompleted();
    std::unordered_map<EncKeyLocation, utils::Map<server::KeyEntry>> requestData;
private:

    bool _completed = false;
    // vector<KeyId, ServerKey, ValidationData>
};

class KeyProvider {
public:
    KeyProvider(const privmx::crypto::PrivateKey& key, std::function<std::shared_ptr<UserVerifierInterface>()> getUserVerifier);
    EncKey generateKey();
    std::string generateContainerControlNumber();
    std::unordered_map<EncKeyLocation,std::unordered_map<std::string, DecryptedEncKeyV2>> getKeysAndVerify(const KeyDecryptionAndVerificationRequest& request);
    privmx::utils::List<server::KeyEntrySet> prepareKeysList(const std::vector<UserWithPubKey>& users, const EncKey& key, const DataIntegrityObject& dio, std::string containerControlNumber);
    privmx::utils::List<server::KeyEntrySet> prepareMissingKeysForNewUsers(const std::unordered_map<std::string, DecryptedEncKeyV2>& missingKeys, const std::vector<UserWithPubKey>& users, const DataIntegrityObject& dio, std::string containerControlNumber);
    
private:
    std::unordered_map<std::string, DecryptedEncKeyV2> decryptKeysAndVerify(utils::Map<server::KeyEntry> keys, const EncKeyLocation& location);
    void verifyForDuplication(std::unordered_map<std::string, DecryptedEncKeyV2>& keys);
    void verifyData(std::unordered_map<std::string, DecryptedEncKeyV2>& decryptedKeys, const EncKeyLocation& location);
    void verifyUserData(std::unordered_map<EncKeyLocation,std::unordered_map<std::string, DecryptedEncKeyV2>>& decryptedKeys);
    privmx::crypto::PrivateKey _key;
    std::function<std::shared_ptr<UserVerifierInterface>()> _getUserVerifier;
    EncKeyEncryptorV1 _encKeyEncryptorV1;
    EncKeyEncryptorV2 _encKeyEncryptorV2;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_KEYPROVIDER_HPP_
