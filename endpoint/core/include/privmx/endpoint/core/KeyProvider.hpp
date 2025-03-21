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

class KeyProvider {
public:
    KeyProvider(const privmx::crypto::PrivateKey& key, std::function<std::shared_ptr<UserVerifierInterface>()> getUserVerifier);
    EncKey generateKey();
    int64_t generateContainerControlNumber();
    DecryptedEncKeyV2 getKey(const utils::List<server::KeyEntry>& keys, const std::string& keyId);
    DecryptedEncKeyV2 getKeyAndVerify(const utils::List<server::KeyEntry>& keys, const std::string& keyId, const EncKeyV2IntegrityValidationData& integrityValidationData);
    std::map<std::string,DecryptedEncKeyV2> getKeysAndVerify(const utils::List<server::KeyEntry>& keys, const std::set<std::string>& keyIds, const EncKeyV2IntegrityValidationData& integrityValidationData);
    std::vector<DecryptedEncKeyV2> getAllKeysAndVerify(const utils::List<server::KeyEntry>& serverKeys, const EncKeyV2IntegrityValidationData& integrityValidationData);
    privmx::utils::List<server::KeyEntrySet> prepareKeysList(const std::vector<UserWithPubKey>& users, const EncKey& key, const DataIntegrityObject& dio, int64_t containerControlNumber);
    privmx::utils::List<server::KeyEntrySet> prepareMissingKeysForNewUsers(const std::vector<DecryptedEncKeyV2>& missingKeys, const std::vector<UserWithPubKey>& users, const DataIntegrityObject& dio, int64_t containerControlNumber);
    void validateUserData(std::vector<DecryptedEncKeyV2>& decryptedKeys);
private:
    std::vector<DecryptedEncKeyV2> decryptKeysAndVerify(utils::List<server::KeyEntry> keys, const EncKeyV2IntegrityValidationData& integrityValidationData);
    void validateKeyForDuplication(std::vector<DecryptedEncKeyV2>& keys);
    void validateData(std::vector<DecryptedEncKeyV2>& decryptedKeys, const EncKeyV2IntegrityValidationData& integrityValidationData);
    privmx::crypto::PrivateKey _key;
    std::function<std::shared_ptr<UserVerifierInterface>()> _getUserVerifier;
    EncKeyEncryptorV1 _encKeyEncryptorV1;
    EncKeyEncryptorV2 _encKeyEncryptorV2;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_KEYPROVIDER_HPP_
