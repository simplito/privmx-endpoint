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
#include <privmx/crypto/ecc/PrivateKey.hpp>

#include "privmx/endpoint/core/CoreTypes.hpp"
#include "privmx/endpoint/core/ServerTypes.hpp"
#include "privmx/endpoint/core/Types.hpp"
#include "privmx/endpoint/core/encryptors/EncKey/EncKeyEncryptorV1.hpp"
#include "privmx/endpoint/core/encryptors/EncKey/EncKeyEncryptorV2.hpp"

namespace privmx {
namespace endpoint {
namespace core {

class KeyProvider {
public:
    KeyProvider(const privmx::crypto::PrivateKey& key, std::shared_ptr<UserVerifierInterface> userVerifier);
    EncKey generateKey();
    EncKeyV2 KeyProvider::getKeyAndVaerify(const utils::List<server::KeyEntry>& keys, const std::string& keyId, const std::string& contextId, const std::string& containerId);
    privmx::utils::List<server::KeyEntrySet> prepareKeysList(const std::vector<UserWithPubKey>& users, const EncKey& key, const DataIntegrityObject& dio);
    privmx::utils::List<server::KeyEntrySet> prepareOldKeysListForNewUsers(const utils::List<server::KeyEntry>& oldKeys, const std::vector<UserWithPubKey>& users, const DataIntegrityObject& dio);     
    void validateServerKeys(const utils::List<server::KeyEntry>& serverKeys);
private:

    EncKeyV2 getKey(const utils::List<server::KeyEntry>& keys, const std::string& keyId);
    EncKeyV2 decryptKeyAndVerify(server::KeyEntry key, const std::string& contextId, const std::string& containerId);
    void verify(EncKeyV2 decryptedKey, const std::string& contextId, const std::string& containerId);
    privmx::crypto::PrivateKey _key;
    std::shared_ptr<UserVerifierInterface> _userVerifier;
    EncKeyEncryptorV1 _encKeyEncryptorV1;
    EncKeyEncryptorV2 _encKeyEncryptorV2;
};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  // _PRIVMXLIB_ENDPOINT_CORE_KEYPROVIDER_HPP_
