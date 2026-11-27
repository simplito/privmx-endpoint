/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/event/EventKeyProvider.hpp"
#include <privmx/crypto/CryptoException.hpp>
#include <privmx/endpoint/core/crypto/PublicKeyCache.hpp>

using namespace privmx::endpoint::event;

EventKeyProvider::EventKeyProvider(const core::PrivateKey& key) : _key(key) {}

std::string EventKeyProvider::generateKey() {
    return core::CryptoSuite::randomBytes(32);
}
DecryptedEventEncKeyV1 EventKeyProvider::decryptKey(
    const std::string& encryptedKey,
    const core::PublicKey& authorPubKey
) {
    std::string encKey;
    std::shared_ptr<const core::Exception> error;
    try {
        encKey = core::Ecies::decryptFromBase64(_key, encryptedKey, authorPubKey);
    } catch (const privmx::endpoint::core::Exception& e) { error = core::asError(e); } catch (...) {
        error = core::unknownError("decrypting the event encryption key");
    }
    return DecryptedEventEncKeyV1{
        core::DecryptedVersionedData{.dataStructureVersion = 1, .error = error}, encKey
    };
}
std::vector<server::UserKey> EventKeyProvider::prepareKeysList(
    const std::vector<core::UserWithPubKey>& users,
    const std::string& key
) {
    std::vector<server::UserKey> userKeys;
    for (auto& user : users) {
        userKeys.push_back(
            server::UserKey{
                .id = user.userId,
                .key = core::Ecies::encryptToBase64(
                    core::PublicKeyCache::getInstance()->fromBase58DER(user.pubKey), key, _key
                )
            }
        );
    }
    return userKeys;
}
