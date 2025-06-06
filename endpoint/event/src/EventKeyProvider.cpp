/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/


#include "privmx/endpoint/event/EventKeyProvider.hpp"
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/crypto/CryptoException.hpp>

using namespace privmx::endpoint::event;

EventKeyProvider::EventKeyProvider(const privmx::crypto::PrivateKey& key) :
    _key(key) {}

std::string EventKeyProvider::generateKey() {
    return privmx::crypto::Crypto::randomBytes(32);
}
DecryptedEventEncKeyV1 EventKeyProvider::decryptKey(const std::string& encryptedKey, const privmx::crypto::PublicKey& authorPubKey) {
    std::string encKey;
    int64_t statusCode = 0;
    try {
        encKey = privmx::crypto::EciesEncryptor::decryptFromBase64(_key, encryptedKey, authorPubKey);
    } catch (const privmx::endpoint::core::Exception& e) {
        statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return DecryptedEventEncKeyV1{
        core::DecryptedVersionedData{
            .dataStructureVersion=1,
            .statusCode=statusCode
        },
        .key = encKey
    };
}
privmx::utils::List<server::UserKey> EventKeyProvider::prepareKeysList(
    const std::vector<core::UserWithPubKey>& users, 
    const std::string& key
) {
    utils::List<server::UserKey> userKeys = utils::TypedObjectFactory::createNewList<server::UserKey>();
    for (auto user : users) {
        server::UserKey userKey = utils::TypedObjectFactory::createNewObject<server::UserKey>();
        userKey.id(user.userId);
        userKey.key(privmx::crypto::EciesEncryptor::encryptToBase64(crypto::PublicKey::fromBase58DER(user.pubKey), key, _key));
        userKeys.add(userKey);
    }
    return userKeys;
}

