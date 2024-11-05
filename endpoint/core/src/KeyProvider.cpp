/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>
#include <privmx/crypto/EciesEncryptor.hpp>

#include <privmx/endpoint/core/CoreException.hpp>

#include "privmx/endpoint/core/KeyProvider.hpp"

using namespace privmx::endpoint::core;

KeyProvider::KeyProvider(const privmx::crypto::PrivateKey& key) : _key(key) {}

EncKey KeyProvider::generateKey() {
    return {
        .id = privmx::utils::Hex::from(privmx::crypto::Crypto::randomBytes(16)),
        .key = privmx::crypto::Crypto::randomBytes(32)
    };
}

EncKey KeyProvider::getKey(const utils::List<server::KeyEntry>& keys, const std::string& keyId) {
    for (auto key : keys) {
        if (key.keyId() == keyId) {
            return {
                .id = keyId,
                .key = privmx::crypto::EciesEncryptor::decryptFromBase64(_key, key.data())
            };
        }
    }
    throw NoUserEntryForGivenKeyIdException();
}

privmx::utils::List<server::KeyEntrySet> KeyProvider::prepareKeysList(const std::vector<UserWithPubKey>& users, const EncKey& key) {
    utils::List<server::KeyEntrySet> result = utils::TypedObjectFactory::createNewList<server::KeyEntrySet>();
    for (auto user : users) {
        server::KeyEntrySet key_entry_set = utils::TypedObjectFactory::createNewObject<server::KeyEntrySet>();
        key_entry_set.user(user.userId);
        key_entry_set.keyId(key.id);
        key_entry_set.data(crypto::EciesEncryptor::encryptToBase64(crypto::PublicKey::fromBase58DER(user.pubKey), key.key));
        result.add(key_entry_set);
    }
    return result;
}

// privmx::utils::List<server::KeyEntrySet> KeyProvider::updateKeysList(const utils::List<server::KeyEntrySet>& currentKeysList, const std::string& currentKeyId, const std::vector<UserWithPubKey>& newUsers, const EncKey& key) {
//     utils::List<server::KeyEntrySet> filteredKeysList = utils::TypedObjectFactory::createNewList<server::KeyEntrySet>();
//     for (auto entry : currentKeysList) {
//         if (currentKeyId.compare(entry.keyId()) == 0) {
//             filteredKeysList.add(entry);
//         }
//     }

//     utils::List<server::KeyEntrySet> result = utils::TypedObjectFactory::createNewList<server::KeyEntrySet>();
    
    
    
//     for (auto user : users) {
//         server::KeyEntrySet key_entry_set = utils::TypedObjectFactory::createNewObject<server::KeyEntrySet>();
//         key_entry_set.user(user.userId);
//         key_entry_set.keyId(key.id);
//         key_entry_set.data(crypto::EciesEncryptor::encryptToBase64(crypto::PublicKey::fromBase58DER(user.pubKey), key.key));
//         result.add(key_entry_set);
//     }
//     return result;
// }