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
#include "privmx/endpoint/core/ExceptionConverter.hpp"

#include "privmx/endpoint/core/KeyProvider.hpp"

using namespace privmx::endpoint::core;

KeyProvider::KeyProvider(const privmx::crypto::PrivateKey& key, std::shared_ptr<UserVerifierInterface> userVerifier) : _key(key), _userVerifier(userVerifier) {}

EncKey KeyProvider::generateKey() {
    return {
        .id = privmx::utils::Hex::from(privmx::crypto::Crypto::randomBytes(16)),
        .key = privmx::crypto::Crypto::randomBytes(32)
    };
}

EncKeyV2 KeyProvider::getKeyAndVaerify(const utils::List<server::KeyEntry>& keys, const std::string& keyId, const std::string& contextId, const std::string& containerId) {
    for (auto key : keys) {
        if (key.keyId() == keyId) {
            return decryptKeyAndVerify(key, contextId, containerId);
        }
    }
    throw NoUserEntryForGivenKeyIdException();
}

EncKeyV2 KeyProvider::getKey(const utils::List<server::KeyEntry>& keys, const std::string& keyId) {
    for (auto key : keys) {
        if (key.keyId() == keyId) {
            if(key.data().type() == typeid(Poco::JSON::Object::Ptr)) {
                auto versioned = utils::TypedObjectFactory::createObjectFromVar<server::VersionedData>(key.data());
                if(versioned.versionEmpty()) {
                    throw EncryptionKeyUnknownDataVersionException();
                } else if(versioned.version() == 2) { 
                    return _encKeyEncryptorV2.decrypt(
                        utils::TypedObjectFactory::createObjectFromVar<server::EncryptedKeyEntryDataV2>(versioned),
                        _key
                    );
                }
            } else if(key.data().isString()) {
                return EncKeyV2{ 
                    EncKey {
                        .id = key.keyId(),
                        .key = _encKeyEncryptorV1.decrypt(key.data(), _key)
                    },
                    .dio= DataIntegrityObject(),
                    .statusCode = 0
                };
            }
            throw EncryptionKeyUnknownDataVersionException();
        }
    }
    throw NoUserEntryForGivenKeyIdException();
}

privmx::utils::List<server::KeyEntrySet> KeyProvider::prepareKeysList(const std::vector<UserWithPubKey>& users, const EncKey& key, const DataIntegrityObject& dio) {
    utils::List<server::KeyEntrySet> result = utils::TypedObjectFactory::createNewList<server::KeyEntrySet>();
    for (auto user : users) {
        server::KeyEntrySet key_entry_set = utils::TypedObjectFactory::createNewObject<server::KeyEntrySet>();
        key_entry_set.user(user.userId);
        key_entry_set.keyId(key.id);
        key_entry_set.data(_encKeyEncryptorV2.encrypt(dio, key, crypto::PublicKey::fromBase58DER(user.pubKey), _key));
        result.add(key_entry_set);
    }
    return result;
}

privmx::utils::List<server::KeyEntrySet> KeyProvider::prepareOldKeysListForNewUsers(const utils::List<server::KeyEntry>& oldKeys, const std::vector<UserWithPubKey>& users, const DataIntegrityObject& dio) {
    utils::List<server::KeyEntrySet> result = utils::TypedObjectFactory::createNewList<server::KeyEntrySet>();
    for (auto oldKey : oldKeys) {
        auto key = privmx::crypto::EciesEncryptor::decryptFromBase64(_key, oldKey.data());
        for (auto user : users) {
            server::KeyEntrySet key_entry_set = utils::TypedObjectFactory::createNewObject<server::KeyEntrySet>();
            key_entry_set.user(user.userId);
            key_entry_set.keyId(oldKey.keyId());
            key_entry_set.data(_encKeyEncryptorV2.encrypt(dio, EncKey{.id=oldKey.keyId(), .key=key}, crypto::PublicKey::fromBase58DER(user.pubKey), _key));
            result.add(key_entry_set);
        }
    }
    return result;
}

EncKeyV2 KeyProvider::decryptKeyAndVerify(server::KeyEntry key, const std::string& contextId, const std::string& containerId) {
    if(key.data().type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = utils::TypedObjectFactory::createObjectFromVar<server::VersionedData>(key.data());
        if(versioned.versionEmpty()) {
            throw EncryptionKeyUnknownDataVersionException();
        } else if(versioned.version() == 2) { 
            EncKeyV2 decryptedKey = _encKeyEncryptorV2.decrypt(
                utils::TypedObjectFactory::createObjectFromVar<server::EncryptedKeyEntryDataV2>(versioned),
                _key
            );
            if(decryptedKey.statusCode == 0) {
                try {
                    verify(decryptedKey, contextId, containerId);
                }  catch (const privmx::endpoint::core::Exception& e) {
                    decryptedKey.statusCode = e.getCode();
                } catch (const privmx::utils::PrivmxException& e) {
                    decryptedKey.statusCode = ExceptionConverter::convert(e).getCode();
                } catch (...) {
                    decryptedKey.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
                }
            }
            return decryptedKey;
        }
    } else if(key.data().isString()) {
        return EncKeyV2{ 
            EncKey {
                .id = key.keyId(),
                .key = _encKeyEncryptorV1.decrypt(key.data(), _key)
            },
            .dio= DataIntegrityObject(),
            .statusCode = 0
        };
    }
    throw EncryptionKeyUnknownDataVersionException();
}

void KeyProvider::verify(EncKeyV2 decryptedKey, const std::string& contextId, const std::string& containerId) {
    std::vector<VerificationRequest> verificationRequest {
        VerificationRequest{
            .contextId = decryptedKey.dio.contextId,
            .senderId = decryptedKey.dio.creatorUserId,
            .senderPubKey = decryptedKey.dio.creatorPubKey,
            .date = decryptedKey.dio.timestamp
        }
    };
    auto verificationResult = _userVerifier->verify(verificationRequest);
    if(verificationResult[0] == false) {
        throw UserVerificationFailureException();
    }
}

void KeyProvider::validateServerKeys(const utils::List<server::KeyEntry>& serverKeys, const std::string& contextId, const std::string& containerId) {
}