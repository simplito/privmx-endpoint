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
#include "privmx/endpoint/core/CoreConstants.hpp"
#include "privmx/endpoint/core/EndpointUtils.hpp"

#include "privmx/endpoint/core/KeyProvider.hpp"

using namespace privmx::endpoint::core;


void KeyDecryptionAndVerificationRequest::addOne(const utils::List<server::KeyEntry>& keys, const std::string& keyId, const EncKeyLocation& location) {
    if(_completed) {
        throw KeyProviderRequestCompletedException();
    }
    server::KeyEntry keyToDecrypt = utils::TypedObjectFactory::createNewObject<server::KeyEntry>();
    keyToDecrypt.keyId(keyId);
    keyToDecrypt.data(Poco::Dynamic::Var());
    for (auto key : keys) {
        if (key.keyId() == keyId) {
            keyToDecrypt = key;
            break;
        }
    }
    if(auto search = requestData.find(location); search != requestData.end()) {
        search->second.add(keyToDecrypt.keyId(), keyToDecrypt);
    } else {
        utils::Map<server::KeyEntry> toDecrypt = utils::TypedObjectFactory::createNewMap<server::KeyEntry>();
        toDecrypt.add(keyToDecrypt.keyId(), keyToDecrypt);
        requestData.insert(std::make_pair(location, toDecrypt));
    }
}

void KeyDecryptionAndVerificationRequest::addMany(const utils::List<server::KeyEntry>& keys, std::set<std::string> keyIds, const EncKeyLocation& location) {
    if(_completed) {
        throw KeyProviderRequestCompletedException();
    }
    utils::List<server::KeyEntry> keysToDecrypt = utils::TypedObjectFactory::createNewList<server::KeyEntry>();
    for (auto key : keys) {
        if(std::find(keyIds.begin(), keyIds.end(), key.keyId()) != keyIds.end()) {
            keysToDecrypt.add(key);
            keyIds.erase(key.keyId());
        }
    }
    for(std::string keyId : keyIds) {
        server::KeyEntry keyToDecrypt = utils::TypedObjectFactory::createNewObject<server::KeyEntry>();
        keyToDecrypt.keyId(keyId);
        keyToDecrypt.data(Poco::Dynamic::Var());
        keysToDecrypt.add(keyToDecrypt);
    }
    if(auto search = requestData.find(location); search != requestData.end()) {
        for(auto keyToDecrypt : keysToDecrypt) {
            search->second.add(keyToDecrypt.keyId(), keyToDecrypt);
        }
    } else {
        utils::Map<server::KeyEntry> toDecrypt = utils::TypedObjectFactory::createNewMap<server::KeyEntry>();
        for(auto keyToDecrypt : keysToDecrypt) {
            toDecrypt.add(keyToDecrypt.keyId(), keyToDecrypt);
        }
        requestData.insert(std::make_pair(location, toDecrypt));
    }
}

void KeyDecryptionAndVerificationRequest::addAll(const utils::List<server::KeyEntry>& keys, const EncKeyLocation& location) {
    if(_completed) {
        throw KeyProviderRequestCompletedException();
    }
    if(auto search = requestData.find(location); search != requestData.end()) {
        for(auto key : keys) {
            search->second.add(key.keyId(), key);
        }
    } else {
        utils::Map<server::KeyEntry> toDecrypt = utils::TypedObjectFactory::createNewMap<server::KeyEntry>();
        for(auto key : keys) {
            toDecrypt.add(key.keyId(), key);
        }
        requestData.insert(std::make_pair(location, toDecrypt));
    }
}
void KeyDecryptionAndVerificationRequest::markAsCompleted() {
    _completed = true;
}

KeyProvider::KeyProvider(const privmx::crypto::PrivateKey& key, std::function<std::shared_ptr<UserVerifier>()> getUserVerifier) : _key(key), _getUserVerifier(getUserVerifier) {}

EncKey KeyProvider::generateKey() {
    return {
        .id = privmx::utils::Hex::from(privmx::crypto::Crypto::randomBytes(16)),
        .key = privmx::crypto::Crypto::randomBytes(32)
    };
}

std::string KeyProvider::generateSecret() {
    return privmx::utils::Hex::from(privmx::crypto::Crypto::randomBytes(32));
}

std::unordered_map<EncKeyLocation,std::unordered_map<std::string, DecryptedEncKeyV2>> KeyProvider::getKeysAndVerify(const KeyDecryptionAndVerificationRequest& request) {
    std::unordered_map<EncKeyLocation,std::unordered_map<std::string, DecryptedEncKeyV2>> result;
    for (auto locationKeyMap : request.requestData) {
        auto locationResult = decryptAndVerifyKeys(locationKeyMap.second, locationKeyMap.first);
        result.insert(std::make_pair(locationKeyMap.first, locationResult));
    }
    verifyUserData(result);
    return result;
}

privmx::utils::List<server::KeyEntrySet> KeyProvider::prepareKeysList(
    const std::vector<UserWithPubKey>& users, 
    const EncKey& key, 
    const DataIntegrityObject& dio, 
    const EncKeyLocation& location, 
    const std::string& containerSecret
) {
    utils::List<server::KeyEntrySet> result = utils::TypedObjectFactory::createNewList<server::KeyEntrySet>();
    for (auto user : users) {
        result.add(createKeyEntrySet(user, key, dio, location, containerSecret));
    }    
    return result;
}

privmx::utils::List<server::KeyEntrySet> KeyProvider::prepareMissingKeysForNewUsers(
    const std::unordered_map<std::string, DecryptedEncKeyV2>& missingKeys, 
    const std::vector<UserWithPubKey>& users, 
    const DataIntegrityObject& dio, 
    const EncKeyLocation& location, 
    const std::string& containerSecret
) {
    utils::List<server::KeyEntrySet> result = utils::TypedObjectFactory::createNewList<server::KeyEntrySet>();
    for (auto t : missingKeys) {
        auto key = t.second;
        DataIntegrityObject missingKeyDIO = dio;
        if(key.dataStructureVersion == EncryptionKeyDataSchema::Version::VERSION_1) {
            missingKeyDIO.randomId = EndpointUtils::generateDIORandomId();
        } else {
            missingKeyDIO.randomId = t.second.dio.randomId;
        }
        if(key.statusCode != 0) continue;
        for (auto user : users) {
            result.add(createKeyEntrySet(user, key, missingKeyDIO, location, containerSecret));
        }
    }
    return result;
}

server::KeyEntrySet KeyProvider::createKeyEntrySet(
    const UserWithPubKey& user,
    const EncKey& key, 
    const DataIntegrityObject& dio, 
    const EncKeyLocation& location, 
    const std::string& containerSecret
) {
    auto keySecret = generateSecret();
    server::KeyEntrySet key_entry_set = utils::TypedObjectFactory::createNewObject<server::KeyEntrySet>();
    key_entry_set.user(user.userId);
    key_entry_set.keyId(key.id);
    key_entry_set.data(_encKeyEncryptorV2.encrypt(
        EncKeyV2ToEncrypt{
            EncKey{.id=key.id, .key=key.key}, 
            .dio=dio, 
            .location = location,
            .keySecret = keySecret,
            .secretHash = privmx::crypto::Crypto::hmacSha256(containerSecret ,keySecret + location.contextId + location.resourceId)
        }, 
        crypto::PublicKey::fromBase58DER(user.pubKey), _key)
    );
    return key_entry_set;
}


bool KeyProvider::verifyKeysSecret(const std::unordered_map<std::string, DecryptedEncKeyV2>& decryptedKeys, const EncKeyLocation& location, const std::string& containerSecret) {
    for(auto key : decryptedKeys) {
        auto keySecretHash = privmx::crypto::Crypto::hmacSha256(containerSecret, key.second.keySecret + location.contextId + location.resourceId);
        if (   
            key.second.statusCode != 0 ||
            (key.second.dataStructureVersion == EncryptionKeyDataSchema::Version::VERSION_2 && key.second.secretHash != keySecretHash)
        ) {
            return false;
        }
    }
    return true;
}

std::unordered_map<std::string, DecryptedEncKeyV2> KeyProvider::decryptAndVerifyKeys(utils::Map<server::KeyEntry> keys, const EncKeyLocation& location) {
    std::unordered_map<std::string, DecryptedEncKeyV2> result;
    for(auto key : keys) {
        DecryptedEncKeyV2 decryptedEncKey;
        decryptedEncKey.statusCode = 0;
        if(key.second.data().type() == typeid(Poco::JSON::Object::Ptr)) {
            auto versioned = utils::TypedObjectFactory::createObjectFromVar<dynamic::VersionedData>(key.second.data());
            if(versioned.versionEmpty()) {
                throw UnknownEncryptionKeyVersionException();
            } else if(versioned.version() == EncryptionKeyDataSchema::Version::VERSION_2) { 
                DecryptedEncKeyV2 decryptedEncKey = _encKeyEncryptorV2.decrypt(
                    utils::TypedObjectFactory::createObjectFromVar<server::EncryptedKeyEntryDataV2>(key.second.data()),
                    _key
                );
                result.insert(std::make_pair(key.first,decryptedEncKey));
            }
        } else if(key.second.data().isString()) {
            decryptedEncKey.id = key.second.keyId();
            decryptedEncKey.key = _encKeyEncryptorV1.decrypt(key.second.data(), _key);
            decryptedEncKey.dataStructureVersion = EncryptionKeyDataSchema::Version::VERSION_1;
            decryptedEncKey.secretHash = "";
            result.insert(std::make_pair(key.first, decryptedEncKey));
        } else {
            decryptedEncKey.statusCode = UnknownEncryptionKeyVersionException().getCode();
            result.insert(std::make_pair(key.first, decryptedEncKey));
        }
    }
    verifyData(result, location);
    if(result.size() > 1) {
        verifyForDuplication(result);
    }
    return result;
}

void KeyProvider::verifyData(std::unordered_map<std::string, DecryptedEncKeyV2>& decryptedKeys, const EncKeyLocation& location) {
    //create data validation request
    for(auto it = decryptedKeys.begin(); it != decryptedKeys.end(); ++it) {
        if(it->second.statusCode == 0 && it->second.dataStructureVersion == EncryptionKeyDataSchema::Version::VERSION_2)  {
            if (it->second.dio.contextId != location.contextId ||
                it->second.dio.resourceId != location.resourceId
            ) {
                it->second.statusCode = EncryptionKeyContainerValidationException().getCode();
            }
        }
    }
}

void KeyProvider::verifyForDuplication(std::unordered_map<std::string, DecryptedEncKeyV2>& keys) {
    std::map<std::pair<std::string, int64_t>, std::string> duplicateMap;
    for(auto it = keys.begin(); it != keys.end(); ++it) {
        if(it->second.statusCode != 0 || it->second.dio.creatorPubKey == "") continue;
        auto keyNonce = it->second.dio.randomId;
        auto keyTimestamp = it->second.dio.timestamp;
        std::pair<std::pair<std::string, int64_t>, std::string> val = std::make_pair(std::make_pair(keyNonce,keyTimestamp), it->first);
        auto ret = duplicateMap.insert(val);
        if(ret.second==false) {
            auto e = DataIntegrityObjectDuplicatedException();
            it->second.statusCode = e.getCode();
            keys[ret.first->second].statusCode = e.getCode();
        }
    }
}

void KeyProvider::verifyUserData(std::unordered_map<EncKeyLocation,std::unordered_map<std::string, DecryptedEncKeyV2>>& decryptedKeys) {
    std::vector<std::pair<EncKeyLocation,std::string>> tmp;
    std::vector<VerificationRequest> verificationRequest;
    for(auto loc = decryptedKeys.begin(); loc != decryptedKeys.end(); ++loc) {
        for(auto it = loc->second.begin(); it != loc->second.end(); ++it) {
            if(it->second.statusCode == 0 && it->second.dataStructureVersion == EncryptionKeyDataSchema::Version::VERSION_2)  {
                tmp.push_back(std::make_pair(loc->first, it->first));
                verificationRequest.push_back(VerificationRequest{
                    .contextId = it->second.dio.contextId,
                    .senderId = it->second.dio.creatorUserId,
                    .senderPubKey = it->second.dio.creatorPubKey,
                    .date = it->second.dio.timestamp,
                    .bridgeIdentity = it->second.dio.bridgeIdentity
                });
            }
        }
    }
    auto verificationResult = _getUserVerifier()->verify(verificationRequest);
    for(size_t i = 0; i < verificationResult.size(); i++) {
        if(verificationResult[i] == false) {
            decryptedKeys[tmp[i].first][tmp[i].second].statusCode = UserVerificationFailureException().getCode();
        }
    }  
}