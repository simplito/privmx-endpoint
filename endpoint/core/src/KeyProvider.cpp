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

KeyProvider::KeyProvider(const privmx::crypto::PrivateKey& key, std::function<std::shared_ptr<UserVerifierInterface>()> getUserVerifier) : _key(key), _getUserVerifier(getUserVerifier) {}

EncKey KeyProvider::generateKey() {
    return {
        .id = privmx::utils::Hex::from(privmx::crypto::Crypto::randomBytes(16)),
        .key = privmx::crypto::Crypto::randomBytes(32)
    };
}

std::string KeyProvider::generateContainerControlNumber() {
    return privmx::utils::Hex::from(privmx::crypto::Crypto::randomBytes(8));
}

DecryptedEncKeyV2 KeyProvider::getKeyAndVerify(const utils::List<server::KeyEntry>& keys, const std::string& keyId, const EncKeyV2IntegrityValidationData& integrityValidationData) {
    utils::List<server::KeyEntry> toDecrypt = utils::TypedObjectFactory::createNewList<server::KeyEntry>();
    for (auto key : keys) {
        if (key.keyId() == keyId) {
            toDecrypt.add(key);
        }
    }
    if(toDecrypt.size()!=1) {
        throw NoUserEntryForGivenKeyIdException();
    }
    auto result = decryptKeysAndVerify(toDecrypt, integrityValidationData);
    return result.at(0);
    
}

std::map<std::string, DecryptedEncKeyV2> KeyProvider::getKeysAndVerify(const utils::List<server::KeyEntry>& keys, const std::set<std::string>& keyIds, const EncKeyV2IntegrityValidationData& integrityValidationData) {
    utils::List<server::KeyEntry> toDecrypt = utils::TypedObjectFactory::createNewList<server::KeyEntry>();
    for (auto key: keys) {
        if(std::find(keyIds.begin(), keyIds.end(), key.keyId()) != keyIds.end()) {
            toDecrypt.add(key);
        }
    }
    if(toDecrypt.size() == 0) return std::map<std::string, DecryptedEncKeyV2>();
    auto decrypted = decryptKeysAndVerify(toDecrypt, integrityValidationData);
    validateKeyForDuplication(decrypted);
    std::map<std::string, DecryptedEncKeyV2> result;
    for (auto key: decrypted) {
        result.insert(std::make_pair(key.id,key));
    }
    return result;
}

std::vector<DecryptedEncKeyV2> KeyProvider::getAllKeysAndVerify(const utils::List<server::KeyEntry>& serverKeys, const EncKeyV2IntegrityValidationData& integrityValidationData) {
    auto result = decryptKeysAndVerify(serverKeys, integrityValidationData);
    validateKeyForDuplication(result);
    return result;
}

privmx::utils::List<server::KeyEntrySet> KeyProvider::prepareKeysList(const std::vector<UserWithPubKey>& users, const EncKey& key, const DataIntegrityObject& dio, std::string containerControlNumber) {
    utils::List<server::KeyEntrySet> result = utils::TypedObjectFactory::createNewList<server::KeyEntrySet>();
    for (auto user : users) {
        server::KeyEntrySet key_entry_set = utils::TypedObjectFactory::createNewObject<server::KeyEntrySet>();
        key_entry_set.user(user.userId);
        key_entry_set.keyId(key.id);
        key_entry_set.data(
            _encKeyEncryptorV2.encrypt(
                EncKeyV2ToEncrypt{
                    key, 
                    .dio=dio, 
                    .containerControlNumber = containerControlNumber
                }, 
                crypto::PublicKey::fromBase58DER(user.pubKey), 
                _key
            )
        );
        result.add(key_entry_set);
    }    
    return result;
}

privmx::utils::List<server::KeyEntrySet> KeyProvider::prepareMissingKeysForNewUsers(const std::vector<DecryptedEncKeyV2>& missingKeys, const std::vector<UserWithPubKey>& users, const DataIntegrityObject& dio, std::string containerControlNumber) {
    utils::List<server::KeyEntrySet> result = utils::TypedObjectFactory::createNewList<server::KeyEntrySet>();
    for (auto missingKey : missingKeys) {
        if(missingKey.statusCode != 0) continue;
        for (auto user : users) {
            server::KeyEntrySet key_entry_set = utils::TypedObjectFactory::createNewObject<server::KeyEntrySet>();
            key_entry_set.user(user.userId);
            key_entry_set.keyId(missingKey.id);
            key_entry_set.data(_encKeyEncryptorV2.encrypt(EncKeyV2ToEncrypt{EncKey{.id=missingKey.id, .key=missingKey.key}, .dio=dio, .containerControlNumber = containerControlNumber}, crypto::PublicKey::fromBase58DER(user.pubKey), _key));
            result.add(key_entry_set);
        }
    }
    return result;
}

std::vector<DecryptedEncKeyV2> KeyProvider::decryptKeysAndVerify(utils::List<server::KeyEntry> keys, const EncKeyV2IntegrityValidationData& integrityValidationData) {
    std::vector<DecryptedEncKeyV2> result;
    for(auto key : keys) {
        DecryptedEncKeyV2 decryptedEncKey;
        decryptedEncKey.statusCode = 0;
        if(key.data().type() == typeid(Poco::JSON::Object::Ptr)) {
            auto versioned = utils::TypedObjectFactory::createObjectFromVar<server::VersionedData>(key.data());
            if(versioned.versionEmpty()) {
                throw UnknownEncryptionKeyVersionException();
            } else if(versioned.version() == 2) { 
                DecryptedEncKeyV2 decryptedEncKey = _encKeyEncryptorV2.decrypt(
                    utils::TypedObjectFactory::createObjectFromVar<server::EncryptedKeyEntryDataV2>(key.data()),
                    _key
                );
                result.push_back(decryptedEncKey);
            }
        } else if(key.data().isString()) {
            decryptedEncKey.id = key.keyId();
            decryptedEncKey.key = _encKeyEncryptorV1.decrypt(key.data(), _key);
            decryptedEncKey.dataStructureVersion = 1;
            decryptedEncKey.containerControlNumber = 0;
            result.push_back(decryptedEncKey);
        } else {
            decryptedEncKey.statusCode = UnknownEncryptionKeyVersionException().getCode();
            result.push_back(decryptedEncKey);
        }
        
    }
    validateData(result, integrityValidationData);
    return result;
}

void KeyProvider::validateData(std::vector<DecryptedEncKeyV2>& decryptedKeys, const EncKeyV2IntegrityValidationData& integrityValidationData) {

    std::optional<int64_t> containerControlNumber = std::nullopt;
    //create data validation request
    for(size_t i = 0; i<decryptedKeys.size();i++) {
        if(decryptedKeys[i].statusCode == 0 && decryptedKeys[i].dataStructureVersion == 2)  {
            if(!containerControlNumber.has_value()) {
                containerControlNumber = decryptedKeys[i].containerControlNumber;
            }
            if (decryptedKeys[i].dio.contextId != integrityValidationData.contextId ||
                decryptedKeys[i].dio.containerId != integrityValidationData.containerId ||
                decryptedKeys[i].containerControlNumber != containerControlNumber.value()
            ) {
                decryptedKeys[i].statusCode = EncryptionKeyContainerValidationException().getCode();
            }
        }
    }
    if(integrityValidationData.enableVerificationRequest) validateUserData(decryptedKeys);
}

void KeyProvider::validateUserData(std::vector<DecryptedEncKeyV2>& decryptedKeys) {
    std::vector<size_t> tmp;
    std::vector<VerificationRequest> verificationRequest;
    for(size_t i = 0; i<decryptedKeys.size();i++) {
        if(decryptedKeys[i].statusCode == 0 && decryptedKeys[i].dataStructureVersion == 2)  {
            tmp.push_back(i);
            verificationRequest.push_back(VerificationRequest{
                .contextId = decryptedKeys[i].dio.contextId,
                .senderId = decryptedKeys[i].dio.creatorUserId,
                .senderPubKey = decryptedKeys[i].dio.creatorPubKey,
                .date = decryptedKeys[i].dio.timestamp
            });
        }
    }
    auto verificationResult = _getUserVerifier()->verify(verificationRequest);
    for(size_t i = 0; i < verificationResult.size(); i++) {
        if(verificationResult[i] == false) {
            decryptedKeys[tmp[i]].statusCode = UserVerificationFailureException().getCode();
        }
    }  
}


void KeyProvider::validateKeyForDuplication(std::vector<DecryptedEncKeyV2>& keys) {
    std::map<std::pair<int64_t, int64_t>, size_t> duplicateMap;
    for(size_t i = 0; i < keys.size(); i++ ) {
        if(keys[i].statusCode != 0 || keys[i].dio.creatorPubKey == "") continue;
        auto keyNonce = keys[i].dio.randomId;
        auto keyTimestamp = keys[i].dio.timestamp;
        std::pair<std::pair<int64_t, int64_t>, size_t> val = std::make_pair(std::make_pair(keyNonce,keyTimestamp), i);
        auto ret = duplicateMap.insert(val);
        if(ret.second==false) {
            auto e = DataIntegrityObjectDuplicatedException();
            keys[i].statusCode = e.getCode();
            keys[ret.first->second].statusCode = e.getCode();
        }
    }
}