/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/encryptors/store/StoreDataEncryptorV5.hpp"

#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/store/StoreException.hpp"
#include <privmx/crypto/Crypto.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

server::EncryptedStoreDataV5 StoreDataEncryptorV5::encrypt(const StoreDataToEncryptV5& storeData,
                                                                     const crypto::PrivateKey& authorPrivateKey,
                                                                     const std::string& encryptionKey) {
    auto result = utils::TypedObjectFactory::createNewObject<server::EncryptedStoreDataV5>();
    result.version(5);
    std::unordered_map<std::string, std::string> fieldChecksums;
    result.publicMeta(_dataEncryptor.signAndEncode(storeData.publicMeta, authorPrivateKey));
    fieldChecksums.insert(std::make_pair("publicMeta",privmx::crypto::Crypto::sha256(result.publicMeta())));
    try {
        result.publicMetaObject(utils::Utils::parseJsonObject(storeData.publicMeta.stdString()));
    } catch (...) {
        result.publicMetaObjectClear();
    }
    result.privateMeta(_dataEncryptor.signAndEncryptAndEncode(storeData.privateMeta, authorPrivateKey, encryptionKey));
    fieldChecksums.insert(std::make_pair("privateMeta",privmx::crypto::Crypto::sha256(result.privateMeta())));
    result.internalMeta(_dataEncryptor.signAndEncryptAndEncode(storeData.internalMeta, authorPrivateKey, encryptionKey));
    fieldChecksums.insert(std::make_pair("internalMeta",privmx::crypto::Crypto::sha256(result.internalMeta())));
    result.authorPubKey(authorPrivateKey.getPublicKey().toBase58DER());
    core::ExpandedDataIntegrityObject expandedDio = {storeData.dio, .structureVersion=5, .fieldChecksums=fieldChecksums};
    result.dio(_DIOEncryptor.signAndEncode(expandedDio, authorPrivateKey));
    return result;
}

DecryptedStoreDataV5 StoreDataEncryptorV5::decrypt(
    const server::EncryptedStoreDataV5& encryptedStoreData, const std::string& encryptionKey) {
    DecryptedStoreDataV5 result;
    result.statusCode = 0;
    result.dataStructureVersion = 5;
    try {
        result.dio = getDIOAndAssertIntegrity(encryptedStoreData);
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedStoreData.authorPubKey());
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedStoreData.publicMeta(), authorPublicKey);
        if(!encryptedStoreData.publicMetaObjectEmpty()) {
            auto tmp_1 = utils::Utils::stringify(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringify(encryptedStoreData.publicMetaObject());
            if(tmp_1 != tmp_2) {
                auto e = StorePublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.privateMeta = _dataEncryptor.decodeAndDecryptAndVerify(encryptedStoreData.privateMeta(), authorPublicKey, encryptionKey);
        result.internalMeta = _dataEncryptor.decodeAndDecryptAndVerify(encryptedStoreData.internalMeta(), authorPublicKey, encryptionKey);
        result.authorPubKey = encryptedStoreData.authorPubKey();   
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

DecryptedStoreDataV5 StoreDataEncryptorV5::extractPublic(const server::EncryptedStoreDataV5& encryptedStoreData) {
    DecryptedStoreDataV5 result;
    result.statusCode = 0;
    result.dataStructureVersion = 5;
    try {
        result.dio = getDIOAndAssertIntegrity(encryptedStoreData);
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedStoreData.authorPubKey());
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedStoreData.publicMeta(), authorPublicKey);
        if(!encryptedStoreData.publicMetaObjectEmpty()) {
            auto tmp_1 = utils::Utils::stringify(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringify(encryptedStoreData.publicMetaObject());
            if(tmp_1 != tmp_2) {
                auto e = StorePublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.authorPubKey = encryptedStoreData.authorPubKey();   
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

core::DataIntegrityObject StoreDataEncryptorV5::getDIOAndAssertIntegrity(const server::EncryptedStoreDataV5& encryptedStoreData) {
    assertDataFormat(encryptedStoreData);
    auto dio = _DIOEncryptor.decodeAndVerify(encryptedStoreData.dio());
    if (
        dio.structureVersion != 5 ||
        dio.creatorPubKey != encryptedStoreData.authorPubKey() ||
        dio.fieldChecksums.at("publicMeta") != privmx::crypto::Crypto::sha256(encryptedStoreData.publicMeta()) ||
        dio.fieldChecksums.at("privateMeta") != privmx::crypto::Crypto::sha256(encryptedStoreData.privateMeta()) || 
        dio.fieldChecksums.at("internalMeta") != privmx::crypto::Crypto::sha256(encryptedStoreData.internalMeta())
    ) {
        throw core::InvalidDataIntegrityObjectChecksumException();
    }
    return dio;
}

void StoreDataEncryptorV5::assertDataFormat(const server::EncryptedStoreDataV5& encryptedStoreData) {
    if (encryptedStoreData.versionEmpty() ||
        encryptedStoreData.version() != 5 ||
        encryptedStoreData.publicMetaEmpty() ||
        encryptedStoreData.privateMetaEmpty() ||
        encryptedStoreData.authorPubKeyEmpty()
    ) {
        throw InvalidEncryptedStoreDataVersionException(std::to_string(encryptedStoreData.version()) + " expected version: 5");
    }
}