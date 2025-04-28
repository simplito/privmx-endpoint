/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/kvdb/encryptors/kvdb/KvdbDataEncryptorV5.hpp"

#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/kvdb/KvdbException.hpp"
#include "privmx/endpoint/kvdb/DynamicTypes.hpp"
#include "privmx/endpoint/kvdb/Constants.hpp"
#include <privmx/crypto/Crypto.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::kvdb;

server::EncryptedKvdbDataV5 KvdbDataEncryptorV5::encrypt(const KvdbDataToEncryptV5& kvdbData,
                                                                     const crypto::PrivateKey& authorPrivateKey,
                                                                     const std::string& encryptionKey) {
    auto result = utils::TypedObjectFactory::createNewObject<server::EncryptedKvdbDataV5>();
    result.version(KvdbDataSchema::Version::VERSION_5);
    std::unordered_map<std::string, std::string> fieldChecksums;
    result.publicMeta(_dataEncryptor.signAndEncode(kvdbData.publicMeta, authorPrivateKey));
    fieldChecksums.insert(std::make_pair("publicMeta",privmx::crypto::Crypto::sha256(result.publicMeta())));
    try {
        result.publicMetaObject(utils::Utils::parseJsonObject(kvdbData.publicMeta.stdString()));
    } catch (...) {
        result.publicMetaObjectClear();
    }
    result.privateMeta(_dataEncryptor.signAndEncryptAndEncode(kvdbData.privateMeta, authorPrivateKey, encryptionKey));
    fieldChecksums.insert(std::make_pair("privateMeta",privmx::crypto::Crypto::sha256(result.privateMeta())));
    auto internalMeta = utils::TypedObjectFactory::createNewObject<dynamic::KvdbInternalMetaV5>();
    internalMeta.secret(kvdbData.internalMeta.secret);
    internalMeta.resourceId(kvdbData.internalMeta.resourceId);
    internalMeta.randomId(kvdbData.internalMeta.randomId);
    result.internalMeta(_dataEncryptor.signAndEncryptAndEncode(core::Buffer::from(utils::Utils::stringifyVar(internalMeta)), authorPrivateKey, encryptionKey));
    fieldChecksums.insert(std::make_pair("internalMeta",privmx::crypto::Crypto::sha256(result.internalMeta())));
    result.authorPubKey(authorPrivateKey.getPublicKey().toBase58DER());
    core::ExpandedDataIntegrityObject expandedDio = {kvdbData.dio, .structureVersion=5, .fieldChecksums=fieldChecksums};
    result.dio(_DIOEncryptor.signAndEncode(expandedDio, authorPrivateKey));
    return result;
}

DecryptedKvdbDataV5 KvdbDataEncryptorV5::decrypt(const server::EncryptedKvdbDataV5& encryptedKvdbData, const std::string& encryptionKey) {
    DecryptedKvdbDataV5 result;
    result.statusCode = 0;
    result.dataStructureVersion = KvdbDataSchema::Version::VERSION_5;
    try {  
        result.dio = getDIOAndAssertIntegrity(encryptedKvdbData);
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedKvdbData.authorPubKey());
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedKvdbData.publicMeta(), authorPublicKey);
        if(!encryptedKvdbData.publicMetaObjectEmpty()) {
            auto tmp_1 = utils::Utils::stringify(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringify(encryptedKvdbData.publicMetaObject());
            if(tmp_1 != tmp_2) {
                auto e = KvdbPublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.privateMeta = _dataEncryptor.decodeAndDecryptAndVerify(encryptedKvdbData.privateMeta(), authorPublicKey, encryptionKey);
        auto internalMeta = _dataEncryptor.decodeAndDecryptAndVerify(encryptedKvdbData.internalMeta(), authorPublicKey, encryptionKey).stdString();
        auto internalMetaJSON = utils::TypedObjectFactory::createObjectFromVar<dynamic::KvdbInternalMetaV5>(utils::Utils::parseJsonObject(internalMeta));
        result.internalMeta = KvdbInternalMetaV5{.secret=internalMetaJSON.secret(), .resourceId=internalMetaJSON.resourceId(), .randomId=internalMetaJSON.randomId()};
        result.authorPubKey = encryptedKvdbData.authorPubKey();    
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}


DecryptedKvdbDataV5 KvdbDataEncryptorV5::extractPublic(const server::EncryptedKvdbDataV5& encryptedKvdbData) {
    DecryptedKvdbDataV5 result;
    result.statusCode = 0;
    result.dataStructureVersion = KvdbDataSchema::Version::VERSION_5;
    try {  
        result.dio = getDIOAndAssertIntegrity(encryptedKvdbData);
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedKvdbData.authorPubKey());
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedKvdbData.publicMeta(), authorPublicKey);
        if(!encryptedKvdbData.publicMetaObjectEmpty()) {
            auto tmp_1 = utils::Utils::stringify(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringify(encryptedKvdbData.publicMetaObject());
            if(tmp_1 != tmp_2) {
                auto e = KvdbPublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.authorPubKey = encryptedKvdbData.authorPubKey();   
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

core::DataIntegrityObject KvdbDataEncryptorV5::getDIOAndAssertIntegrity(const server::EncryptedKvdbDataV5& encryptedKvdbData) {
    assertDataFormat(encryptedKvdbData);
    auto encryptedDIO = encryptedKvdbData.dio();
    auto dio = _DIOEncryptor.decodeAndVerify(encryptedDIO);
    if (
        dio.structureVersion != KvdbDataSchema::Version::VERSION_5 ||
        dio.creatorPubKey != encryptedKvdbData.authorPubKey() ||
        dio.fieldChecksums.at("publicMeta") != privmx::crypto::Crypto::sha256(encryptedKvdbData.publicMeta()) ||
        dio.fieldChecksums.at("privateMeta") != privmx::crypto::Crypto::sha256(encryptedKvdbData.privateMeta()) ||
        dio.fieldChecksums.at("internalMeta") != privmx::crypto::Crypto::sha256(encryptedKvdbData.internalMeta())     
    ) {
        throw core::InvalidDataIntegrityObjectChecksumException();
    }
    return dio;
}

void KvdbDataEncryptorV5::assertDataFormat(const server::EncryptedKvdbDataV5& encryptedKvdbData) {
    if (encryptedKvdbData.versionEmpty() ||
        encryptedKvdbData.version() != KvdbDataSchema::Version::VERSION_5 ||
        encryptedKvdbData.publicMetaEmpty() ||
        encryptedKvdbData.privateMetaEmpty() ||
        encryptedKvdbData.internalMetaEmpty() ||
        encryptedKvdbData.authorPubKeyEmpty() ||
        encryptedKvdbData.dioEmpty()
    ) {
        throw InvalidEncryptedKvdbDataVersionException(std::to_string(encryptedKvdbData.version()) + " expected version: " + std::to_string(KvdbDataSchema::Version::VERSION_5));
    }
}
