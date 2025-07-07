/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/kvdb/encryptors/entry/EntryDataEncryptorV5.hpp"
#include "privmx/utils/Utils.hpp"
#include "privmx/utils/Debug.hpp"
#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/kvdb/KvdbException.hpp"
#include "privmx/endpoint/kvdb/Constants.hpp"
#include <privmx/crypto/Crypto.hpp>


using namespace privmx::endpoint;
using namespace privmx::endpoint::kvdb;

server::EncryptedKvdbEntryDataV5 EntryDataEncryptorV5::encrypt(const KvdbEntryDataToEncryptV5& messageData,
                                                                     const crypto::PrivateKey& authorPrivateKey,
                                                                     const std::string& encryptionKey) {
    auto result = utils::TypedObjectFactory::createNewObject<server::EncryptedKvdbEntryDataV5>();
    result.version(KvdbEntryDataSchema::Version::VERSION_5);
    std::unordered_map<std::string, std::string> fieldChecksums;
    result.publicMeta(_dataEncryptor.signAndEncode(messageData.publicMeta, authorPrivateKey));
    fieldChecksums.insert(std::make_pair("publicMeta",privmx::crypto::Crypto::sha256(result.publicMeta())));
    try {
        result.publicMetaObject(utils::Utils::parseJsonObject(messageData.publicMeta.stdString()));
    } catch (...) {
        result.publicMetaObjectClear();
    }
    result.privateMeta(_dataEncryptor.signAndEncryptAndEncode(messageData.privateMeta, authorPrivateKey, encryptionKey));
    fieldChecksums.insert(std::make_pair("privateMeta",privmx::crypto::Crypto::sha256(result.privateMeta())));
    result.data(_dataEncryptor.signAndEncryptAndEncode(messageData.data, authorPrivateKey, encryptionKey));
    fieldChecksums.insert(std::make_pair("data",privmx::crypto::Crypto::sha256(result.data())));
    if (messageData.internalMeta.has_value()) {
        result.internalMeta(_dataEncryptor.signAndEncryptAndEncode(messageData.internalMeta.value(), authorPrivateKey, encryptionKey));
        fieldChecksums.insert(std::make_pair("internalMeta",privmx::crypto::Crypto::sha256(result.internalMeta())));
    }
    result.authorPubKey(authorPrivateKey.getPublicKey().toBase58DER());
    core::ExpandedDataIntegrityObject expandedDio = {messageData.dio, .structureVersion=5, .fieldChecksums=fieldChecksums};
    result.dio(_DIOEncryptor.signAndEncode(expandedDio, authorPrivateKey));
    return result;
}

DecryptedKvdbEntryDataV5 EntryDataEncryptorV5::decrypt(const server::EncryptedKvdbEntryDataV5& encryptedEntryData, const std::string& encryptionKey) {
    DecryptedKvdbEntryDataV5 result;
    result.statusCode = 0;
    result.dataStructureVersion = KvdbEntryDataSchema::Version::VERSION_5;
    try {
        result.dio = getDIOAndAssertIntegrity(encryptedEntryData);
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedEntryData.authorPubKey());
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedEntryData.publicMeta(), authorPublicKey);
        if(!encryptedEntryData.publicMetaObjectEmpty()) {
            auto tmp_1 = utils::Utils::stringify(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringify(encryptedEntryData.publicMetaObject());
            if(tmp_1 != tmp_2) {
                auto e = KvdbEntryPublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.privateMeta = _dataEncryptor.decodeAndDecryptAndVerify(encryptedEntryData.privateMeta(), authorPublicKey, encryptionKey);
        result.data = _dataEncryptor.decodeAndDecryptAndVerify(encryptedEntryData.data(), authorPublicKey, encryptionKey);
        result.internalMeta = encryptedEntryData.internalMetaEmpty() ? 
            std::nullopt : 
            std::make_optional(_dataEncryptor.decodeAndDecryptAndVerify(encryptedEntryData.internalMeta(), authorPublicKey, encryptionKey));
        result.authorPubKey = encryptedEntryData.authorPubKey();   
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

DecryptedKvdbEntryDataV5 EntryDataEncryptorV5::extractPublic(const server::EncryptedKvdbEntryDataV5& encryptedEntryData) {
    DecryptedKvdbEntryDataV5 result;
    result.statusCode = 0;
    result.dataStructureVersion = KvdbEntryDataSchema::Version::VERSION_5;
    try {
        result.dio = getDIOAndAssertIntegrity(encryptedEntryData);
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedEntryData.authorPubKey());
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedEntryData.publicMeta(), authorPublicKey);
        if(!encryptedEntryData.publicMetaObjectEmpty()) {
            auto tmp_1 = utils::Utils::stringify(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringify(encryptedEntryData.publicMetaObject());
            if(tmp_1 != tmp_2) {
                auto e = KvdbEntryPublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.authorPubKey = encryptedEntryData.authorPubKey();   
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

core::DataIntegrityObject EntryDataEncryptorV5::getDIOAndAssertIntegrity(const server::EncryptedKvdbEntryDataV5& encryptedEntryData) {
    assertDataFormat(encryptedEntryData);
    auto dio = _DIOEncryptor.decodeAndVerify(encryptedEntryData.dio());
    if (
        dio.structureVersion != KvdbEntryDataSchema::Version::VERSION_5 ||
        dio.creatorPubKey != encryptedEntryData.authorPubKey() ||
        dio.fieldChecksums.at("publicMeta") != privmx::crypto::Crypto::sha256(encryptedEntryData.publicMeta()) ||
        dio.fieldChecksums.at("privateMeta") != privmx::crypto::Crypto::sha256(encryptedEntryData.privateMeta()) ||
        dio.fieldChecksums.at("data") != privmx::crypto::Crypto::sha256(encryptedEntryData.data()) || (
            !encryptedEntryData.internalMetaEmpty() &&
            dio.fieldChecksums.at("internalMeta") != privmx::crypto::Crypto::sha256(encryptedEntryData.internalMeta())
        )
    ) {
        throw core::InvalidDataIntegrityObjectChecksumException();
    }
    return dio;
}

void EntryDataEncryptorV5::assertDataFormat(const server::EncryptedKvdbEntryDataV5& encryptedEntryData) {
    if (encryptedEntryData.versionEmpty() ||
        encryptedEntryData.version() != KvdbEntryDataSchema::Version::VERSION_5 ||
        encryptedEntryData.publicMetaEmpty() ||
        encryptedEntryData.privateMetaEmpty() ||
        encryptedEntryData.authorPubKeyEmpty() ||
        encryptedEntryData.dataEmpty() ||
        encryptedEntryData.dioEmpty()
    ) {
        throw InvalidEncryptedKvdbEntryDataVersionException(std::to_string(encryptedEntryData.version()) + " expected version: " + std::to_string(KvdbEntryDataSchema::Version::VERSION_5));
    }
}
