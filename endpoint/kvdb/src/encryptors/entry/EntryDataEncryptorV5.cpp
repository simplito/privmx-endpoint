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
#include <privmx/crypto/Crypto.hpp>


using namespace privmx::endpoint;
using namespace privmx::endpoint::kvdb;

server::EncryptedKvdbEntryDataV5 EntryDataEncryptorV5::encrypt(const KvdbEntryDataToEncryptV5& messageData,
                                                                     const crypto::PrivateKey& authorPrivateKey,
                                                                     const std::string& encryptionKey) {
    auto result = utils::TypedObjectFactory::createNewObject<server::EncryptedKvdbEntryDataV5>();
    result.version(5);
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

DecryptedKvdbEntryDataV5 EntryDataEncryptorV5::decrypt(
    const server::EncryptedKvdbEntryDataV5& encryptedItemData, const std::string& encryptionKey) {
    DecryptedKvdbEntryDataV5 result;
    result.statusCode = 0;
    result.dataStructureVersion = 5;
    try {
        result.dio = getDIOAndAssertIntegrity(encryptedItemData);
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedItemData.authorPubKey());
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedItemData.publicMeta(), authorPublicKey);
        if(!encryptedItemData.publicMetaObjectEmpty()) {
            auto tmp_1 = utils::Utils::stringify(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringify(encryptedItemData.publicMetaObject());
            if(tmp_1 != tmp_2) {
                auto e = ItemPublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.privateMeta = _dataEncryptor.decodeAndDecryptAndVerify(encryptedItemData.privateMeta(), authorPublicKey, encryptionKey);
        result.data = _dataEncryptor.decodeAndDecryptAndVerify(encryptedItemData.data(), authorPublicKey, encryptionKey);
        result.internalMeta = encryptedItemData.internalMetaEmpty() ? 
            std::nullopt : 
            std::make_optional(_dataEncryptor.decodeAndDecryptAndVerify(encryptedItemData.internalMeta(), authorPublicKey, encryptionKey));
        result.authorPubKey = encryptedItemData.authorPubKey();   
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

DecryptedKvdbEntryDataV5 EntryDataEncryptorV5::extractPublic(const server::EncryptedKvdbEntryDataV5& encryptedItemData) {
    DecryptedKvdbEntryDataV5 result;
    result.statusCode = 0;
    result.dataStructureVersion = 5;
    try {
        result.dio = getDIOAndAssertIntegrity(encryptedItemData);
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedItemData.authorPubKey());
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedItemData.publicMeta(), authorPublicKey);
        if(!encryptedItemData.publicMetaObjectEmpty()) {
            auto tmp_1 = utils::Utils::stringify(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringify(encryptedItemData.publicMetaObject());
            if(tmp_1 != tmp_2) {
                auto e = ItemPublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.authorPubKey = encryptedItemData.authorPubKey();   
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

core::DataIntegrityObject EntryDataEncryptorV5::getDIOAndAssertIntegrity(const server::EncryptedKvdbEntryDataV5& encryptedItemData) {
    assertDataFormat(encryptedItemData);
    auto dio = _DIOEncryptor.decodeAndVerify(encryptedItemData.dio());
    if (
        dio.structureVersion != 5 ||
        dio.creatorPubKey != encryptedItemData.authorPubKey() ||
        dio.fieldChecksums.at("publicMeta") != privmx::crypto::Crypto::sha256(encryptedItemData.publicMeta()) ||
        dio.fieldChecksums.at("privateMeta") != privmx::crypto::Crypto::sha256(encryptedItemData.privateMeta()) ||
        dio.fieldChecksums.at("data") != privmx::crypto::Crypto::sha256(encryptedItemData.data()) || (
            !encryptedItemData.internalMetaEmpty() &&
            dio.fieldChecksums.at("internalMeta") != privmx::crypto::Crypto::sha256(encryptedItemData.internalMeta())
        )
    ) {
        throw core::InvalidDataIntegrityObjectChecksumException();
    }
    return dio;
}

void EntryDataEncryptorV5::assertDataFormat(const server::EncryptedKvdbEntryDataV5& encryptedItemData) {
    if (encryptedItemData.versionEmpty() ||
        encryptedItemData.version() != 5 ||
        encryptedItemData.publicMetaEmpty() ||
        encryptedItemData.privateMetaEmpty() ||
        encryptedItemData.authorPubKeyEmpty() ||
        encryptedItemData.dataEmpty() ||
        encryptedItemData.dioEmpty()
    ) {
        throw InvalidEncryptedItemDataVersionException(std::to_string(encryptedItemData.version()) + " expected version: 5");
    }
}
