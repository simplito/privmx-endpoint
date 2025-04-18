/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/thread/encryptors/message/MessageDataEncryptorV5.hpp"

#include "privmx/utils/Utils.hpp"
#include "privmx/utils/Debug.hpp"
#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/thread/ThreadException.hpp"
#include <privmx/crypto/Crypto.hpp>
#include "privmx/endpoint/thread/Constants.hpp"


using namespace privmx::endpoint;
using namespace privmx::endpoint::thread;

server::EncryptedMessageDataV5 MessageDataEncryptorV5::encrypt(const MessageDataToEncryptV5& messageData,
                                                                     const crypto::PrivateKey& authorPrivateKey,
                                                                     const std::string& encryptionKey) {
    auto result = utils::TypedObjectFactory::createNewObject<server::EncryptedMessageDataV5>();
    result.version(MessageDataStructVersion::VERSION_5);
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
    core::ExpandedDataIntegrityObject expandedDio = {messageData.dio, .structureVersion=MessageDataStructVersion::VERSION_5, .fieldChecksums=fieldChecksums};
    result.dio(_DIOEncryptor.signAndEncode(expandedDio, authorPrivateKey));
    return result;
}

DecryptedMessageDataV5 MessageDataEncryptorV5::decrypt(
    const server::EncryptedMessageDataV5& encryptedMessageData, const std::string& encryptionKey) {
    DecryptedMessageDataV5 result;
    result.statusCode = 0;
    result.dataStructureVersion = MessageDataStructVersion::VERSION_5;
    try {
        result.dio = getDIOAndAssertIntegrity(encryptedMessageData);
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedMessageData.authorPubKey());
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedMessageData.publicMeta(), authorPublicKey);
        if(!encryptedMessageData.publicMetaObjectEmpty()) {
            auto tmp_1 = utils::Utils::stringify(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringify(encryptedMessageData.publicMetaObject());
            if(tmp_1 != tmp_2) {
                auto e = MessagePublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.privateMeta = _dataEncryptor.decodeAndDecryptAndVerify(encryptedMessageData.privateMeta(), authorPublicKey, encryptionKey);
        result.data = _dataEncryptor.decodeAndDecryptAndVerify(encryptedMessageData.data(), authorPublicKey, encryptionKey);
        result.internalMeta = encryptedMessageData.internalMetaEmpty() ? 
            std::nullopt : 
            std::make_optional(_dataEncryptor.decodeAndDecryptAndVerify(encryptedMessageData.internalMeta(), authorPublicKey, encryptionKey));
        result.authorPubKey = encryptedMessageData.authorPubKey();   
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

DecryptedMessageDataV5 MessageDataEncryptorV5::extractPublic(const server::EncryptedMessageDataV5& encryptedMessageData) {
    DecryptedMessageDataV5 result;
    result.statusCode = 0;
    result.dataStructureVersion = MessageDataStructVersion::VERSION_5;
    try {
        result.dio = getDIOAndAssertIntegrity(encryptedMessageData);
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedMessageData.authorPubKey());
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedMessageData.publicMeta(), authorPublicKey);
        if(!encryptedMessageData.publicMetaObjectEmpty()) {
            auto tmp_1 = utils::Utils::stringify(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringify(encryptedMessageData.publicMetaObject());
            if(tmp_1 != tmp_2) {
                auto e = MessagePublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.authorPubKey = encryptedMessageData.authorPubKey();   
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

core::DataIntegrityObject MessageDataEncryptorV5::getDIOAndAssertIntegrity(const server::EncryptedMessageDataV5& encryptedMessageData) {
    assertDataFormat(encryptedMessageData);
    auto dio = _DIOEncryptor.decodeAndVerify(encryptedMessageData.dio());
    if (
        dio.structureVersion != MessageDataStructVersion::VERSION_5 ||
        dio.creatorPubKey != encryptedMessageData.authorPubKey() ||
        dio.fieldChecksums.at("publicMeta") != privmx::crypto::Crypto::sha256(encryptedMessageData.publicMeta()) ||
        dio.fieldChecksums.at("privateMeta") != privmx::crypto::Crypto::sha256(encryptedMessageData.privateMeta()) ||
        dio.fieldChecksums.at("data") != privmx::crypto::Crypto::sha256(encryptedMessageData.data()) || (
            !encryptedMessageData.internalMetaEmpty() &&
            dio.fieldChecksums.at("internalMeta") != privmx::crypto::Crypto::sha256(encryptedMessageData.internalMeta())
        )
    ) {
        throw core::InvalidDataIntegrityObjectChecksumException();
    }
    return dio;
}

void MessageDataEncryptorV5::assertDataFormat(const server::EncryptedMessageDataV5& encryptedMessageData) {
    if (encryptedMessageData.versionEmpty() ||
        encryptedMessageData.version() != MessageDataStructVersion::VERSION_5 ||
        encryptedMessageData.publicMetaEmpty() ||
        encryptedMessageData.privateMetaEmpty() ||
        encryptedMessageData.authorPubKeyEmpty() ||
        encryptedMessageData.dataEmpty() ||
        encryptedMessageData.dioEmpty()
    ) {
        throw InvalidEncryptedMessageDataVersionException(std::to_string(encryptedMessageData.version()) + " expected version: 5");
    }
}
