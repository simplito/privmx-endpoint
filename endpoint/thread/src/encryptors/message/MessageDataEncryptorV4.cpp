/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/thread/encryptors/message/MessageDataEncryptorV4.hpp"

#include "privmx/utils/Utils.hpp"
#include "privmx/utils/Debug.hpp"
#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/thread/ThreadException.hpp"


using namespace privmx::endpoint;
using namespace privmx::endpoint::thread;

server::EncryptedMessageDataV4 MessageDataEncryptorV4::encrypt(const MessageDataToEncryptV4& messageData,
                                                                     const crypto::PrivateKey& authorPrivateKey,
                                                                     const std::string& encryptionKey) {
    auto result = utils::TypedObjectFactory::createNewObject<server::EncryptedMessageDataV4>();
    result.version(4);
    result.publicMeta(_dataEncryptor.signAndEncode(messageData.publicMeta, authorPrivateKey));
    try {
        result.publicMetaObject(utils::Utils::parseJsonObject(messageData.publicMeta.stdString()));
    } catch (...) {
        result.publicMetaObjectClear();
    }
    result.privateMeta(
        _dataEncryptor.signAndEncryptAndEncode(messageData.privateMeta, authorPrivateKey, encryptionKey));
    result.data(_dataEncryptor.signAndEncryptAndEncode(messageData.data, authorPrivateKey, encryptionKey));
    if (messageData.internalMeta.has_value()) {
        result.internalMeta(
            _dataEncryptor.signAndEncryptAndEncode(messageData.internalMeta.value(), authorPrivateKey, encryptionKey));
    }
    result.authorPubKey(authorPrivateKey.getPublicKey().toBase58DER());
    return result;
}

DecryptedMessageDataV4 MessageDataEncryptorV4::decrypt(
    const server::EncryptedMessageDataV4& encryptedMessageData, const std::string& encryptionKey) {
    DecryptedMessageDataV4 result;
    result.statusCode = 0;
    result.dataStructureVersion = 4;
    try {
        validateVersion(encryptedMessageData);
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

void MessageDataEncryptorV4::validateVersion(const server::EncryptedMessageDataV4& encryptedMessageData) {
    if (encryptedMessageData.version() != 4) {
        throw InvalidEncryptedMessageDataVersionException(std::to_string(encryptedMessageData.version()) + " expected version: 4");
    }
}
