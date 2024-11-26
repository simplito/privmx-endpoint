/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/stream/StreamRoomDataEncryptorV4.hpp"

#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/stream/StreamException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::stream;

server::EncryptedStreamRoomDataV4 StreamRoomDataEncryptorV4::encrypt(const StreamRoomDataToEncrypt& streamRoomData,
                                                                     const crypto::PrivateKey& authorPrivateKey,
                                                                     const std::string& encryptionKey) {
    auto result = utils::TypedObjectFactory::createNewObject<server::EncryptedStreamRoomDataV4>();
    result.version(4);
    result.publicMeta(_dataEncryptor.signAndEncode(streamRoomData.publicMeta, authorPrivateKey));
    try {
        result.publicMetaObject(utils::Utils::parseJsonObject(streamRoomData.publicMeta.stdString()));
    } catch (...) {
        result.publicMetaObjectClear();
    }
    result.privateMeta(
        _dataEncryptor.signAndEncryptAndEncode(streamRoomData.privateMeta, authorPrivateKey, encryptionKey));
    if (streamRoomData.internalMeta.has_value()) {
        result.internalMeta(
            _dataEncryptor.signAndEncryptAndEncode(streamRoomData.internalMeta.value(), authorPrivateKey, encryptionKey));
    }
    result.authorPubKey(authorPrivateKey.getPublicKey().toBase58DER());
    return result;
}

DecryptedStreamRoomData StreamRoomDataEncryptorV4::decrypt(
    const server::EncryptedStreamRoomDataV4& encryptedStreamRoomData, const std::string& encryptionKey) {
    validateVersion(encryptedStreamRoomData);
    DecryptedStreamRoomData result;
    result.statusCode = 0;
    try {
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedStreamRoomData.authorPubKey());
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedStreamRoomData.publicMeta(), authorPublicKey);
        if(!encryptedStreamRoomData.publicMetaObjectEmpty()) {
            auto tmp_1 = utils::Utils::stringify(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringify(encryptedStreamRoomData.publicMetaObject());
            if(tmp_1 != tmp_2) {
                auto e = StreamRoomPublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.privateMeta = _dataEncryptor.decodeAndDecryptAndVerify(encryptedStreamRoomData.privateMeta(), authorPublicKey, encryptionKey);
        result.internalMeta = encryptedStreamRoomData.internalMetaEmpty() ? 
            std::nullopt : 
            std::make_optional(_dataEncryptor.decodeAndDecryptAndVerify(encryptedStreamRoomData.internalMeta(), authorPublicKey, encryptionKey));
        result.authorPubKey = encryptedStreamRoomData.authorPubKey();   
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

void StreamRoomDataEncryptorV4::validateVersion(const server::EncryptedStreamRoomDataV4& encryptedStreamRoomData) {
    if (encryptedStreamRoomData.version() != 4) {
        throw InvalidEncryptedStreamRoomDataVersionException(std::to_string(encryptedStreamRoomData.version()) + " expected version: 4");
    }
}
