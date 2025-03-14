/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/thread/encryptors/thread/ThreadDataEncryptorV4.hpp"

#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/thread/ThreadException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::thread;

server::EncryptedThreadDataV4 ThreadDataEncryptorV4::encrypt(const ThreadDataToEncryptV4& threadData,
                                                                     const crypto::PrivateKey& authorPrivateKey,
                                                                     const std::string& encryptionKey) {
    auto result = utils::TypedObjectFactory::createNewObject<server::EncryptedThreadDataV4>();
    result.version(4);
    result.publicMeta(_dataEncryptor.signAndEncode(threadData.publicMeta, authorPrivateKey));
    try {
        result.publicMetaObject(utils::Utils::parseJsonObject(threadData.publicMeta.stdString()));
    } catch (...) {
        result.publicMetaObjectClear();
    }
    result.privateMeta(
        _dataEncryptor.signAndEncryptAndEncode(threadData.privateMeta, authorPrivateKey, encryptionKey));
    if (threadData.internalMeta.has_value()) {
        result.internalMeta(
            _dataEncryptor.signAndEncryptAndEncode(threadData.internalMeta.value(), authorPrivateKey, encryptionKey));
    }
    result.authorPubKey(authorPrivateKey.getPublicKey().toBase58DER());
    return result;
}

DecryptedThreadDataV4 ThreadDataEncryptorV4::decrypt(
    const server::EncryptedThreadDataV4& encryptedThreadData, const std::string& encryptionKey) {
    DecryptedThreadDataV4 result;
    result.statusCode = 0;
    result.dataStructureVersion = 4;
    try {
        validateVersion(encryptedThreadData);
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedThreadData.authorPubKey());
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedThreadData.publicMeta(), authorPublicKey);
        if(!encryptedThreadData.publicMetaObjectEmpty()) {
            auto tmp_1 = utils::Utils::stringify(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringify(encryptedThreadData.publicMetaObject());
            if(tmp_1 != tmp_2) {
                auto e = ThreadPublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.privateMeta = _dataEncryptor.decodeAndDecryptAndVerify(encryptedThreadData.privateMeta(), authorPublicKey, encryptionKey);
        result.internalMeta = encryptedThreadData.internalMetaEmpty() ? 
            std::nullopt : 
            std::make_optional(_dataEncryptor.decodeAndDecryptAndVerify(encryptedThreadData.internalMeta(), authorPublicKey, encryptionKey));
        result.authorPubKey = encryptedThreadData.authorPubKey();   
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

void ThreadDataEncryptorV4::validateVersion(const server::EncryptedThreadDataV4& encryptedThreadData) {
    if (encryptedThreadData.version() != 4) {
        throw InvalidEncryptedThreadDataVersionException(std::to_string(encryptedThreadData.version()) + " expected version: 4");
    }
}
