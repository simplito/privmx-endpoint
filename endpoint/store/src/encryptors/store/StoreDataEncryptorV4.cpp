/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/encryptors/store/StoreDataEncryptorV4.hpp"

#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/store/StoreException.hpp"
#include "privmx/endpoint/store/Constants.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

server::EncryptedStoreDataV4 StoreDataEncryptorV4::encrypt(const StoreDataToEncryptV4& plainData,
                                                                     const crypto::PrivateKey& authorPrivateKey,
                                                                     const std::string& encryptionKey) {
    auto result = utils::TypedObjectFactory::createNewObject<server::EncryptedStoreDataV4>();
    result.version(StoreDataStructVersion::VERSION_4);
    result.publicMeta(_dataEncryptor.signAndEncode(plainData.publicMeta, authorPrivateKey));
    try {
        result.publicMetaObject(utils::Utils::parseJsonObject(plainData.publicMeta.stdString()));
    } catch (...) {
        result.publicMetaObjectClear();
    }
    result.privateMeta(
        _dataEncryptor.signAndEncryptAndEncode(plainData.privateMeta, authorPrivateKey, encryptionKey));
    if (plainData.internalMeta.has_value()) {
        result.internalMeta(
            _dataEncryptor.signAndEncryptAndEncode(plainData.internalMeta.value(), authorPrivateKey, encryptionKey));
    }
    result.authorPubKey(authorPrivateKey.getPublicKey().toBase58DER());
    return result;
}

DecryptedStoreDataV4 StoreDataEncryptorV4::decrypt(
    const server::EncryptedStoreDataV4& encryptedData, const std::string& encryptionKey) {
    DecryptedStoreDataV4 result;
    result.statusCode = 0;
    result.dataStructureVersion = StoreDataStructVersion::VERSION_4;
    try {
        validateVersion(encryptedData);
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedData.authorPubKey());
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedData.publicMeta(), authorPublicKey);
        if(!encryptedData.publicMetaObjectEmpty()) {
            auto tmp_1 = utils::Utils::stringify(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringify(encryptedData.publicMetaObject());
            if(tmp_1 != tmp_2) {
                auto e = StorePublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.privateMeta = _dataEncryptor.decodeAndDecryptAndVerify(encryptedData.privateMeta(), authorPublicKey, encryptionKey);
        result.internalMeta = encryptedData.internalMetaEmpty() ? 
            std::nullopt : 
            std::make_optional(_dataEncryptor.decodeAndDecryptAndVerify(encryptedData.internalMeta(), authorPublicKey, encryptionKey));
        result.authorPubKey = encryptedData.authorPubKey();   
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

void StoreDataEncryptorV4::validateVersion(const server::EncryptedStoreDataV4& encryptedData) {
    if (encryptedData.version() != StoreDataStructVersion::VERSION_4) {
        throw InvalidEncryptedStoreDataVersionException();
    }
}
