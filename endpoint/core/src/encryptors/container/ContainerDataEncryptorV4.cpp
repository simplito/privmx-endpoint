/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/encryptors/container/ContainerDataEncryptorV4.hpp"
#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/core/CoreException.hpp"
#include <privmx/endpoint/core/encryptors/container/Constants.hpp>
#include <privmx/crypto/Crypto.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core::container;


dynamic::EncryptedContainerDataV4 ContainerDataEncryptorV4::encrypt(const ContainerDataToEncryptV4& containerData,
                                                                     const crypto::PrivateKey& authorPrivateKey,
                                                                     const std::string& encryptionKey) {
    auto result = utils::TypedObjectFactory::createNewObject<dynamic::EncryptedContainerDataV4>();
    result.version(ContainerDataSchema::Version::VERSION_4);
    result.publicMeta(_dataEncryptor.signAndEncode(containerData.publicMeta, authorPrivateKey));
    try {
        result.publicMetaObject(utils::Utils::parseJsonObject(containerData.publicMeta.stdString()));
    } catch (...) {
        result.publicMetaObjectClear();
    }
    result.privateMeta(
        _dataEncryptor.signAndEncryptAndEncode(containerData.privateMeta, authorPrivateKey, encryptionKey));
    if (containerData.internalMeta.has_value()) {
        result.internalMeta(
            _dataEncryptor.signAndEncryptAndEncode(containerData.internalMeta.value(), authorPrivateKey, encryptionKey));
    }
    result.authorPubKey(authorPrivateKey.getPublicKey().toBase58DER());
    return result;
}

DecryptedContainerDataV4 ContainerDataEncryptorV4::decrypt(
    const dynamic::EncryptedContainerDataV4& encryptedContainerData, const std::string& encryptionKey) {
    DecryptedContainerDataV4 result;
    result.statusCode = 0;
    result.dataStructureVersion = ContainerDataSchema::Version::VERSION_4;
    try {
        validateVersion(encryptedContainerData);
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedContainerData.authorPubKey());
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedContainerData.publicMeta(), authorPublicKey);
        if(!encryptedContainerData.publicMetaObjectEmpty()) {
            auto tmp_1 = utils::Utils::stringify(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringify(encryptedContainerData.publicMetaObject());
            if(tmp_1 != tmp_2) {
                auto e = core::ContainerPublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.privateMeta = _dataEncryptor.decodeAndDecryptAndVerify(encryptedContainerData.privateMeta(), authorPublicKey, encryptionKey);
        result.internalMeta = encryptedContainerData.internalMetaEmpty() ? 
            std::nullopt : 
            std::make_optional(_dataEncryptor.decodeAndDecryptAndVerify(encryptedContainerData.internalMeta(), authorPublicKey, encryptionKey));
        result.authorPubKey = encryptedContainerData.authorPubKey();   
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

void ContainerDataEncryptorV4::validateVersion(const dynamic::EncryptedContainerDataV4& encryptedContainerData) {
    if (encryptedContainerData.version() != ContainerDataSchema::Version::VERSION_4) {
        throw InvalidEncryptedContainerDataVersionException(std::to_string(encryptedContainerData.version()) + " expected version: " + std::to_string(ContainerDataSchema::Version::VERSION_4));
    }
}
