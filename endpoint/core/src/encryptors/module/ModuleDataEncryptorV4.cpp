/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/encryptors/module/ModuleDataEncryptorV4.hpp"
#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/core/CoreException.hpp"
#include <privmx/endpoint/core/encryptors/module/Constants.hpp>
#include <privmx/crypto/Crypto.hpp>

using namespace privmx::endpoint::core;


dynamic::EncryptedModuleDataV4 ModuleDataEncryptorV4::encrypt(const ModuleDataToEncryptV4& moduleData,
                                                                     const privmx::crypto::PrivateKey& authorPrivateKey,
                                                                     const std::string& encryptionKey) {
    auto result = utils::TypedObjectFactory::createNewObject<dynamic::EncryptedModuleDataV4>();
    result.version(ModuleDataSchema::Version::VERSION_4);
    result.publicMeta(_dataEncryptor.signAndEncode(moduleData.publicMeta, authorPrivateKey));
    try {
        result.publicMetaObject(utils::Utils::parseJsonObject(moduleData.publicMeta.stdString()));
    } catch (...) {
        result.publicMetaObjectClear();
    }
    result.privateMeta(
        _dataEncryptor.signAndEncryptAndEncode(moduleData.privateMeta, authorPrivateKey, encryptionKey));
    if (moduleData.internalMeta.has_value()) {
        result.internalMeta(
            _dataEncryptor.signAndEncryptAndEncode(moduleData.internalMeta.value(), authorPrivateKey, encryptionKey));
    }
    result.authorPubKey(authorPrivateKey.getPublicKey().toBase58DER());
    return result;
}

DecryptedModuleDataV4 ModuleDataEncryptorV4::decrypt(
    const dynamic::EncryptedModuleDataV4& encryptedModuleData, const std::string& encryptionKey) {
    DecryptedModuleDataV4 result;
    result.statusCode = 0;
    result.dataStructureVersion = ModuleDataSchema::Version::VERSION_4;
    try {
        validateVersion(encryptedModuleData);
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedModuleData.authorPubKey());
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedModuleData.publicMeta(), authorPublicKey);
        if(!encryptedModuleData.publicMetaObjectEmpty()) {
            auto tmp_1 = utils::Utils::stringify(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringify(encryptedModuleData.publicMetaObject());
            if(tmp_1 != tmp_2) {
                auto e = ModulePublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.privateMeta = _dataEncryptor.decodeAndDecryptAndVerify(encryptedModuleData.privateMeta(), authorPublicKey, encryptionKey);
        result.internalMeta = encryptedModuleData.internalMetaEmpty() ? 
            std::nullopt : 
            std::make_optional(_dataEncryptor.decodeAndDecryptAndVerify(encryptedModuleData.internalMeta(), authorPublicKey, encryptionKey));
        result.authorPubKey = encryptedModuleData.authorPubKey();   
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

void ModuleDataEncryptorV4::validateVersion(const dynamic::EncryptedModuleDataV4& encryptedModuleData) {
    if (encryptedModuleData.version() != ModuleDataSchema::Version::VERSION_4) {
        throw InvalidEncryptedModuleDataVersionException(std::to_string(encryptedModuleData.version()) + " expected version: " + std::to_string(ModuleDataSchema::Version::VERSION_4));
    }
}
