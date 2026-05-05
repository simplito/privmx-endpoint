/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/encryptors/module/ModuleDataEncryptorV5.hpp"
#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/core/CoreException.hpp"
#include <privmx/endpoint/core/encryptors/module/Constants.hpp>
#include <privmx/crypto/Crypto.hpp>
#include <privmx/utils/Utils.hpp>

using namespace privmx::endpoint::core;

dynamic::EncryptedModuleDataV5 ModuleDataEncryptorV5::encrypt(const ModuleDataToEncryptV5& kvdbData,
                                                                     const privmx::crypto::PrivateKey& authorPrivateKey,
                                                                     const std::string& encryptionKey) {
    dynamic::EncryptedModuleDataV5 result;
    result.version = ModuleDataSchema::Version::VERSION_5;
    std::unordered_map<std::string, std::string> fieldChecksums;
    result.publicMeta = _dataEncryptor.signAndEncode(kvdbData.publicMeta, authorPrivateKey);
    fieldChecksums.insert(std::make_pair("publicMeta",privmx::crypto::Crypto::sha256(result.publicMeta)));
    try {
        result.publicMetaObject = utils::Utils::parseJsonObject(kvdbData.publicMeta.stdString());
    } catch (...) {
        result.publicMetaObject = Poco::Dynamic::Var();
    }
    result.privateMeta = _dataEncryptor.signAndEncryptAndEncode(kvdbData.privateMeta, authorPrivateKey, encryptionKey);
    fieldChecksums.insert(std::make_pair("privateMeta",privmx::crypto::Crypto::sha256(result.privateMeta)));
    dynamic::ModuleInternalMetaV5 internalMeta;
    internalMeta.secret = kvdbData.internalMeta.secret;
    internalMeta.resourceId =kvdbData.internalMeta.resourceId;
    internalMeta.randomId = kvdbData.internalMeta.randomId;
    result.internalMeta = _dataEncryptor.signAndEncryptAndEncode(Buffer::from(utils::Utils::stringifyVar(internalMeta.toJSON())), authorPrivateKey, encryptionKey);
    fieldChecksums.insert(std::make_pair("internalMeta",privmx::crypto::Crypto::sha256(result.internalMeta)));
    result.authorPubKey = authorPrivateKey.getPublicKey().toBase58DER();
    ExpandedDataIntegrityObject expandedDio = {kvdbData.dio, .structureVersion=5, .fieldChecksums=fieldChecksums};
    result.dio = _DIOEncryptor.signAndEncode(expandedDio, authorPrivateKey);
    return result;
}

DecryptedModuleDataV5 ModuleDataEncryptorV5::decrypt(const dynamic::EncryptedModuleDataV5& encryptedModuleData, const std::string& encryptionKey) {
    DecryptedModuleDataV5 result;
    result.statusCode = 0;
    result.dataStructureVersion = ModuleDataSchema::Version::VERSION_5;
    try {  
        result.dio = getDIOAndAssertIntegrity(encryptedModuleData);
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedModuleData.authorPubKey);
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedModuleData.publicMeta, authorPublicKey);
        if(!encryptedModuleData.publicMetaObject.isEmpty()) {
            auto tmp_1 = utils::Utils::stringifyVar(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringifyVar(encryptedModuleData.publicMetaObject);
            if(tmp_1 != tmp_2) {
                auto e = ModulePublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.privateMeta = _dataEncryptor.decodeAndDecryptAndVerify(encryptedModuleData.privateMeta, authorPublicKey, encryptionKey);
        auto internalMeta = _dataEncryptor.decodeAndDecryptAndVerify(encryptedModuleData.internalMeta, authorPublicKey, encryptionKey).stdString();
        auto internalMetaJSON = dynamic::ModuleInternalMetaV5::fromJSON(utils::Utils::parseJsonObject(internalMeta));
        result.internalMeta = ModuleInternalMetaV5{.secret=internalMetaJSON.secret, .resourceId=internalMetaJSON.resourceId, .randomId=internalMetaJSON.randomId};
        result.authorPubKey = encryptedModuleData.authorPubKey;    
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}


DecryptedModuleDataV5 ModuleDataEncryptorV5::extractPublic(const dynamic::EncryptedModuleDataV5& encryptedModuleData) {
    DecryptedModuleDataV5 result;
    result.statusCode = 0;
    result.dataStructureVersion = ModuleDataSchema::Version::VERSION_5;
    try {  
        result.dio = getDIOAndAssertIntegrity(encryptedModuleData);
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedModuleData.authorPubKey);
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedModuleData.publicMeta, authorPublicKey);
        if(!encryptedModuleData.publicMetaObject.isEmpty()) {
            auto tmp_1 = utils::Utils::stringifyVar(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringifyVar(encryptedModuleData.publicMetaObject);
            if(tmp_1 != tmp_2) {
                auto e = ModulePublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.authorPubKey = encryptedModuleData.authorPubKey;   
    }  catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

DataIntegrityObject ModuleDataEncryptorV5::getDIOAndAssertIntegrity(const dynamic::EncryptedModuleDataV5& encryptedModuleData) {
    assertDataFormat(encryptedModuleData);
    auto encryptedDIO = encryptedModuleData.dio;
    auto dio = _DIOEncryptor.decodeAndVerify(encryptedDIO);
    if (
        dio.structureVersion != ModuleDataSchema::Version::VERSION_5 ||
        dio.creatorPubKey != encryptedModuleData.authorPubKey ||
        dio.fieldChecksums.at("publicMeta") != privmx::crypto::Crypto::sha256(encryptedModuleData.publicMeta) ||
        dio.fieldChecksums.at("privateMeta") != privmx::crypto::Crypto::sha256(encryptedModuleData.privateMeta) ||
        dio.fieldChecksums.at("internalMeta") != privmx::crypto::Crypto::sha256(encryptedModuleData.internalMeta)     
    ) {
        throw InvalidDataIntegrityObjectChecksumException();
    }
    return dio;
}

void ModuleDataEncryptorV5::assertDataFormat(const dynamic::EncryptedModuleDataV5& encryptedModuleData) {
    if (
        encryptedModuleData.version != ModuleDataSchema::Version::VERSION_5 ||
        encryptedModuleData.publicMeta.empty() ||
        encryptedModuleData.privateMeta.empty() ||
        encryptedModuleData.internalMeta.empty() ||
        encryptedModuleData.authorPubKey.empty() ||
        encryptedModuleData.dio.empty()
    ) {
        throw InvalidEncryptedModuleDataVersionException(std::to_string(encryptedModuleData.version) + " expected version: " + std::to_string(ModuleDataSchema::Version::VERSION_5));
    }
}
