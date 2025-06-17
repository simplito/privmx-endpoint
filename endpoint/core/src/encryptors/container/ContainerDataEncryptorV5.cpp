/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/encryptors/container/ContainerDataEncryptorV5.hpp"
#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/core/CoreException.hpp"
#include <privmx/endpoint/core/encryptors/container/Constants.hpp>
#include <privmx/crypto/Crypto.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::core::container;

dynamic::EncryptedContainerDataV5 ContainerDataEncryptorV5::encrypt(const ContainerDataToEncryptV5& kvdbData,
                                                                     const crypto::PrivateKey& authorPrivateKey,
                                                                     const std::string& encryptionKey) {
    auto result = utils::TypedObjectFactory::createNewObject<dynamic::EncryptedContainerDataV5>();
    result.version(ContainerDataSchema::Version::VERSION_5);
    std::unordered_map<std::string, std::string> fieldChecksums;
    result.publicMeta(_dataEncryptor.signAndEncode(kvdbData.publicMeta, authorPrivateKey));
    fieldChecksums.insert(std::make_pair("publicMeta",privmx::crypto::Crypto::sha256(result.publicMeta())));
    try {
        result.publicMetaObject(utils::Utils::parseJsonObject(kvdbData.publicMeta.stdString()));
    } catch (...) {
        result.publicMetaObjectClear();
    }
    result.privateMeta(_dataEncryptor.signAndEncryptAndEncode(kvdbData.privateMeta, authorPrivateKey, encryptionKey));
    fieldChecksums.insert(std::make_pair("privateMeta",privmx::crypto::Crypto::sha256(result.privateMeta())));
    auto internalMeta = utils::TypedObjectFactory::createNewObject<dynamic::ContainerInternalMetaV5>();
    internalMeta.secret(kvdbData.internalMeta.secret);
    internalMeta.resourceId(kvdbData.internalMeta.resourceId);
    internalMeta.randomId(kvdbData.internalMeta.randomId);
    result.internalMeta(_dataEncryptor.signAndEncryptAndEncode(core::Buffer::from(utils::Utils::stringifyVar(internalMeta)), authorPrivateKey, encryptionKey));
    fieldChecksums.insert(std::make_pair("internalMeta",privmx::crypto::Crypto::sha256(result.internalMeta())));
    result.authorPubKey(authorPrivateKey.getPublicKey().toBase58DER());
    core::ExpandedDataIntegrityObject expandedDio = {kvdbData.dio, .structureVersion=5, .fieldChecksums=fieldChecksums};
    result.dio(_DIOEncryptor.signAndEncode(expandedDio, authorPrivateKey));
    return result;
}

DecryptedContainerDataV5 ContainerDataEncryptorV5::decrypt(const dynamic::EncryptedContainerDataV5& encryptedContainerData, const std::string& encryptionKey) {
    DecryptedContainerDataV5 result;
    result.statusCode = 0;
    result.dataStructureVersion = ContainerDataSchema::Version::VERSION_5;
    try {  
        result.dio = getDIOAndAssertIntegrity(encryptedContainerData);
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
        auto internalMeta = _dataEncryptor.decodeAndDecryptAndVerify(encryptedContainerData.internalMeta(), authorPublicKey, encryptionKey).stdString();
        auto internalMetaJSON = utils::TypedObjectFactory::createObjectFromVar<dynamic::ContainerInternalMetaV5>(utils::Utils::parseJsonObject(internalMeta));
        result.internalMeta = ContainerInternalMetaV5{.secret=internalMetaJSON.secret(), .resourceId=internalMetaJSON.resourceId(), .randomId=internalMetaJSON.randomId()};
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


DecryptedContainerDataV5 ContainerDataEncryptorV5::extractPublic(const dynamic::EncryptedContainerDataV5& encryptedContainerData) {
    DecryptedContainerDataV5 result;
    result.statusCode = 0;
    result.dataStructureVersion = ContainerDataSchema::Version::VERSION_5;
    try {  
        result.dio = getDIOAndAssertIntegrity(encryptedContainerData);
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

core::DataIntegrityObject ContainerDataEncryptorV5::getDIOAndAssertIntegrity(const dynamic::EncryptedContainerDataV5& encryptedContainerData) {
    assertDataFormat(encryptedContainerData);
    auto encryptedDIO = encryptedContainerData.dio();
    auto dio = _DIOEncryptor.decodeAndVerify(encryptedDIO);
    if (
        dio.structureVersion != ContainerDataSchema::Version::VERSION_5 ||
        dio.creatorPubKey != encryptedContainerData.authorPubKey() ||
        dio.fieldChecksums.at("publicMeta") != privmx::crypto::Crypto::sha256(encryptedContainerData.publicMeta()) ||
        dio.fieldChecksums.at("privateMeta") != privmx::crypto::Crypto::sha256(encryptedContainerData.privateMeta()) ||
        dio.fieldChecksums.at("internalMeta") != privmx::crypto::Crypto::sha256(encryptedContainerData.internalMeta())     
    ) {
        throw core::InvalidDataIntegrityObjectChecksumException();
    }
    return dio;
}

void ContainerDataEncryptorV5::assertDataFormat(const dynamic::EncryptedContainerDataV5& encryptedContainerData) {
    if (encryptedContainerData.versionEmpty() ||
        encryptedContainerData.version() != ContainerDataSchema::Version::VERSION_5 ||
        encryptedContainerData.publicMetaEmpty() ||
        encryptedContainerData.privateMetaEmpty() ||
        encryptedContainerData.internalMetaEmpty() ||
        encryptedContainerData.authorPubKeyEmpty() ||
        encryptedContainerData.dioEmpty()
    ) {
        throw core::InvalidEncryptedContainerDataVersionException(std::to_string(encryptedContainerData.version()) + " expected version: " + std::to_string(ContainerDataSchema::Version::VERSION_5));
    }
}
