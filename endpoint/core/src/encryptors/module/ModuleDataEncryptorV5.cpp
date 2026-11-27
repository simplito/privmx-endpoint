/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/core/encryptors/module/ModuleDataEncryptorV5.hpp"
#include "privmx/endpoint/core/CoreException.hpp"
#include <privmx/endpoint/core/crypto/PublicKeyCache.hpp>
#include <privmx/endpoint/core/encryptors/module/Constants.hpp>
#include <privmx/utils/Utils.hpp>

using namespace privmx::endpoint::core;

dynamic::EncryptedModuleDataV5 ModuleDataEncryptorV5::encrypt(
    const ModuleDataToEncryptV5& kvdbData,
    const core::PrivateKey& authorPrivateKey,
    const core::EncKey& encryptionKey
) {
    dynamic::EncryptedModuleDataV5 result;
    result.version = ModuleDataSchema::Version::VERSION_5;
    std::unordered_map<std::string, std::string> fieldChecksums;
    result.publicMeta = _dataEncryptor.signAndEncode(kvdbData.publicMeta, authorPrivateKey);
    fieldChecksums.insert(std::make_pair("publicMeta", encryptionKey.suite.hash(result.publicMeta)));
    try {
        result.publicMetaObject = utils::Utils::parseJsonObject(kvdbData.publicMeta.stdString());
    } catch (...) { result.publicMetaObject = Poco::Dynamic::Var(); }
    result.privateMeta = _dataEncryptor.signAndEncryptAndEncode(kvdbData.privateMeta, authorPrivateKey, encryptionKey);
    fieldChecksums.insert(std::make_pair("privateMeta", encryptionKey.suite.hash(result.privateMeta)));
    dynamic::ModuleInternalMetaV5 internalMeta{
        .secret = kvdbData.internalMeta.secret,
        .resourceId = kvdbData.internalMeta.resourceId,
        .randomId = kvdbData.internalMeta.randomId
    };
    result.internalMeta = _dataEncryptor.signAndEncryptAndEncode(
        Buffer::from(internalMeta.serialize()), authorPrivateKey, encryptionKey
    );
    fieldChecksums.insert(std::make_pair("internalMeta", encryptionKey.suite.hash(result.internalMeta)));
    result.authorPubKey = authorPrivateKey.getPublicKey().toBase58DER();
    ExpandedDataIntegrityObject expandedDio = {kvdbData.dio, 5, fieldChecksums, encryptionKey.suite};
    result.dio = _DIOEncryptor.signAndEncode(expandedDio, authorPrivateKey);
    return result;
}

DecryptedModuleDataV5 ModuleDataEncryptorV5::decrypt(
    const dynamic::EncryptedModuleDataV5& encryptedModuleData,
    const std::string& encryptionKey,
    const std::optional<DataIntegrityObject>& verifiedDio
) {
    DecryptedModuleDataV5 result;
    result.dataStructureVersion = ModuleDataSchema::Version::VERSION_5;
    try {
        result.dio = verifiedDio.has_value() ? verifiedDio.value() : getDIOAndAssertIntegrity(encryptedModuleData);
        auto authorPublicKey = core::PublicKeyCache::getInstance()->fromBase58DER(encryptedModuleData.authorPubKey);
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedModuleData.publicMeta, authorPublicKey);
        if (!encryptedModuleData.publicMetaObject.isEmpty()) {
            auto tmp_1 = utils::Utils::stringifyVar(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringifyVar(encryptedModuleData.publicMetaObject);
            if (tmp_1 != tmp_2) {
                result.error = asError(ModulePublicDataMismatchException());
            }
        }
        result.privateMeta = _dataEncryptor.decodeAndDecryptAndVerify(
            encryptedModuleData.privateMeta, authorPublicKey, encryptionKey
        );
        auto internalMeta = _dataEncryptor.decodeAndDecryptAndVerify(
            encryptedModuleData.internalMeta, authorPublicKey, encryptionKey
        );
        auto internalMetaJSON = dynamic::ModuleInternalMetaV5::fromJSON(
            utils::Utils::parseJsonObject(internalMeta.stdString())
        );
        result.internalMeta = ModuleInternalMetaV5{
            .secret = internalMetaJSON.secret,
            .resourceId = internalMetaJSON.resourceId,
            .randomId = internalMetaJSON.randomId
        };
        result.authorPubKey = encryptedModuleData.authorPubKey;
    } catch (const privmx::endpoint::core::Exception& e) { result.error = asError(e); } catch (...) {
        result.error = unknownError("decrypting module data");
    }
    return result;
}

DecryptedModuleDataV5 ModuleDataEncryptorV5::extractPublic(
    const dynamic::EncryptedModuleDataV5& encryptedModuleData,
    const std::optional<DataIntegrityObject>& verifiedDio
) {
    DecryptedModuleDataV5 result;
    result.dataStructureVersion = ModuleDataSchema::Version::VERSION_5;
    try {
        result.dio = verifiedDio.has_value() ? verifiedDio.value() : getDIOAndAssertIntegrity(encryptedModuleData);
        auto authorPublicKey = core::PublicKeyCache::getInstance()->fromBase58DER(encryptedModuleData.authorPubKey);
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedModuleData.publicMeta, authorPublicKey);
        if (!encryptedModuleData.publicMetaObject.isEmpty()) {
            auto tmp_1 = utils::Utils::stringifyVar(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringifyVar(encryptedModuleData.publicMetaObject);
            if (tmp_1 != tmp_2) {
                result.error = asError(ModulePublicDataMismatchException());
            }
        }
        result.authorPubKey = encryptedModuleData.authorPubKey;
    } catch (const privmx::endpoint::core::Exception& e) { result.error = asError(e); } catch (...) {
        result.error = unknownError("decrypting module data");
    }
    return result;
}

DataIntegrityObject ModuleDataEncryptorV5::getDIOAndAssertIntegrity(
    const dynamic::EncryptedModuleDataV5& encryptedModuleData
) {
    assertDataFormat(encryptedModuleData);
    auto encryptedDIO = encryptedModuleData.dio;
    auto dio = _DIOEncryptor.decodeAndVerify(encryptedDIO);
    if (dio.structureVersion != ModuleDataSchema::Version::VERSION_5 ||
        dio.creatorPubKey != encryptedModuleData.authorPubKey ||
        dio.fieldChecksums.at("publicMeta") != dio.suite.hash(encryptedModuleData.publicMeta) ||
        dio.fieldChecksums.at("privateMeta") != dio.suite.hash(encryptedModuleData.privateMeta) ||
        dio.fieldChecksums.at("internalMeta") != dio.suite.hash(encryptedModuleData.internalMeta)) {
        throw InvalidDataIntegrityObjectChecksumException();
    }
    return dio;
}

void ModuleDataEncryptorV5::assertDataFormat(const dynamic::EncryptedModuleDataV5& encryptedModuleData) {
    if (encryptedModuleData.version != ModuleDataSchema::Version::VERSION_5 ||
        encryptedModuleData.publicMeta.empty() ||
        encryptedModuleData.privateMeta.empty() ||
        encryptedModuleData.internalMeta.empty() ||
        encryptedModuleData.authorPubKey.empty() ||
        encryptedModuleData.dio.empty()) {
        throw InvalidEncryptedModuleDataVersionException(
            std::to_string(encryptedModuleData.version) +
            " expected version: " +
            std::to_string(ModuleDataSchema::Version::VERSION_5)
        );
    }
}
