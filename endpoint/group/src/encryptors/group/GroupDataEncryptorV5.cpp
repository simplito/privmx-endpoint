#include "privmx/endpoint/group/encryptors/group/GroupDataEncryptorV5.hpp"
#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/encryptors/module/DynamicTypes.hpp"
#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include <privmx/crypto/Crypto.hpp>
#include <privmx/endpoint/core/encryptors/module/Constants.hpp>
#include <privmx/utils/Utils.hpp>

#include "privmx/endpoint/group/GroupException.hpp"

using namespace privmx::endpoint::group;
using namespace privmx::endpoint;

dynamic::EncryptedGroupDataV5 GroupDataEncryptorV5::encrypt(
    const GroupDataToEncryptV5& data,
    const privmx::crypto::PrivateKey& authorPrivateKey,
    const std::string& encryptionKey
) {
    dynamic::EncryptedGroupDataV5 result;
    result.version = core::ModuleDataSchema::Version::VERSION_5;
    std::unordered_map<std::string, std::string> fieldChecksums;

    result.publicMeta = _dataEncryptor.signAndEncode(data.publicMeta, authorPrivateKey);
    fieldChecksums.insert(std::make_pair("publicMeta", privmx::crypto::Crypto::sha256(result.publicMeta)));
    try {
        result.publicMetaObject = privmx::utils::Utils::parseJsonObject(data.publicMeta.stdString());
    } catch (...) { result.publicMetaObject = Poco::Dynamic::Var(); }

    result.privateMeta = _dataEncryptor.signAndEncryptAndEncode(data.privateMeta, authorPrivateKey, encryptionKey);
    fieldChecksums.insert(std::make_pair("privateMeta", privmx::crypto::Crypto::sha256(result.privateMeta)));

    core::dynamic::ModuleInternalMetaV5 internalMetaObj{
        .secret = data.internalMeta.secret,
        .resourceId = data.internalMeta.resourceId,
        .randomId = data.internalMeta.randomId
    };
    result.internalMeta = _dataEncryptor.signAndEncryptAndEncode(
        core::Buffer::from(internalMetaObj.serialize()), authorPrivateKey, encryptionKey
    );
    fieldChecksums.insert(std::make_pair("internalMeta", privmx::crypto::Crypto::sha256(result.internalMeta)));

    result.groupPrivKey = _dataEncryptor.signAndEncryptAndEncode(
        core::Buffer::from(data.groupPrivKey), authorPrivateKey, encryptionKey
    );
    fieldChecksums.insert(std::make_pair("groupPrivKey", privmx::crypto::Crypto::sha256(result.groupPrivKey)));

    result.membership = _dataEncryptor.signAndEncode(
        core::Buffer::from(privmx::utils::Utils::stringifyVar(data.membership.toJSON())), authorPrivateKey
    );
    fieldChecksums.insert(std::make_pair("membership", privmx::crypto::Crypto::sha256(result.membership)));

    result.authorPubKey = authorPrivateKey.getPublicKey().toBase58DER();
    core::ExpandedDataIntegrityObject expandedDio = {data.dio, .structureVersion = 5, .fieldChecksums = fieldChecksums};
    result.dio = _DIOEncryptor.signAndEncode(expandedDio, authorPrivateKey);
    return result;
}

DecryptedGroupDataV5 GroupDataEncryptorV5::decrypt(
    const dynamic::EncryptedGroupDataV5& encryptedData,
    const std::string& encryptionKey
) {
    DecryptedGroupDataV5 result;
    result.statusCode = 0;
    result.dataStructureVersion = core::ModuleDataSchema::Version::VERSION_5;
    try {
        result.dio = getDIOAndAssertIntegrity(encryptedData);
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedData.authorPubKey);
        result.authorPubKey = encryptedData.authorPubKey;

        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedData.publicMeta, authorPublicKey);
        if (!encryptedData.publicMetaObject.isEmpty()) {
            auto tmp_1 = privmx::utils::Utils::stringifyVar(
                privmx::utils::Utils::parseJsonObject(result.publicMeta.stdString())
            );
            auto tmp_2 = privmx::utils::Utils::stringifyVar(encryptedData.publicMetaObject);
            if (tmp_1 != tmp_2) {
                auto e = core::ModulePublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }

        result.privateMeta = _dataEncryptor.decodeAndDecryptAndVerify(
            encryptedData.privateMeta, authorPublicKey, encryptionKey
        );

        auto internalMetaRaw = _dataEncryptor.decodeAndDecryptAndVerify(
            encryptedData.internalMeta, authorPublicKey, encryptionKey
        );
        auto internalMetaJSON = core::dynamic::ModuleInternalMetaV5::fromJSON(
            privmx::utils::Utils::parseJsonObject(internalMetaRaw.stdString())
        );
        result.internalMeta = core::ModuleInternalMetaV5{
            .secret = internalMetaJSON.secret,
            .resourceId = internalMetaJSON.resourceId,
            .randomId = internalMetaJSON.randomId
        };

        auto groupPrivKeyRaw = _dataEncryptor.decodeAndDecryptAndVerify(
            encryptedData.groupPrivKey, authorPublicKey, encryptionKey
        );
        result.groupPrivKey = groupPrivKeyRaw.stdString();

        auto membershipRaw = _dataEncryptor.decodeAndVerify(encryptedData.membership, authorPublicKey);
        result.membership = dynamic::MembershipBlock::fromJSON(
            privmx::utils::Utils::parseJsonObject(membershipRaw.stdString())
        );
    } catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) { result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE; }
    return result;
}

DecryptedGroupDataV5 GroupDataEncryptorV5::extractPublic(const dynamic::EncryptedGroupDataV5& encryptedData) {
    DecryptedGroupDataV5 result;
    result.statusCode = 0;
    result.dataStructureVersion = core::ModuleDataSchema::Version::VERSION_5;
    try {
        result.dio = getDIOAndAssertIntegrity(encryptedData);
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedData.authorPubKey);
        result.authorPubKey = encryptedData.authorPubKey;

        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedData.publicMeta, authorPublicKey);
        if (!encryptedData.publicMetaObject.isEmpty()) {
            auto tmp_1 = privmx::utils::Utils::stringifyVar(
                privmx::utils::Utils::parseJsonObject(result.publicMeta.stdString())
            );
            auto tmp_2 = privmx::utils::Utils::stringifyVar(encryptedData.publicMetaObject);
            if (tmp_1 != tmp_2) {
                auto e = core::ModulePublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }

        auto membershipRaw = _dataEncryptor.decodeAndVerify(encryptedData.membership, authorPublicKey);
        result.membership = dynamic::MembershipBlock::fromJSON(
            privmx::utils::Utils::parseJsonObject(membershipRaw.stdString())
        );
    } catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) { result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE; }
    return result;
}

core::DataIntegrityObject GroupDataEncryptorV5::getDIOAndAssertIntegrity(
    const dynamic::EncryptedGroupDataV5& encryptedData
) {
    assertDataFormat(encryptedData);
    auto dio = _DIOEncryptor.decodeAndVerify(encryptedData.dio);
    if (dio.structureVersion != core::ModuleDataSchema::Version::VERSION_5 ||
        dio.creatorPubKey != encryptedData.authorPubKey ||
        dio.fieldChecksums.at("publicMeta") != privmx::crypto::Crypto::sha256(encryptedData.publicMeta) ||
        dio.fieldChecksums.at("privateMeta") != privmx::crypto::Crypto::sha256(encryptedData.privateMeta) ||
        dio.fieldChecksums.at("internalMeta") != privmx::crypto::Crypto::sha256(encryptedData.internalMeta) ||
        dio.fieldChecksums.at("groupPrivKey") != privmx::crypto::Crypto::sha256(encryptedData.groupPrivKey) ||
        dio.fieldChecksums.at("membership") != privmx::crypto::Crypto::sha256(encryptedData.membership)) {
        throw core::InvalidDataIntegrityObjectChecksumException();
    }
    return dio;
}

void GroupDataEncryptorV5::assertDataFormat(const dynamic::EncryptedGroupDataV5& encryptedData) {
    if (encryptedData.version != core::ModuleDataSchema::Version::VERSION_5 ||
        encryptedData.publicMeta.empty() ||
        encryptedData.privateMeta.empty() ||
        encryptedData.internalMeta.empty() ||
        encryptedData.groupPrivKey.empty() ||
        encryptedData.membership.empty() ||
        encryptedData.authorPubKey.empty() ||
        encryptedData.dio.empty()) {
        throw InvalidEncryptedGroupDataVersionException(
            std::to_string(encryptedData.version) +
            " expected version: " +
            std::to_string(core::ModuleDataSchema::Version::VERSION_5)
        );
    }
}
