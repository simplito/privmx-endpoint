#include "privmx/endpoint/group/encryptors/group/GroupDataEncryptorV5.hpp"
#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/core/encryptors/module/DynamicTypes.hpp"
#include <privmx/crypto/Crypto.hpp>
#include <privmx/endpoint/core/encryptors/module/Constants.hpp>
#include <privmx/utils/Utils.hpp>

#include "privmx/endpoint/group/GroupException.hpp"

using namespace privmx::endpoint::group;
using namespace privmx::endpoint;

namespace {

// Both envelopes carry `internalMeta` under the same encoding, so the round trip lives in one place.
std::string encodeInternalMeta(
    core::DataEncryptorV4& dataEncryptor,
    const core::ModuleInternalMetaV5& internalMeta,
    const privmx::crypto::PrivateKey& authorPrivateKey,
    const std::string& encryptionKey
) {
    core::dynamic::ModuleInternalMetaV5 internalMetaObj{
        .secret = internalMeta.secret, .resourceId = internalMeta.resourceId, .randomId = internalMeta.randomId
    };
    return dataEncryptor.signAndEncryptAndEncode(
        core::Buffer::from(internalMetaObj.serialize()), authorPrivateKey, encryptionKey
    );
}

core::ModuleInternalMetaV5 decodeInternalMeta(
    core::DataEncryptorV4& dataEncryptor,
    const std::string& encoded,
    const privmx::crypto::PublicKey& authorPublicKey,
    const std::string& encryptionKey
) {
    auto raw = dataEncryptor.decodeAndDecryptAndVerify(encoded, authorPublicKey, encryptionKey);
    auto parsed = core::dynamic::ModuleInternalMetaV5::fromJSON(privmx::utils::Utils::parseJsonObject(raw.stdString()));
    return core::ModuleInternalMetaV5{
        .secret = parsed.secret, .resourceId = parsed.resourceId, .randomId = parsed.randomId
    };
}

} // namespace

dynamic::EncryptedGroupRosterV5 GroupDataEncryptorV5::encryptRoster(
    const GroupRosterToEncryptV5& data,
    const privmx::crypto::PrivateKey& authorPrivateKey,
    const std::string& encryptionKey
) {
    dynamic::EncryptedGroupRosterV5 result;
    result.version = core::ModuleDataSchema::Version::VERSION_5;
    std::unordered_map<std::string, std::string> fieldChecksums;

    result.internalMeta = encodeInternalMeta(_dataEncryptor, data.internalMeta, authorPrivateKey, encryptionKey);
    fieldChecksums.insert(std::make_pair("internalMeta", privmx::crypto::Crypto::sha256(result.internalMeta)));

    result.membership = _dataEncryptor.signAndEncode(
        core::Buffer::from(privmx::utils::Utils::stringifyVar(data.membership.toJSON())), authorPrivateKey
    );
    fieldChecksums.insert(std::make_pair("membership", privmx::crypto::Crypto::sha256(result.membership)));

    result.authorPubKey = authorPrivateKey.getPublicKey().toBase58DER();
    core::ExpandedDataIntegrityObject expandedDio = {data.dio, .structureVersion = 5, .fieldChecksums = fieldChecksums};
    result.dio = _DIOEncryptor.signAndEncode(expandedDio, authorPrivateKey);
    return result;
}

DecryptedGroupRosterV5 GroupDataEncryptorV5::decryptRoster(
    const dynamic::EncryptedGroupRosterV5& encryptedData,
    const std::string& encryptionKey
) {
    DecryptedGroupRosterV5 result;
    result.statusCode = 0;
    result.dataStructureVersion = core::ModuleDataSchema::Version::VERSION_5;
    try {
        result.dio = getRosterDIOAndAssertIntegrity(encryptedData);
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedData.authorPubKey);
        result.authorPubKey = encryptedData.authorPubKey;

        result.internalMeta = decodeInternalMeta(
            _dataEncryptor, encryptedData.internalMeta, authorPublicKey, encryptionKey
        );

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

core::DataIntegrityObject GroupDataEncryptorV5::getRosterDIOAndAssertIntegrity(
    const dynamic::EncryptedGroupRosterV5& encryptedData
) {
    assertRosterFormat(encryptedData);
    auto dio = _DIOEncryptor.decodeAndVerify(encryptedData.dio);
    if (dio.structureVersion != core::ModuleDataSchema::Version::VERSION_5 ||
        dio.creatorPubKey != encryptedData.authorPubKey ||
        dio.fieldChecksums.at("internalMeta") != privmx::crypto::Crypto::sha256(encryptedData.internalMeta) ||
        dio.fieldChecksums.at("membership") != privmx::crypto::Crypto::sha256(encryptedData.membership)) {
        throw core::InvalidDataIntegrityObjectChecksumException();
    }
    return dio;
}

void GroupDataEncryptorV5::assertRosterFormat(const dynamic::EncryptedGroupRosterV5& encryptedData) {
    if (encryptedData.version != core::ModuleDataSchema::Version::VERSION_5 ||
        encryptedData.internalMeta.empty() ||
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

dynamic::EncryptedGroupMetaV5 GroupDataEncryptorV5::encrypt(
    const GroupMetaToEncryptV5& data,
    const privmx::crypto::PrivateKey& authorPrivateKey,
    const std::string& encryptionKey
) {
    dynamic::EncryptedGroupMetaV5 result;
    result.version = core::ModuleDataSchema::Version::VERSION_5;
    std::unordered_map<std::string, std::string> fieldChecksums;

    result.publicMeta = _dataEncryptor.signAndEncode(data.publicMeta, authorPrivateKey);
    fieldChecksums.insert(std::make_pair("publicMeta", privmx::crypto::Crypto::sha256(result.publicMeta)));
    try {
        result.publicMetaObject = privmx::utils::Utils::parseJsonObject(data.publicMeta.stdString());
    } catch (...) { result.publicMetaObject = Poco::Dynamic::Var(); }

    result.privateMeta = _dataEncryptor.signAndEncryptAndEncode(data.privateMeta, authorPrivateKey, encryptionKey);
    fieldChecksums.insert(std::make_pair("privateMeta", privmx::crypto::Crypto::sha256(result.privateMeta)));

    result.internalMeta = encodeInternalMeta(_dataEncryptor, data.internalMeta, authorPrivateKey, encryptionKey);
    fieldChecksums.insert(std::make_pair("internalMeta", privmx::crypto::Crypto::sha256(result.internalMeta)));

    result.meta = _dataEncryptor.signAndEncode(
        core::Buffer::from(privmx::utils::Utils::stringifyVar(data.meta.toJSON())), authorPrivateKey
    );
    fieldChecksums.insert(std::make_pair("meta", privmx::crypto::Crypto::sha256(result.meta)));

    result.authorPubKey = authorPrivateKey.getPublicKey().toBase58DER();
    core::ExpandedDataIntegrityObject expandedDio = {data.dio, .structureVersion = 5, .fieldChecksums = fieldChecksums};
    result.dio = _DIOEncryptor.signAndEncode(expandedDio, authorPrivateKey);
    return result;
}

DecryptedGroupMetaV5 GroupDataEncryptorV5::decrypt(
    const dynamic::EncryptedGroupMetaV5& encryptedData,
    const std::string& encryptionKey
) {
    DecryptedGroupMetaV5 result;
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

        result.internalMeta = decodeInternalMeta(
            _dataEncryptor, encryptedData.internalMeta, authorPublicKey, encryptionKey
        );

        auto metaRaw = _dataEncryptor.decodeAndVerify(encryptedData.meta, authorPublicKey);
        result.meta = dynamic::MetaBlock::fromJSON(privmx::utils::Utils::parseJsonObject(metaRaw.stdString()));
    } catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) { result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE; }
    return result;
}

DecryptedGroupMetaV5 GroupDataEncryptorV5::extractPublic(const dynamic::EncryptedGroupMetaV5& encryptedData) {
    DecryptedGroupMetaV5 result;
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

        auto metaRaw = _dataEncryptor.decodeAndVerify(encryptedData.meta, authorPublicKey);
        result.meta = dynamic::MetaBlock::fromJSON(privmx::utils::Utils::parseJsonObject(metaRaw.stdString()));
    } catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) { result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE; }
    return result;
}

core::DataIntegrityObject GroupDataEncryptorV5::getDIOAndAssertIntegrity(
    const dynamic::EncryptedGroupMetaV5& encryptedData
) {
    assertMetaFormat(encryptedData);
    auto dio = _DIOEncryptor.decodeAndVerify(encryptedData.dio);
    if (dio.structureVersion != core::ModuleDataSchema::Version::VERSION_5 ||
        dio.creatorPubKey != encryptedData.authorPubKey ||
        dio.fieldChecksums.at("publicMeta") != privmx::crypto::Crypto::sha256(encryptedData.publicMeta) ||
        dio.fieldChecksums.at("privateMeta") != privmx::crypto::Crypto::sha256(encryptedData.privateMeta) ||
        dio.fieldChecksums.at("internalMeta") != privmx::crypto::Crypto::sha256(encryptedData.internalMeta) ||
        dio.fieldChecksums.at("meta") != privmx::crypto::Crypto::sha256(encryptedData.meta)) {
        throw core::InvalidDataIntegrityObjectChecksumException();
    }
    return dio;
}

void GroupDataEncryptorV5::assertMetaFormat(const dynamic::EncryptedGroupMetaV5& encryptedData) {
    if (encryptedData.version != core::ModuleDataSchema::Version::VERSION_5 ||
        encryptedData.publicMeta.empty() ||
        encryptedData.privateMeta.empty() ||
        encryptedData.internalMeta.empty() ||
        encryptedData.meta.empty() ||
        encryptedData.authorPubKey.empty() ||
        encryptedData.dio.empty()) {
        throw InvalidEncryptedGroupDataVersionException(
            std::to_string(encryptedData.version) +
            " expected version: " +
            std::to_string(core::ModuleDataSchema::Version::VERSION_5)
        );
    }
}
