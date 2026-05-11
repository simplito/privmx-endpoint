/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/encryptors/file/FileMetaEncryptorV5.hpp"

#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/store/StoreException.hpp"
#include "privmx/endpoint/store/Constants.hpp"
#include <privmx/crypto/Crypto.hpp>
#include <privmx/utils/Utils.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

store::server::EncryptedFileMetaV5 FileMetaEncryptorV5::encrypt(
    const store::FileMetaToEncryptV5& fileMeta, const crypto::PrivateKey& authorPrivateKey, const std::string& encryptionKey)
{
    server::EncryptedFileMetaV5 result;
    result.version = FileDataSchema::Version::VERSION_5;
    std::unordered_map<std::string, std::string> fieldChecksums;
    result.publicMeta = _dataEncryptor.signAndEncode(fileMeta.publicMeta, authorPrivateKey);
    fieldChecksums.insert(std::make_pair("publicMeta", privmx::crypto::Crypto::sha256(result.publicMeta)));
    try {
        result.publicMetaObject = utils::Utils::parseJsonObject(fileMeta.publicMeta.stdString());
    } catch (...) {
        result.publicMetaObject = Poco::Dynamic::Var();
    }
    result.privateMeta = _dataEncryptor.signAndEncryptAndEncode(fileMeta.privateMeta, authorPrivateKey, encryptionKey);
    fieldChecksums.insert(std::make_pair("privateMeta", privmx::crypto::Crypto::sha256(result.privateMeta)));
    auto internalMeta = _dataEncryptor.signAndEncryptAndEncode(fileMeta.internalMeta, authorPrivateKey, encryptionKey);
    result.internalMeta = internalMeta;
    fieldChecksums.insert(std::make_pair("internalMeta", privmx::crypto::Crypto::sha256(internalMeta)));
    result.authorPubKey = authorPrivateKey.getPublicKey().toBase58DER();
    core::ExpandedDataIntegrityObject expandedDio = {fileMeta.dio, .structureVersion = FileDataSchema::Version::VERSION_5, .fieldChecksums = fieldChecksums};
    result.dio = _DIOEncryptor.signAndEncode(expandedDio, authorPrivateKey);
    return result;
}

store::DecryptedFileMetaV5 FileMetaEncryptorV5::decrypt(const store::server::EncryptedFileMetaV5& encryptedFileMeta,
                                                        const std::string& encryptionKey) {
    DecryptedFileMetaV5 result;
    result.statusCode = 0;
    result.dataStructureVersion = FileDataSchema::Version::VERSION_5;
    try {
        result.dio = getDIOAndAssertIntegrity(encryptedFileMeta);
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedFileMeta.authorPubKey);
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedFileMeta.publicMeta, authorPublicKey);
        if (!encryptedFileMeta.publicMetaObject.isEmpty()) {
            auto tmp_1 = utils::Utils::stringifyVar(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringifyVar(encryptedFileMeta.publicMetaObject);
            if (tmp_1 != tmp_2) {
                auto e = FilePublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.privateMeta = _dataEncryptor.decodeAndDecryptAndVerify(encryptedFileMeta.privateMeta, authorPublicKey, encryptionKey);
        result.internalMeta = _dataEncryptor.decodeAndDecryptAndVerify(encryptedFileMeta.internalMeta.value(), authorPublicKey, encryptionKey);
        result.authorPubKey = encryptedFileMeta.authorPubKey;
    } catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

store::DecryptedFileMetaV5 FileMetaEncryptorV5::extractPublic(const store::server::EncryptedFileMetaV5& encryptedFileMeta) {
    DecryptedFileMetaV5 result;
    result.statusCode = 0;
    result.dataStructureVersion = FileDataSchema::Version::VERSION_5;
    try {
        result.dio = getDIOAndAssertIntegrity(encryptedFileMeta);
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedFileMeta.authorPubKey);
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedFileMeta.publicMeta, authorPublicKey);
        if (encryptedFileMeta.publicMetaObject.isEmpty()) {
            auto tmp_1 = utils::Utils::stringifyVar(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringifyVar(encryptedFileMeta.publicMetaObject);
            if (tmp_1 != tmp_2) {
                auto e = FilePublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.authorPubKey = encryptedFileMeta.authorPubKey;
    } catch (const privmx::endpoint::core::Exception& e) {
        result.statusCode = e.getCode();
    } catch (const privmx::utils::PrivmxException& e) {
        result.statusCode = core::ExceptionConverter::convert(e).getCode();
    } catch (...) {
        result.statusCode = ENDPOINT_CORE_EXCEPTION_CODE;
    }
    return result;
}

core::DataIntegrityObject FileMetaEncryptorV5::getDIOAndAssertIntegrity(const server::EncryptedFileMetaV5& encryptedFileMeta) {
    assertDataFormat(encryptedFileMeta);
    auto dio = _DIOEncryptor.decodeAndVerify(encryptedFileMeta.dio);
    if (
        dio.structureVersion != FileDataSchema::Version::VERSION_5 ||
        dio.creatorPubKey != encryptedFileMeta.authorPubKey ||
        dio.fieldChecksums.at("publicMeta") != privmx::crypto::Crypto::sha256(encryptedFileMeta.publicMeta) ||
        dio.fieldChecksums.at("privateMeta") != privmx::crypto::Crypto::sha256(encryptedFileMeta.privateMeta) ||
        dio.fieldChecksums.at("internalMeta") != privmx::crypto::Crypto::sha256(encryptedFileMeta.internalMeta.value())
    ) {
        throw core::InvalidDataIntegrityObjectChecksumException();
    }
    return dio;
}

void FileMetaEncryptorV5::assertDataFormat(const server::EncryptedFileMetaV5& encryptedFileMeta) {
    if (
        encryptedFileMeta.version != FileDataSchema::Version::VERSION_5 ||
        encryptedFileMeta.publicMeta.empty() ||
        encryptedFileMeta.privateMeta.empty() ||
        encryptedFileMeta.authorPubKey.empty() ||
        !encryptedFileMeta.internalMeta.has_value()
    ) {
        throw InvalidEncryptedStoreFileMetaVersionException(std::to_string(encryptedFileMeta.version) + " expected version: " + std::to_string(FileDataSchema::Version::VERSION_5));
    }
}

core::Buffer FileMetaEncryptorV5::serializeNumber(const int64_t& number) {
    return core::Buffer::from(std::to_string(number));
}

int64_t FileMetaEncryptorV5::deserializeNumber(const core::Buffer& buffer) {
    return std::stoll(buffer.stdString());
}
