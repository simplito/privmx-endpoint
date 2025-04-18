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

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

store::server::EncryptedFileMetaV5 FileMetaEncryptorV5::encrypt(
    const store::FileMetaToEncryptV5& fileMeta, const crypto::PrivateKey& authorPrivateKey, const std::string& encryptionKey) 
{
    auto result = utils::TypedObjectFactory::createNewObject<store::server::EncryptedFileMetaV5>();
    result.version(FileDataStructVersion::VERSION_5);
    std::unordered_map<std::string, std::string> fieldChecksums;
    result.publicMeta(_dataEncryptor.signAndEncode(fileMeta.publicMeta, authorPrivateKey));
    fieldChecksums.insert(std::make_pair("publicMeta",privmx::crypto::Crypto::sha256(result.publicMeta())));
    try {
        result.publicMetaObject(utils::Utils::parseJsonObject(fileMeta.publicMeta.stdString()));
    } catch (...) {
        result.publicMetaObjectClear();
    }
    result.privateMeta(_dataEncryptor.signAndEncryptAndEncode(fileMeta.privateMeta, authorPrivateKey, encryptionKey));
    fieldChecksums.insert(std::make_pair("privateMeta",privmx::crypto::Crypto::sha256(result.privateMeta())));
    result.internalMeta(_dataEncryptor.signAndEncryptAndEncode(fileMeta.internalMeta, authorPrivateKey, encryptionKey));
    fieldChecksums.insert(std::make_pair("internalMeta",privmx::crypto::Crypto::sha256(result.internalMeta())));
    result.authorPubKey(authorPrivateKey.getPublicKey().toBase58DER());
    core::ExpandedDataIntegrityObject expandedDio = {fileMeta.dio, .structureVersion=FileDataStructVersion::VERSION_5, .fieldChecksums=fieldChecksums};
    result.dio(_DIOEncryptor.signAndEncode(expandedDio, authorPrivateKey));
    return result;
}

store::DecryptedFileMetaV5 FileMetaEncryptorV5::decrypt(const store::server::EncryptedFileMetaV5& encryptedFileMeta,
                                                      const std::string& encryptionKey) {
    DecryptedFileMetaV5 result;
    result.statusCode = 0;
    result.dataStructureVersion = FileDataStructVersion::VERSION_5;
    try {
        result.dio = getDIOAndAssertIntegrity(encryptedFileMeta);
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedFileMeta.authorPubKey());
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedFileMeta.publicMeta(), authorPublicKey);
        if(!encryptedFileMeta.publicMetaObjectEmpty()) {
            auto tmp_1 = utils::Utils::stringify(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringify(encryptedFileMeta.publicMetaObject());
            if(tmp_1 != tmp_2) {
                auto e = FilePublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.privateMeta = _dataEncryptor.decodeAndDecryptAndVerify(encryptedFileMeta.privateMeta(), authorPublicKey, encryptionKey);
        result.internalMeta = _dataEncryptor.decodeAndDecryptAndVerify(encryptedFileMeta.internalMeta(), authorPublicKey, encryptionKey);
        result.authorPubKey = encryptedFileMeta.authorPubKey();   
    }  catch (const privmx::endpoint::core::Exception& e) {
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
    result.dataStructureVersion = FileDataStructVersion::VERSION_5;
    try {
        result.dio = getDIOAndAssertIntegrity(encryptedFileMeta);
        auto authorPublicKey = crypto::PublicKey::fromBase58DER(encryptedFileMeta.authorPubKey());
        result.publicMeta = _dataEncryptor.decodeAndVerify(encryptedFileMeta.publicMeta(), authorPublicKey);
        if(!encryptedFileMeta.publicMetaObjectEmpty()) {
            auto tmp_1 = utils::Utils::stringify(utils::Utils::parseJsonObject(result.publicMeta.stdString()));
            auto tmp_2 = utils::Utils::stringify(encryptedFileMeta.publicMetaObject());
            if(tmp_1 != tmp_2) {
                auto e = FilePublicDataMismatchException();
                result.statusCode = e.getCode();
            }
        }
        result.authorPubKey = encryptedFileMeta.authorPubKey();   
    }  catch (const privmx::endpoint::core::Exception& e) {
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
    auto dio = _DIOEncryptor.decodeAndVerify(encryptedFileMeta.dio());
    if (
        dio.structureVersion != FileDataStructVersion::VERSION_5 ||
        dio.creatorPubKey != encryptedFileMeta.authorPubKey() ||
        dio.fieldChecksums.at("publicMeta") != privmx::crypto::Crypto::sha256(encryptedFileMeta.publicMeta()) ||
        dio.fieldChecksums.at("privateMeta") != privmx::crypto::Crypto::sha256(encryptedFileMeta.privateMeta()) ||
        dio.fieldChecksums.at("internalMeta") != privmx::crypto::Crypto::sha256(encryptedFileMeta.internalMeta())
    ) {
        throw core::InvalidDataIntegrityObjectChecksumException();
    }
    return dio;
}

void FileMetaEncryptorV5::assertDataFormat(const server::EncryptedFileMetaV5& encryptedFileMeta) {
    if (encryptedFileMeta.versionEmpty() ||
        encryptedFileMeta.version() != FileDataStructVersion::VERSION_5 ||
        encryptedFileMeta.publicMetaEmpty() ||
        encryptedFileMeta.privateMetaEmpty() ||
        encryptedFileMeta.authorPubKeyEmpty() ||
        encryptedFileMeta.internalMetaEmpty()
    ) {
        throw InvalidEncryptedStoreFileMetaVersionException(std::to_string(encryptedFileMeta.version()) + " expected version: " + std::to_string(FileDataStructVersion::VERSION_5));
    }
}