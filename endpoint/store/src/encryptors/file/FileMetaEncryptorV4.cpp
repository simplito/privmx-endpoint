/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/encryptors/file/FileMetaEncryptorV4.hpp"

#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/core/CoreException.hpp"
#include "privmx/endpoint/store/StoreException.hpp"
#include "privmx/endpoint/store/Constants.hpp"
using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

store::server::EncryptedFileMetaV4 FileMetaEncryptorV4::encrypt(const store::FileMetaToEncryptV4& fileMeta,
                                                                const crypto::PrivateKey& authorPrivateKey,
                                                                const std::string& encryptionKey) {
    auto result = utils::TypedObjectFactory::createNewObject<store::server::EncryptedFileMetaV4>();
    {
    result.version(FileDataStructVersion::VERSION_4);
    result.publicMeta(_dataEncryptor.signAndEncode(fileMeta.publicMeta, authorPrivateKey));
    try {
        result.publicMetaObject(utils::Utils::parseJsonObject(fileMeta.publicMeta.stdString()));
    } catch (...) {
        result.publicMetaObjectClear();
    }
    result.privateMeta(_dataEncryptor.signAndEncryptAndEncode(fileMeta.privateMeta, authorPrivateKey, encryptionKey));
    result.fileSize(
        _dataEncryptor.signAndEncryptAndEncode(serializeNumber(fileMeta.fileSize), authorPrivateKey, encryptionKey));
    result.internalMeta(_dataEncryptor.signAndEncryptAndEncode(fileMeta.internalMeta, authorPrivateKey, encryptionKey));
    result.authorPubKey(authorPrivateKey.getPublicKey().toBase58DER());
    }
    
    return result;
}

store::DecryptedFileMetaV4 FileMetaEncryptorV4::decrypt(const store::server::EncryptedFileMetaV4& encryptedFileMeta,
                                                      const std::string& encryptionKey) {
    DecryptedFileMetaV4 result;
    result.statusCode = 0;
    result.dataStructureVersion = FileDataStructVersion::VERSION_4;
    try {
        validateVersion(encryptedFileMeta);
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
        result.fileSize = deserializeNumber(_dataEncryptor.decodeAndDecryptAndVerify(encryptedFileMeta.fileSize(), authorPublicKey, encryptionKey));
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

void FileMetaEncryptorV4::validateVersion(const store::server::EncryptedFileMetaV4& encryptedFileMeta) {
    if (encryptedFileMeta.version() != FileDataStructVersion::VERSION_4) {
        throw InvalidEncryptedStoreFileMetaVersionException();
    }
}

core::Buffer FileMetaEncryptorV4::serializeNumber(const int64_t& number) {
    return core::Buffer::from(std::to_string(number));
}

int64_t FileMetaEncryptorV4::deserializeNumber(const core::Buffer& buffer) {
    return std::stoll(buffer.stdString());
}
