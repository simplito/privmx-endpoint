/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_FILEMETAENCRYPTOR_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_FILEMETAENCRYPTOR_HPP_

#include <optional>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include "privmx/endpoint/store/Constants.hpp"
#include "privmx/endpoint/store/encryptors/file/FileMetaEncryptorV1.hpp"
#include "privmx/endpoint/store/encryptors/file/FileMetaEncryptorV4.hpp"
#include "privmx/endpoint/store/encryptors/file/FileMetaEncryptorV5.hpp"

namespace privmx {
namespace endpoint {
namespace store {

class FileMetaEncryptor {
public:
    struct DecryptedFileMeta {
    public:
        DecryptedFileMeta() : version(FileDataSchema::Version::UNKNOWN), v1(std::nullopt), v4(std::nullopt), v5(std::nullopt) {};
        DecryptedFileMeta(const FileMetaSigned& v1) : version(FileDataSchema::Version::VERSION_1), v1(v1), v4(std::nullopt), v5(std::nullopt) {};
        DecryptedFileMeta(const DecryptedFileMetaV4& v4) : version(FileDataSchema::Version::VERSION_4), v1(std::nullopt), v4(v4), v5(std::nullopt) {};
        DecryptedFileMeta(const DecryptedFileMetaV5& v5) : version(FileDataSchema::Version::VERSION_5), v1(std::nullopt), v4(std::nullopt), v5(v5) {};
        FileDataSchema::Version version;
        std::optional<FileMetaSigned> v1;
        std::optional<DecryptedFileMetaV4> v4;
        std::optional<DecryptedFileMetaV5> v5;

    };

    FileMetaEncryptor(const privmx::crypto::PrivateKey& userPrivKey, const core::Connection& connection);

    Poco::Dynamic::Var encrypt(const FileInfo& fileInfo, const FileMeta& fileMeta, core::EncKey encKey, int64_t keyVersion = core::CURRENT_ENCRYPTION_KEY_DATA_SCHEMA_VERSION);
    DecryptedFileMeta decrypt(const FileInfo& fileInfo, Poco::Dynamic::Var encryptedFileMeta, core::EncKey encKey);
    DecryptedFileMeta extractPublic(const FileInfo& fileInfo, Poco::Dynamic::Var encryptedFileMeta);
    FileDataSchema::Version getFileDataStructureVersion(Poco::Dynamic::Var encryptedFileMeta);
private:
    privmx::endpoint::core::DataIntegrityObject createDIO(const FileInfo& fileInfo);
    privmx::crypto::PrivateKey _userPrivKey;
    core::Connection _connection;
    FileMetaEncryptorV1 _fileMetaEncryptorV1;
    FileMetaEncryptorV4 _fileMetaEncryptorV4;
    FileMetaEncryptorV5 _fileMetaEncryptorV5;

};

}  // namespace core
}  // namespace endpoint
}  // namespace privmx

#endif  //_PRIVMXLIB_ENDPOINT_STORE_FILEMETAENCRYPTOR_HPP_
