/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_FILEMETADATASCHEMAMAPPER_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_FILEMETADATASCHEMAMAPPER_HPP_

#include <cstdint>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

#include <Poco/Dynamic/Var.h>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/Connection.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include <privmx/endpoint/core/KeyProvider.hpp>
#include <privmx/endpoint/core/encryptors/VersionStrategyMapper.hpp>

#include "privmx/endpoint/store/Constants.hpp"
#include "privmx/endpoint/store/FileKeyIdFormatValidator.hpp"
#include "privmx/endpoint/store/ServerTypes.hpp"
#include "privmx/endpoint/store/StoreTypes.hpp"
#include "privmx/endpoint/store/Types.hpp"
#include "privmx/endpoint/store/encryptors/file/FileDataSchemaStrategyV4.hpp"
#include "privmx/endpoint/store/encryptors/file/FileDataSchemaStrategyV5.hpp"

namespace privmx {
namespace endpoint {
namespace store {

class FileMetaDataSchemaMapper {
public:
    FileMetaDataSchemaMapper(
        const privmx::crypto::PrivateKey& userPrivKey,
        const core::Connection& connection
    );

    Poco::Dynamic::Var encrypt(
        const std::string& storeId,
        const std::string& fileResourceId,
        const std::string& contextId,
        const std::string& storeResourceId,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        const core::Buffer& internalMeta,
        const core::DecryptedEncKeyV2& fileKey
    );

    std::tuple<File, core::DataIntegrityObject> decrypt(
        const server::File& file,
        const core::DecryptedEncKey& encKey
    );

    FileDataSchema::Version getDataStructureVersion(const server::File& file);
    StoreDataSchema::Version getMinimumStoreSchemaVersion(const server::File& file);

    uint32_t validateDataIntegrity(const server::File& file, const std::string& storeResourceId);

    DecryptedFileMetaV4 decryptFileMetaV4(const server::File& file, const core::DecryptedEncKey& encKey);
    DecryptedFileMetaV5 decryptFileMetaV5(const server::File& file, const core::DecryptedEncKey& encKey);
    dynamic::InternalStoreFileMeta decryptFileInternalMeta(
        const server::File& file,
        const core::DecryptedEncKey& encKey
    );

    std::vector<File> validateDecryptAndConvertFiles(
        std::vector<server::File> files,
        const core::ModuleKeys& storeKeys,
        const std::shared_ptr<core::KeyProvider>& keyProvider
    );

    File validateDecryptAndConvertFile(
        server::File file,
        const core::ModuleKeys& storeKeys,
        const std::shared_ptr<core::KeyProvider>& keyProvider
    );

    dynamic::InternalStoreFileMeta validateDecryptFileInternalMeta(
        server::File file,
        const core::ModuleKeys& storeKeys,
        const std::shared_ptr<core::KeyProvider>& keyProvider
    );

    static File toLibFile(
        const server::File& file,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        int64_t size,
        const std::string& authorPubKey,
        int64_t statusCode,
        int64_t schemaVersion,
        bool randomWrite = false
    );

private:
    privmx::crypto::PrivateKey _userPrivKey;
    core::Connection _connection;
    FileKeyIdFormatValidator _fileKeyIdFormatValidator;
    core::VersionStrategyMapper<server::File, std::tuple<File, core::DataIntegrityObject>> _strategyMapper;
    std::shared_ptr<FileDataSchemaStrategyV4> _strategyV4;
    std::shared_ptr<FileDataSchemaStrategyV5> _strategyV5;
};

} // namespace store
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_FILEMETADATASCHEMAMAPPER_HPP_
