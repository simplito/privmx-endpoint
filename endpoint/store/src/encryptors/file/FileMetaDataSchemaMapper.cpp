/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/encryptors/file/FileMetaDataSchemaMapper.hpp"

#include <Poco/JSON/Object.h>
#include <privmx/endpoint/core/encryptors/DataSchemaMapperUtils.hpp>
#include <privmx/utils/Utils.hpp>

#include "privmx/endpoint/store/StoreException.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

FileMetaDataSchemaMapper::FileMetaDataSchemaMapper(
    const privmx::crypto::PrivateKey& userPrivKey,
    const core::Connection& connection
)
    : _userPrivKey(userPrivKey), _connection(connection) {
    _strategyV4 = std::make_shared<FileDataSchemaStrategyV4>();
    _strategyMapper.registerStrategy(FileDataSchema::Version::VERSION_4, _strategyV4);
    _strategyV5 = std::make_shared<FileDataSchemaStrategyV5>();
    _strategyMapper.registerStrategy(FileDataSchema::Version::VERSION_5, _strategyV5);
}

Poco::Dynamic::Var FileMetaDataSchemaMapper::encrypt(
    const std::string& storeId,
    const std::string& fileResourceId,
    const std::string& contextId,
    const std::string& storeResourceId,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const core::Buffer& internalMeta,
    const core::DecryptedEncKeyV2& fileKey
) {
    switch (fileKey.dataStructureVersion) {
    case core::EncryptionKeyDataSchema::Version::UNKNOWN:
        throw UnknowFileFormatException();
    case core::EncryptionKeyDataSchema::Version::VERSION_1:
        return _strategyV4->encrypt(publicMeta, privateMeta, internalMeta, _userPrivKey, fileKey.key).toJSON();
    case core::EncryptionKeyDataSchema::Version::VERSION_2: {
        auto fileDIO = _connection.getImpl()->createDIO(contextId, fileResourceId, storeId, storeResourceId);
        return _strategyV5->encrypt(publicMeta, privateMeta, internalMeta, _userPrivKey, fileKey.key, fileDIO).toJSON();
    }
    }
    throw UnknowFileFormatException();
}

std::tuple<File, core::DataIntegrityObject> FileMetaDataSchemaMapper::decrypt(
    const server::File& file,
    const core::DecryptedEncKey& encKey
) {
    return _strategyMapper.dispatch(
        static_cast<int64_t>(getDataStructureVersion(file)), file, encKey,
        [&]() -> std::tuple<File, core::DataIntegrityObject> {
            return {
                toLibFile(
                    file, {}, {}, 0, {}, UnknowFileFormatException().getCode(), FileDataSchema::Version::UNKNOWN, false
                ),
                {}
            };
        }
    );
}

StoreDataSchema::Version FileMetaDataSchemaMapper::getMinimumStoreSchemaVersion(const server::File& file) {
    switch (getDataStructureVersion(file)) {
    case FileDataSchema::Version::VERSION_4:
        return StoreDataSchema::VERSION_4;
    case FileDataSchema::Version::VERSION_5:
        return StoreDataSchema::VERSION_5;
    default:
        return StoreDataSchema::UNKNOWN;
    }
}

FileDataSchema::Version FileMetaDataSchemaMapper::getDataStructureVersion(const server::File& file) {
    return core::DataSchemaMapperUtils::mapVersionedData(file.meta, FileDataSchema::Version::UNKNOWN, [](int64_t v) {
        switch (v) {
        case FileDataSchema::Version::VERSION_4:
            return FileDataSchema::Version::VERSION_4;
        case FileDataSchema::Version::VERSION_5:
            return FileDataSchema::Version::VERSION_5;
        default:
            return FileDataSchema::Version::UNKNOWN;
        }
    });
}

uint32_t FileMetaDataSchemaMapper::validateDataIntegrity(const server::File& file, const std::string& storeResourceId) {
    return core::DataSchemaMapperUtils::toStatusCode([&] {
        switch (getDataStructureVersion(file)) {
        case FileDataSchema::Version::VERSION_4:
            return;
        case FileDataSchema::Version::VERSION_5: {
            auto fileMeta = server::EncryptedFileMetaV5::fromJSON(file.meta);
            auto dio = _strategyV5->getDIOAndAssertIntegrity(fileMeta);
            core::DataSchemaMapperUtils::assertEntryDIOIntegrity(
                dio, file.contextId, file.resourceId, file.storeId, storeResourceId, file.lastModifier,
                file.lastModificationDate, [] { throw FileDataIntegrityException(); }
            );
            return;
        }
        default:
            throw UnknowFileFormatException();
        }
    });
}

DecryptedFileMetaV5 FileMetaDataSchemaMapper::decryptFileMetaV5(
    const server::File& file,
    const core::DecryptedEncKey& encKey
) {
    return _strategyV5->decryptFileMeta(file, encKey);
}

DecryptedFileMetaV4 FileMetaDataSchemaMapper::decryptFileMetaV4(
    const server::File& file,
    const core::DecryptedEncKey& encKey
) {
    return _strategyV4->decryptFileMeta(file, encKey);
}

dynamic::InternalStoreFileMeta FileMetaDataSchemaMapper::decryptFileInternalMeta(
    const server::File& file,
    const core::DecryptedEncKey& encKey
) {
    if (encKey.statusCode == 0) {
        switch (getDataStructureVersion(file)) {
        case FileDataSchema::Version::VERSION_4:
            return dynamic::InternalStoreFileMeta::fromJSON(
                utils::Utils::parseJson(decryptFileMetaV4(file, encKey).internalMeta.stdString())
            );
        case FileDataSchema::Version::VERSION_5:
            return dynamic::InternalStoreFileMeta::fromJSON(
                utils::Utils::parseJson(decryptFileMetaV5(file, encKey).internalMeta.stdString())
            );
        default:
            throw UnknowFileFormatException();
        }
    }
    throw UnknowFileFormatException();
}

std::vector<File> FileMetaDataSchemaMapper::validateDecryptAndConvertFiles(
    const std::vector<server::File>& files,
    const core::ModuleKeys& storeKeys,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    return core::DataSchemaMapperUtils::batchValidateDecryptVerifyEntries<File>(
        files, storeKeys, keyProvider, _connection,
        [&](const server::File& f) { return validateDataIntegrity(f, storeKeys.moduleResourceId); },
        [&](const server::File& f) {
            return core::DataSchemaMapperUtils::toStatusCode([&] {
                _fileKeyIdFormatValidator.assertKeyIdFormat(f.keyId);
            });
        },
        [&](const server::File& f, const core::DecryptedEncKey& key) { return decrypt(f, key); },
        [](const server::File& f, uint32_t code) {
            return toLibFile(f, {}, {}, 0, {}, code, FileDataSchema::Version::UNKNOWN, false);
        }
    );
}

File FileMetaDataSchemaMapper::validateDecryptAndConvertFile(
    const server::File& file,
    const core::ModuleKeys& storeKeys,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    return validateDecryptAndConvertFiles({file}, storeKeys, keyProvider)[0];
}

dynamic::InternalStoreFileMeta FileMetaDataSchemaMapper::validateDecryptFileInternalMeta(
    const server::File& file,
    const core::ModuleKeys& storeKeys,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    const auto& keyId = file.keyId;
    core::KeyDecryptionAndVerificationRequest keyProviderRequest;
    core::EncKeyLocation location{.contextId = file.contextId, .resourceId = storeKeys.moduleResourceId};
    keyProviderRequest.addOne(storeKeys.keys, keyId, location);
    auto encKey = keyProvider->getKeysAndVerify(keyProviderRequest).at(location).at(keyId);
    return decryptFileInternalMeta(file, encKey);
}

File FileMetaDataSchemaMapper::toLibFile(
    const server::File& file,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    int64_t size,
    const std::string& authorPubKey,
    int64_t statusCode,
    int64_t schemaVersion,
    bool randomWrite
) {
    return File{
        .info =
            {
                .storeId = file.storeId,
                .fileId = file.id,
                .createDate = file.created,
                .author = file.creator,
            },
        .publicMeta = publicMeta,
        .privateMeta = privateMeta,
        .size = size,
        .authorPubKey = authorPubKey,
        .statusCode = statusCode,
        .schemaVersion = schemaVersion,
        .randomWrite = randomWrite
    };
}
