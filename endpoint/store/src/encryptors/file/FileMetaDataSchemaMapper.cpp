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
#include <privmx/endpoint/core/ConnectionImpl.hpp>
#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/DynamicTypes.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/endpoint/core/TimestampValidator.hpp>
#include <privmx/utils/Utils.hpp>
#include <set>

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
    auto version = getDataStructureVersion(file);
    auto strategy = _strategyMapper.getStrategy(static_cast<int64_t>(version));
    if (!strategy) {
        auto e = UnknowFileFormatException();
        return {
            toLibFile(file, {}, {}, 0, {}, e.getCode(), FileDataSchema::Version::UNKNOWN, false),
            core::DataIntegrityObject{}
        };
    }
    return strategy->decryptAndConvert(file, encKey);
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
    if (file.meta.type() == typeid(Poco::JSON::Object::Ptr)) {
        auto versioned = core::dynamic::VersionedData::fromJSON(file.meta);
        switch (versioned.version) {
        case FileDataSchema::Version::VERSION_4:
            return FileDataSchema::Version::VERSION_4;
        case FileDataSchema::Version::VERSION_5:
            return FileDataSchema::Version::VERSION_5;
        default:
            return FileDataSchema::Version::UNKNOWN;
        }
    }
    return FileDataSchema::Version::UNKNOWN;
}

uint32_t FileMetaDataSchemaMapper::validateDataIntegrity(const server::File& file, const std::string& storeResourceId) {
    try {
        switch (getDataStructureVersion(file)) {
        case FileDataSchema::Version::VERSION_4:
            return 0;
        case FileDataSchema::Version::VERSION_5: {
            auto fileMeta = server::EncryptedFileMetaV5::fromJSON(file.meta);
            auto dio = _strategyV5->getDIOAndAssertIntegrity(fileMeta);
            if (dio.contextId != file.contextId ||
                dio.resourceId != file.resourceId ||
                !dio.containerId.has_value() ||
                dio.containerId.value() != file.storeId ||
                !dio.containerResourceId.has_value() ||
                dio.containerResourceId.value() != storeResourceId ||
                dio.creatorUserId != file.lastModifier ||
                !core::TimestampValidator::validate(dio.timestamp, file.lastModificationDate)) {
                return FileDataIntegrityException().getCode();
            }
            return 0;
        }
        default:
            return UnknowFileFormatException().getCode();
        }
    } catch (const core::Exception& e) { return e.getCode(); } catch (const privmx::utils::PrivmxException& e) {
        return core::ExceptionConverter::convert(e).getCode();
    } catch (...) { return ENDPOINT_CORE_EXCEPTION_CODE; }
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
    std::vector<server::File> files,
    const core::ModuleKeys& storeKeys,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    if (files.size() == 0) {
        return std::vector<File>{};
    }
    std::vector<File> result(files.size());
    std::vector<core::DataIntegrityObject> filesDIO(files.size());
    std::set<std::string> seenRandomIds;

    // integrity validation
    for (size_t i = 0; i < files.size(); i++) {
        auto code = validateDataIntegrity(files[i], storeKeys.moduleResourceId);

        if (code != 0) {
            result[i] = toLibFile(files[i], {}, {}, 0, {}, code, FileDataSchema::Version::UNKNOWN, false);
        } else {
            result[i].statusCode = 0;
        }
    }

    // batch key fetch with per-file key ID format validation
    const core::EncKeyLocation location{.contextId = storeKeys.contextId, .resourceId = storeKeys.moduleResourceId};
    core::KeyDecryptionAndVerificationRequest keyRequest;
    for (size_t i = 0; i < files.size(); i++) {
        if (result[i].statusCode != 0) {
            continue;
        }
        try {
            _fileKeyIdFormatValidator.assertKeyIdFormat(files[i].keyId);
        } catch (const core::Exception& e) {
            result[i] = toLibFile(files[i], {}, {}, 0, {}, e.getCode(), FileDataSchema::Version::UNKNOWN, false);
            continue;
        }
        keyRequest.addOne(storeKeys.keys, files[i].keyId, location);
    }
    auto keysResult = keyProvider->getKeysAndVerify(keyRequest);
    auto keyMapIt = keysResult.find(location);

    // decrypt + deduplication
    for (size_t i = 0; i < files.size(); i++) {
        if (result[i].statusCode != 0) {
            continue;
        }
        try {
            if (keyMapIt == keysResult.end()) {
                throw UnknowFileFormatException();
            }
            auto [file, dio] = decrypt(files[i], keyMapIt->second.at(files[i].keyId));
            result[i] = file;
            filesDIO[i] = dio;
            if (!seenRandomIds.insert(dio.randomId + "-" + std::to_string(dio.timestamp)).second) {
                result[i].statusCode = core::DataIntegrityObjectDuplicatedException().getCode();
            }
        } catch (const core::Exception& e) {
            result[i] = toLibFile(files[i], {}, {}, 0, {}, e.getCode(), FileDataSchema::Version::UNKNOWN, false);
        }
    }

    // batch identity verification
    std::vector<core::VerificationRequest> verifyRequests;
    std::vector<size_t> verifyIndices;
    for (size_t i = 0; i < result.size(); i++) {
        if (result[i].statusCode != 0) {
            continue;
        }
        verifyRequests.push_back(
            {.contextId = storeKeys.contextId,
             .senderId = result[i].info.author,
             .senderPubKey = result[i].authorPubKey,
             .date = result[i].info.createDate,
             .bridgeIdentity = filesDIO[i].bridgeIdentity}
        );
        verifyIndices.push_back(i);
    }
    auto verified = _connection.getImpl()->getUserVerifier()->verify(verifyRequests);
    for (size_t j = 0; j < verifyIndices.size(); j++) {
        result[verifyIndices[j]].statusCode = verified[j] ?
            0 :
            core::ExceptionConverter::getCodeOfUserVerificationFailureException();
    }
    return result;
}

File FileMetaDataSchemaMapper::validateDecryptAndConvertFile(
    server::File file,
    const core::ModuleKeys& storeKeys,
    const std::shared_ptr<core::KeyProvider>& keyProvider
) {
    return validateDecryptAndConvertFiles({std::move(file)}, storeKeys, keyProvider)[0];
}

dynamic::InternalStoreFileMeta FileMetaDataSchemaMapper::validateDecryptFileInternalMeta(
    server::File file,
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
