/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/encryptors/file/FileDataSchemaStrategyV4.hpp"
#include "privmx/endpoint/store/encryptors/file/FileMetaDataSchemaMapper.hpp"

#include <privmx/endpoint/core/CoreConstants.hpp>
#include <privmx/endpoint/core/ExceptionConverter.hpp>
#include <privmx/utils/Utils.hpp>

#include "privmx/endpoint/store/Constants.hpp"
#include "privmx/endpoint/store/DynamicTypes.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

DecryptedFileMetaV4 FileDataSchemaStrategyV4::decrypt(
    const server::File& file,
    const core::DecryptedEncKey& encKey
) const {
    auto encryptedFileMeta = server::EncryptedFileMetaV4::fromJSON(file.meta);
    return _encryptor.decrypt(encryptedFileMeta, encKey.key);
}

DecryptedFileMetaV4 FileDataSchemaStrategyV4::decryptFileMeta(
    const server::File& file,
    const core::DecryptedEncKey& encKey
) const {
    try {
        return decrypt(file, encKey);
    } catch (const core::Exception& e) {
        return DecryptedFileMetaV4(
            {{.dataStructureVersion = FileDataSchema::Version::VERSION_4, .statusCode = e.getCode()},
             {},
             {},
             {},
             {},
             {}}
        );
    } catch (const privmx::utils::PrivmxException& e) {
        return DecryptedFileMetaV4(
            {{.dataStructureVersion = FileDataSchema::Version::VERSION_4,
              .statusCode = core::ExceptionConverter::convert(e).getCode()},
             {},
             {},
             {},
             {},
             {}}
        );
    } catch (...) {
        return DecryptedFileMetaV4(
            {{.dataStructureVersion = FileDataSchema::Version::VERSION_4, .statusCode = ENDPOINT_CORE_EXCEPTION_CODE},
             {},
             {},
             {},
             {},
             {}}
        );
    }
}

std::tuple<File, core::DataIntegrityObject> FileDataSchemaStrategyV4::convert(
    const server::File& file,
    const DecryptedFileMetaV4& raw
) const {
    bool randomWrite = false;
    auto statusCode = raw.statusCode;
    if (statusCode == 0) {
        try {
            auto internalMeta = dynamic::InternalStoreFileMeta::fromJSON(
                utils::Utils::parseJson(raw.internalMeta.stdString())
            );
            randomWrite = internalMeta.randomWrite.value_or(false);
        } catch (const core::Exception& e) {
            statusCode = e.getCode();
        } catch (const privmx::utils::PrivmxException& e) {
            statusCode = core::ExceptionConverter::convert(e).getCode();
        } catch (...) { statusCode = ENDPOINT_CORE_EXCEPTION_CODE; }
    }
    return {
        FileMetaDataSchemaMapper::toLibFile(
            file, raw.publicMeta, raw.privateMeta, raw.fileSize, raw.authorPubKey, statusCode,
            FileDataSchema::Version::VERSION_4, randomWrite
        ),
        core::DataIntegrityObject{
            .creatorUserId = file.lastModifier,
            .creatorPubKey = raw.authorPubKey,
            .contextId = file.contextId,
            .resourceId = file.resourceId,
            .timestamp = file.lastModificationDate,
            .randomId = std::string(),
            .containerId = file.storeId,
            .containerResourceId = std::string(),
            .bridgeIdentity = std::nullopt
        }
    };
}

server::EncryptedFileMetaV4 FileDataSchemaStrategyV4::encrypt(
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    const core::Buffer& internalMeta,
    const privmx::crypto::PrivateKey& userPrivKey,
    const std::string& key
) const {
    FileMetaToEncryptV4 fileMeta{
        .publicMeta = publicMeta, .privateMeta = privateMeta, .fileSize = 0, .internalMeta = internalMeta
    };
    return _encryptor.encrypt(fileMeta, userPrivKey, key);
}

std::tuple<File, core::DataIntegrityObject> FileDataSchemaStrategyV4::makeErrorResult(
    const server::File& file,
    int64_t errorCode
) const {
    return {
        FileMetaDataSchemaMapper::toLibFile(file, {}, {}, 0, {}, errorCode, FileDataSchema::Version::VERSION_4, false),
        core::DataIntegrityObject{}
    };
}
