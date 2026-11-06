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
            {{.dataStructureVersion = FileDataSchema::Version::VERSION_4, .error = core::asError(e)},
             {},
             {},
             {},
             {},
             {}}
        );
    } catch (...) {
        return DecryptedFileMetaV4(
            {{.dataStructureVersion = FileDataSchema::Version::VERSION_4,
              .error = core::unknownError("decrypting file meta")},
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
    auto error = core::toPublicError(raw.error);
    if (!error.has_value()) {
        try {
            auto internalMeta = dynamic::InternalStoreFileMeta::fromJSON(
                utils::Utils::parseJson(raw.internalMeta.stdString())
            );
            randomWrite = internalMeta.randomWrite.value_or(false);
        } catch (const core::Exception& e) { error = core::toPublicError(e); } catch (...) {
            error = core::toPublicError(*core::unknownError("decoding the file's internal meta"));
        }
    }
    return {
        FileMetaDataSchemaMapper::toLibFile(
            file, raw.publicMeta, raw.privateMeta, raw.fileSize, raw.authorPubKey, error,
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

File FileDataSchemaStrategyV4::toLibError(const server::File& file, const std::optional<core::Error>& error) const {
    return FileMetaDataSchemaMapper::toLibFile(file, {}, {}, 0, {}, error, FileDataSchema::Version::VERSION_4, false);
}
