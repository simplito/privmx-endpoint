/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/Mapper.hpp"
#include "privmx/endpoint/store/encryptors/fileData/ChunkEncryptor.hpp"

using namespace privmx::endpoint::store;

StoreDeletedEventData Mapper::mapToStoreDeletedEventData(const server::StoreDeletedEventData& data) {
    return {.storeId = data.storeId};
}

StoreFileDeletedEventData Mapper::mapToStoreFileDeletedEventData(const server::StoreFileDeletedEventData& data) {
    return {.contextId = data.contextId, .storeId = data.storeId, .fileId = data.id};
}

StoreStatsChangedEventData Mapper::mapToStoreStatsChangedEventData(const server::StoreStatsChangedEventData& data) {
    return {
        .contextId = data.contextId, .storeId = data.id, .lastFileDate = data.lastFileDate, .filesCount = data.files
    };
}

StoreFileUpdatedEventData Mapper::mapToStoreFileUpdatedEventData(
    const server::StoreFileUpdatedEventData& data,
    const File& file,
    const FileDecryptionParams& fileDecryptionParams
) {
    auto result = StoreFileUpdatedEventData{.file = file, .changes = {}};

    if (data.changes.has_value() && !data.changes->empty()) {
        // The file's own format, not this build's default: the two sizes below convert server offsets
        // into plain ones, and they differ per cipher. Taking the default here reports the wrong range
        // to the application for every file written with another format.
        store::ChunkEncryptor chunkEncryptor = store::ChunkEncryptor(
            fileDecryptionParams.key, fileDecryptionParams.chunkSize,
            FileCipher::forType(fileDecryptionParams.cipherType)
        );
        auto encryptedChunkSize = chunkEncryptor.getEncryptedChunkSize();
        auto plainChunkSize = chunkEncryptor.getPlainChunkSize();
        for (auto change : data.changes.value()) {
            if (change.type == "file") {
                int64_t pos = (change.pos / encryptedChunkSize) * plainChunkSize;
                int64_t length = ((change.length + encryptedChunkSize - 1) / encryptedChunkSize) * plainChunkSize;
                // A change the server reports past the end of the file leaves nothing to report: clamp
                // to zero rather than hand the application a negative length.
                if (pos >= file.size) {
                    pos = file.size;
                    length = 0;
                } else if (pos + length > file.size) {
                    length = file.size - pos;
                }
                result.changes.push_back(FileChange{.pos = pos, .length = length, .truncate = change.truncate});
            }
        }
    }
    return result;
}
