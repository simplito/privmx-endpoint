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
    return {.storeId = data.storeId()};
}

StoreFileDeletedEventData Mapper::mapToStoreFileDeletedEventData(const server::StoreFileDeletedEventData& data) {
    return {.contextId = data.contextId(), .storeId = data.storeId(), .fileId = data.id()};
}

StoreStatsChangedEventData Mapper::mapToStoreStatsChangedEventData(const server::StoreStatsChangedEventData& data) {
    return {.contextId = data.contextId(),
            .storeId = data.id(),
            .lastFileDate = data.lastFileDate(),
            .filesCount = data.files()};
}

StoreFileUpdatedEventData Mapper::mapToStoreFileUpdatedEventData(const server::StoreFileUpdatedEventData& data, const File& file, const FileDecryptionParams& fileDecryptionParams) {
    auto result = StoreFileUpdatedEventData{.file = file, .changes = {}};

    if (!data.changesEmpty()) {
        store::ChunkEncryptor chunkEncryptor = store::ChunkEncryptor(fileDecryptionParams.key, fileDecryptionParams.chunkSize);
        auto encryptedChunkSize =  chunkEncryptor.getEncryptedChunkSize();
        auto plainChunkSize =  chunkEncryptor.getPlainChunkSize();
        for(auto change: data.changes()) {
            if(change.type() == "file") {
                int64_t pos = (change.pos() / encryptedChunkSize) * plainChunkSize;
                int64_t length = ((change.length() + encryptedChunkSize-1) / encryptedChunkSize) * plainChunkSize;
                if(pos+length > file.size) {
                    length = file.size - pos;
                }
                result.changes.push_back(FileChange{
                    .pos = pos,
                    .length = length,
                    .truncate = change.truncate()
                });
            }
        }
    }
    return result;
}
