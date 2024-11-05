/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/ChunkDataProvider.hpp"

using namespace privmx::endpoint::store;

ChunkDataProvider::ChunkDataProvider(
    std::shared_ptr<ServerApi> server,
    size_t chunkSize,
    size_t severChunkSize,
    const std::string& fileId,
    uint64_t serverFileSize,
    int64_t fileVersion
)
    : _server(server),
    _encryptedChunkSize(chunkSize),
    _serverChunkSize(getServerReadDataSize(chunkSize, severChunkSize)),
    _fileId(fileId),
    _serverFileSize(serverFileSize),
    _fileVersion(fileVersion)
{}

std::string ChunkDataProvider::getChunk(uint32_t chunkNumber) {
    uint64_t from = _encryptedChunkSize * chunkNumber;
    uint64_t serverChunkNumber = from / _serverChunkSize;
    uint64_t serverChunkPos = from % _serverChunkSize;
    if(!_lastServerChunkNumber.has_value() || _lastServerChunkNumber.value() != serverChunkNumber) {
        _lastServerChunk = requestServerChunk(serverChunkNumber);
        _lastServerChunkNumber = serverChunkNumber;
    }
    return _lastServerChunk.substr(serverChunkPos, _encryptedChunkSize);
}

std::string ChunkDataProvider::getChecksums() {
    auto range = utils::TypedObjectFactory::createNewObject<server::BufferReadRangeChecksum>();
    auto fileDataModel = utils::TypedObjectFactory::createNewObject<server::StoreFileReadModel>();
    fileDataModel.fileId(_fileId);
    fileDataModel.range(range);
    fileDataModel.thumb(false);
    return _server->storeFileRead(fileDataModel).data();
}

std::string ChunkDataProvider::requestServerChunk(uint32_t serverChunkNumber) {
    auto range = utils::TypedObjectFactory::createNewObject<server::BufferReadRangeSlice>();
    auto from = _serverChunkSize * serverChunkNumber;
    range.from(from);
    auto to = _serverChunkSize * (serverChunkNumber + 1);
    range.to(to);

    auto fileDataModel = utils::TypedObjectFactory::createNewObject<server::StoreFileReadModel>();
    fileDataModel.fileId(_fileId);
    fileDataModel.version(_fileVersion);
    fileDataModel.range(range);
    fileDataModel.thumb(false);
    auto fileData = _server->storeFileRead(fileDataModel);
    return fileData.data();
}

int64_t ChunkDataProvider::getServerReadDataSize(int64_t encryptedChunkSize, int64_t severChunkSize) {
    return ((severChunkSize + encryptedChunkSize -1) / encryptedChunkSize) * encryptedChunkSize;
}