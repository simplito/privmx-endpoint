/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/ChunkDataProvider.hpp"
#include "privmx/endpoint/store/StoreException.hpp"
#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/core/ConvertedExceptions.hpp"

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

void ChunkDataProvider::sync(
    int64_t newfileVersion, 
    int64_t encryptedFileSize, 
    std::optional<size_t> encryptedChunkSize, 
    std::optional<size_t> serverChunkSize
) {
    if(_fileVersion < newfileVersion) {
        _lastServerChunkNumber = std::nullopt;
        _lastServerChunk = "";
    }
    _serverFileSize = encryptedFileSize;
    _fileVersion = newfileVersion;
    if(encryptedChunkSize.has_value()) {
        _encryptedChunkSize = encryptedChunkSize.value();
    }
    if(serverChunkSize.has_value()) {
        _serverChunkSize = serverChunkSize.value();
    }
}

std::string ChunkDataProvider::getChunk(uint32_t chunkNumber) {
    return getChunk(chunkNumber, _fileVersion);
}

std::string ChunkDataProvider::getChunk(uint32_t chunkNumber, int64_t fileVersion) {
    if(fileVersion != _fileVersion) {
        _lastServerChunkNumber = std::nullopt;
        _fileVersion = fileVersion;
    }
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

void ChunkDataProvider::update(int64_t newfileVersion, uint32_t chunkNumber, const std::string newChunkEncryptedData, int64_t encryptedFileSize, bool truncate) {
    uint64_t from = _encryptedChunkSize * chunkNumber;
    uint64_t serverChunkNumber = from / _serverChunkSize;
    uint64_t serverChunkPos = from % _serverChunkSize;
    if(_fileVersion < newfileVersion) {
        if(_lastServerChunkNumber.has_value() && _lastServerChunkNumber.value() == serverChunkNumber) {
            std::string oldServerChunkDataBefore = _lastServerChunk.substr(0, serverChunkPos);
            std::string oldServerChunkDataAfter = "";
            if(!truncate && _lastServerChunk.size() > serverChunkPos + newChunkEncryptedData.size()) {
                oldServerChunkDataAfter = _lastServerChunk.substr(serverChunkPos + newChunkEncryptedData.size());
            }
            _lastServerChunk = oldServerChunkDataBefore + newChunkEncryptedData + oldServerChunkDataAfter;
        }
        _serverFileSize = encryptedFileSize;
        _fileVersion = newfileVersion;
    }
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
    auto fileData = utils::TypedObjectFactory::createNewObject<server::StoreFileReadResult>();
    try {
        fileData = _server->storeFileRead(fileDataModel);
    } catch(const utils::PrivmxException& e) {
        if(core::ExceptionConverter::convert(e).getCode() == privmx::endpoint::server::StoreFileVersionMismatchException().getCode()) {
            // STORE_FILE_VERSION_MISMATCH
            throw store::FileVersionMismatchException();
        } else {
            e.rethrow();
        }
    }
    return fileData.data();
}

int64_t ChunkDataProvider::getServerReadDataSize(int64_t encryptedChunkSize, int64_t severChunkSize) {
    return ((severChunkSize + encryptedChunkSize -1) / encryptedChunkSize) * encryptedChunkSize;
}