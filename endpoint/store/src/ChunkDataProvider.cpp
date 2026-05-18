/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/ChunkDataProvider.hpp"
#include "privmx/endpoint/core/ConvertedExceptions.hpp"
#include "privmx/endpoint/core/ExceptionConverter.hpp"
#include "privmx/endpoint/store/StoreException.hpp"
#include "privmx/endpoint/store/cache/CacheKey.hpp"
#include <Pson/BinaryString.hpp>

using namespace privmx::endpoint::store;

ChunkDataProvider::ChunkDataProvider(
    std::shared_ptr<ServerApi> server,
    std::shared_ptr<IChunkEncryptor> chunkEncryptor,
    size_t chunkSize,
    size_t severChunkSize,
    const std::string& fileId,
    uint64_t serverFileSize,
    int64_t fileVersion,
    std::shared_ptr<CacheInterface> cache
)
    : _server(server), _chunkEncryptor(chunkEncryptor), _encryptedChunkSize(chunkSize),
      _serverChunkSize(getServerReadDataSize(chunkSize, severChunkSize)), _fileId(fileId),
      _serverFileSize(serverFileSize), _fileVersion(fileVersion), _cache(std::move(cache)) {}

void ChunkDataProvider::sync(
    int64_t newfileVersion,
    int64_t encryptedFileSize,
    std::optional<size_t> encryptedChunkSize,
    std::optional<size_t> serverChunkSize
) {
    if (_fileVersion < newfileVersion) {
        _lastServerChunkNumber = std::nullopt;
        _lastServerChunk = "";
    }
    _serverFileSize = encryptedFileSize;
    _fileVersion = newfileVersion;
    if (encryptedChunkSize.has_value()) {
        _encryptedChunkSize = encryptedChunkSize.value();
    }
    if (serverChunkSize.has_value()) {
        _serverChunkSize = serverChunkSize.value();
    }
}

std::string ChunkDataProvider::getChunk(uint32_t chunkNumber, const std::string& hash) {
    return getChunk(chunkNumber, _fileVersion, hash);
}

std::string ChunkDataProvider::getChunk(uint32_t chunkNumber, int64_t fileVersion, const std::string& hash) {
    auto cacheKey = CacheKey::chunk(_fileId, chunkNumber);
    auto cached = _cache->get(cacheKey);
    if (cached.has_value()) {
        if (!_chunkEncryptor->hasHash(cached.value(), hash)) {
            // TODO: Race condition: between get() and del() another thread may have replaced the entry
            // with a valid chunk, but we delete it anyway — non-atomic, acceptable as best-effort eviction.
            _cache->del(cacheKey);
        } else {
            return cached.value();
        }
    }

    if (fileVersion != _fileVersion) {
        _lastServerChunkNumber = std::nullopt;
        _fileVersion = fileVersion;
    }
    uint64_t from = _encryptedChunkSize * chunkNumber;
    uint64_t serverChunkNumber = from / _serverChunkSize;
    uint64_t serverChunkPos = from % _serverChunkSize;
    if (!_lastServerChunkNumber.has_value() || _lastServerChunkNumber.value() != serverChunkNumber) {
        _lastServerChunk = requestServerChunk(serverChunkNumber);
        _lastServerChunkNumber = serverChunkNumber;

        uint64_t firstChunkNumber = serverChunkNumber * _serverChunkSize / _encryptedChunkSize;
        uint64_t chunksInSegment = (_lastServerChunk.size() + _encryptedChunkSize - 1) / _encryptedChunkSize;
        for (uint64_t i = 0; i < chunksInSegment; ++i) {
            uint64_t pos = i * _encryptedChunkSize;
            _cache->put(
                CacheKey::chunk(_fileId, firstChunkNumber + i),
                Pson::BinaryString(_lastServerChunk.substr(pos, _encryptedChunkSize))
            );
        }
    }
    if (serverChunkPos > _lastServerChunk.size()) {
        return std::string();
    }
    return _lastServerChunk.substr(serverChunkPos, _encryptedChunkSize);
}

std::string ChunkDataProvider::getCurrentChecksumsFromBridge() {
    server::StoreFileReadModel fileDataModel{};
    fileDataModel.fileId = _fileId;
    fileDataModel.range = server::BufferReadRange{.type = "checksum"}.toJSON();
    fileDataModel.thumb = false;
    return _server->storeFileRead(fileDataModel).data;
}

void ChunkDataProvider::update(
    int64_t newfileVersion,
    uint32_t chunkNumber,
    const std::string newChunkEncryptedData,
    int64_t encryptedFileSize,
    bool truncate
) {
    uint64_t from = _encryptedChunkSize * chunkNumber;
    uint64_t serverChunkNumber = from / _serverChunkSize;
    uint64_t serverChunkPos = from % _serverChunkSize;
    if (_lastServerChunkNumber.has_value() && _lastServerChunkNumber.value() == serverChunkNumber) {
        std::string oldServerChunkDataBefore = _lastServerChunk.substr(0, serverChunkPos);
        std::string oldServerChunkDataAfter = "";
        if (!truncate && _lastServerChunk.size() > serverChunkPos + newChunkEncryptedData.size()) {
            oldServerChunkDataAfter = _lastServerChunk.substr(serverChunkPos + newChunkEncryptedData.size());
        }
        _lastServerChunk = oldServerChunkDataBefore + newChunkEncryptedData + oldServerChunkDataAfter;
    }
    _serverFileSize = encryptedFileSize;
    _fileVersion = newfileVersion;
}

void ChunkDataProvider::cacheChunk(uint32_t chunkNumber, const std::string& encryptedData) {
    _cache->put(CacheKey::chunk(_fileId, chunkNumber), Pson::BinaryString(encryptedData));
}

std::string ChunkDataProvider::requestServerChunk(uint32_t serverChunkNumber) {
    server::BufferReadRangeSlice range{
        server::BufferReadRange{.type = "slice"}, .from = _serverChunkSize * serverChunkNumber,
        .to = _serverChunkSize * (serverChunkNumber + 1)
    };
    server::StoreFileReadModel fileDataModel{};
    fileDataModel.fileId = _fileId;
    fileDataModel.range = range.toJSON();
    fileDataModel.version = _fileVersion;
    fileDataModel.thumb = false;
    server::StoreFileReadResult fileData;
    try {
        fileData = _server->storeFileRead(fileDataModel);
    } catch (const utils::PrivmxException& e) {
        if (core::ExceptionConverter::convert(e).getCode() ==
            privmx::endpoint::server::StoreFileVersionMismatchException().getCode()) {
            // STORE_FILE_VERSION_MISMATCH
            throw store::FileVersionMismatchException();
        } else {
            e.rethrow();
        }
    }
    return fileData.data;
}

int64_t ChunkDataProvider::getServerReadDataSize(int64_t encryptedChunkSize, int64_t severChunkSize) {
    return ((severChunkSize + encryptedChunkSize - 1) / encryptedChunkSize) * encryptedChunkSize;
}