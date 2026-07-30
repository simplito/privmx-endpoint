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
      _segmentSize(getSegmentSize(chunkSize, severChunkSize)), _fileId(fileId), _serverFileSize(serverFileSize),
      _fileVersion(fileVersion), _cache(std::move(cache)) {}

void ChunkDataProvider::sync(int64_t newfileVersion, int64_t encryptedFileSize) {
    if (_fileVersion < newfileVersion) {
        _lastSegmentNumber = std::nullopt;
        _lastSegment = "";
    }
    _serverFileSize = encryptedFileSize;
    _fileVersion = newfileVersion;
}

std::string ChunkDataProvider::getChunk(uint32_t chunkNumber, const std::string& hash) {
    return getChunk(chunkNumber, _fileVersion, hash);
}

// NOTE: Concurrent calls to getChunk() are not intended. Two races are present:
//   1. get() + del() are non-atomic — another thread may write a valid chunk between them, which we then delete.
//   2. On a cache miss, concurrent callers will each issue a separate server request for the same chunk part.
// Fix: synchronize getChunk().
std::string ChunkDataProvider::getChunk(uint32_t chunkNumber, int64_t fileVersion, const std::string& hash) {
    auto cacheKey = CacheKey::chunk(_fileId, chunkNumber);
    auto cached = _cache->get(cacheKey);
    if (cached.has_value()) {
        auto value = cached->stdString();
        if (!_chunkEncryptor->hasHash(value, hash)) {
            _cache->del(cacheKey);
        } else {
            return value;
        }
    }

    if (fileVersion != _fileVersion) {
        _lastSegmentNumber = std::nullopt;
        _fileVersion = fileVersion;
    }
    uint64_t from = _encryptedChunkSize * chunkNumber;
    uint64_t segmentNumber = from / _segmentSize;
    uint64_t segmentPos = from % _segmentSize;
    if (!_lastSegmentNumber.has_value() || _lastSegmentNumber.value() != segmentNumber) {
        _lastSegment = requestSegment(segmentNumber);
        _lastSegmentNumber = segmentNumber;

        uint64_t firstChunkNumber = segmentNumber * _segmentSize / _encryptedChunkSize;
        uint64_t chunksInSegment = (_lastSegment.size() + _encryptedChunkSize - 1) / _encryptedChunkSize;
        for (uint64_t i = 0; i < chunksInSegment; ++i) {
            uint64_t pos = i * _encryptedChunkSize;
            _cache->put(
                CacheKey::chunk(_fileId, firstChunkNumber + i),
                core::Buffer::from(_lastSegment.substr(pos, _encryptedChunkSize))
            );
        }
    }
    if (segmentPos > _lastSegment.size()) {
        return std::string();
    }
    return _lastSegment.substr(segmentPos, _encryptedChunkSize);
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
    uint64_t segmentNumber = from / _segmentSize;
    uint64_t segmentPos = from % _segmentSize;
    if (_lastSegmentNumber.has_value() && _lastSegmentNumber.value() == segmentNumber) {
        std::string segmentDataBefore = _lastSegment.substr(0, segmentPos);
        std::string segmentDataAfter = "";
        if (!truncate && _lastSegment.size() > segmentPos + newChunkEncryptedData.size()) {
            segmentDataAfter = _lastSegment.substr(segmentPos + newChunkEncryptedData.size());
        }
        _lastSegment = segmentDataBefore + newChunkEncryptedData + segmentDataAfter;
    }
    _serverFileSize = encryptedFileSize;
    _fileVersion = newfileVersion;
}

void ChunkDataProvider::cacheChunk(uint32_t chunkNumber, const std::string& encryptedData) {
    _cache->put(CacheKey::chunk(_fileId, chunkNumber), core::Buffer::from(encryptedData));
}

std::string ChunkDataProvider::requestSegment(uint32_t segmentNumber) {
    server::BufferReadRangeSlice range{
        server::BufferReadRange{.type = "slice"}, .from = _segmentSize * segmentNumber,
        .to = _segmentSize * (segmentNumber + 1)
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

int64_t ChunkDataProvider::getSegmentSize(int64_t encryptedChunkSize, int64_t severChunkSize) {
    return ((severChunkSize + encryptedChunkSize - 1) / encryptedChunkSize) * encryptedChunkSize;
}