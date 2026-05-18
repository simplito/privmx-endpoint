/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/FileHandler.hpp"
#include <Pson/BinaryString.hpp>
#include <map>
#include <privmx/utils/Debug.hpp>

using namespace privmx::endpoint::store;
using namespace privmx::endpoint;

FileHandler::FileHandler(
    std::shared_ptr<IChunkDataProvider> chunkDataProvider,
    std::shared_ptr<IChunkEncryptor> chunkEncryptor,
    std::shared_ptr<IHashList> hashList,
    std::shared_ptr<IChunkReader> chunkReader,
    std::shared_ptr<FileMetaEncryptor> metaEncryptor,
    uint64_t plainfileSize,
    uint64_t encryptedFileSize,
    int64_t version,
    FileInfo fileInfo,
    FileMeta fileMeta,
    core::DecryptedEncKey fileEncKey,
    std::shared_ptr<ServerApi> server
)
    : _chunkDataProvider(chunkDataProvider), _chunkEncryptor(chunkEncryptor), _hashList(hashList),
      _chunkReader(chunkReader), _fileMetaEncryptor(metaEncryptor), _plainfileSize(plainfileSize),
      _encryptedFileSize(encryptedFileSize), _version(version), _fileInfo(fileInfo), _fileMeta(fileMeta),
      _fileEncKey(fileEncKey), _server(server), _plainChunkSize(chunkEncryptor->getPlainChunkSize()),
      _encryptedChunkSize(chunkEncryptor->getEncryptedChunkSize()), _pendingPlainfileSize(plainfileSize) {}

void FileHandler::loadChunkIntoDirty(uint64_t chunkIndex) {
    uint64_t numCommitted = _plainfileSize == 0 ? 0 : (_plainfileSize + _plainChunkSize - 1) / _plainChunkSize;
    // hasMidTruncate: truncate happened during the session but the file was later extended beyond it
    bool hasMidTruncate = _pendingTruncateBoundary < _pendingPlainfileSize && _pendingTruncateBoundary < _plainfileSize;
    uint64_t clearStart = hasMidTruncate ? (_pendingTruncateBoundary + _plainChunkSize - 1) / _plainChunkSize :
                                           numCommitted;

    if (chunkIndex >= numCommitted || chunkIndex >= clearStart) {
        // Gap or cleared chunk — start with zeros
        _dirtyChunks[chunkIndex] = std::string(_plainChunkSize, '\0');
    } else {
        std::string hash = _hashList->getHash(chunkIndex);
        std::string enc = _chunkDataProvider->getChunk(chunkIndex, _version, hash);
        _dirtyChunks[chunkIndex] = _chunkEncryptor->decrypt(chunkIndex, {.data = enc, .hmac = hash});
        // If this is the mid-truncate boundary chunk, zero out data beyond the truncate point
        if (hasMidTruncate) {
            uint64_t boundaryChunk = _pendingTruncateBoundary / _plainChunkSize;
            uint64_t offsetInChunk = _pendingTruncateBoundary % _plainChunkSize;
            if (chunkIndex == boundaryChunk && offsetInChunk > 0) {
                auto& data = _dirtyChunks[chunkIndex];
                if (data.size() > offsetInChunk)
                    data.resize(offsetInChunk);
                data.resize(_plainChunkSize, '\0');
            }
        }
    }
}

void FileHandler::write(uint64_t offset, const core::Buffer& data, bool truncate) {
    auto dataStr = data.stdString();
    uint64_t writeEnd = offset + static_cast<uint64_t>(dataStr.size());

    _pendingPlainfileSize = std::max(_pendingPlainfileSize, writeEnd);

    if (!dataStr.empty()) {
        uint64_t startChunk = offset / _plainChunkSize;
        uint64_t endChunk = (writeEnd - 1) / _plainChunkSize;
        for (uint64_t ci = startChunk; ci <= endChunk; ci++) {
            if (_dirtyChunks.find(ci) == _dirtyChunks.end()) {
                loadChunkIntoDirty(ci);
            }
            auto& chunk = _dirtyChunks[ci];
            uint64_t chunkBase = ci * _plainChunkSize;
            uint64_t writeFrom = std::max(offset, chunkBase);
            uint64_t writeTo = std::min(writeEnd, chunkBase + _plainChunkSize);
            uint64_t posInChunk = writeFrom - chunkBase;
            uint64_t writeLen = writeTo - writeFrom;
            if (chunk.size() < posInChunk + writeLen) {
                chunk.resize(posInChunk + writeLen, '\0');
            }
            chunk.replace(posInChunk, writeLen, dataStr, writeFrom - offset, writeLen);
        }
    }

    if (truncate) {
        this->truncate(writeEnd);
    }
}

void FileHandler::truncate(uint64_t length) {
    _pendingPlainfileSize = length;
    _pendingTruncateBoundary = std::min(_pendingTruncateBoundary, length);
    uint64_t boundaryChunk = length / _plainChunkSize;
    uint64_t offsetInChunk = length % _plainChunkSize;
    _dirtyChunks.erase(_dirtyChunks.upper_bound(boundaryChunk), _dirtyChunks.end());
    if (offsetInChunk == 0) {
        _dirtyChunks.erase(boundaryChunk);
    } else {
        auto it = _dirtyChunks.find(boundaryChunk);
        if (it != _dirtyChunks.end() && it->second.size() > offsetInChunk) {
            it->second.resize(offsetInChunk);
        }
    }
}

core::Buffer FileHandler::read(uint64_t offset, uint64_t size) {
    if (offset >= _pendingPlainfileSize)
        return core::Buffer();
    if (offset + size > _pendingPlainfileSize)
        size = _pendingPlainfileSize - offset;
    if (size == 0)
        return core::Buffer();

    std::string result(size, '\0');
    uint64_t numCommitted = _plainfileSize == 0 ? 0 : (_plainfileSize + _plainChunkSize - 1) / _plainChunkSize;
    // Chunks in [clearStart, numCommitted) were truncated away mid-session and must appear as zeros
    bool hasMidTruncate = _pendingTruncateBoundary < _pendingPlainfileSize && _pendingTruncateBoundary < _plainfileSize;
    uint64_t clearStart = hasMidTruncate ? (_pendingTruncateBoundary + _plainChunkSize - 1) / _plainChunkSize :
                                           numCommitted;
    uint64_t startChunk = offset / _plainChunkSize;
    uint64_t endChunk = (offset + size - 1) / _plainChunkSize;

    for (uint64_t ci = startChunk; ci <= endChunk; ci++) {
        uint64_t chunkBase = ci * _plainChunkSize;
        uint64_t readFrom = std::max(offset, chunkBase);
        uint64_t readTo = std::min(offset + size, chunkBase + _plainChunkSize);
        uint64_t posInChunk = readFrom - chunkBase;
        uint64_t copyLen = readTo - readFrom;
        uint64_t resultOffset = readFrom - offset;

        auto it = _dirtyChunks.find(ci);
        if (it != _dirtyChunks.end()) {
            const auto& plain = it->second;
            if (posInChunk < plain.size()) {
                uint64_t avail = std::min(copyLen, plain.size() - posInChunk);
                result.replace(resultOffset, avail, plain, posInChunk, avail);
            }
        } else if (ci < numCommitted && ci < clearStart) {
            // Committed and not in the mid-truncate cleared range — fetch from server
            std::string plain = _chunkReader->getDecryptedChunk(ci);
            if (posInChunk < plain.size()) {
                uint64_t avail = std::min(copyLen, plain.size() - posInChunk);
                result.replace(resultOffset, avail, plain, posInChunk, avail);
            }
        }
        // gap or cleared area stays as zeros
    }

    return core::Buffer::from(result);
}

uint64_t FileHandler::getFileSize() {
    return _pendingPlainfileSize;
}

void FileHandler::updateOnServer(
    const std::vector<UpdateChunkData>& chunks,
    Poco::Dynamic::Var updatedMeta,
    const std::string& encKeyId,
    bool truncate
) {
    std::vector<server::StoreFileRandomWriteOperation> operations;

    for (size_t i = 0; i < chunks.size();) {
        size_t j = i;
        std::string fileData = chunks[j].chunk.data;
        std::string checksumData = chunks[j].chunk.hmac;
        uint64_t filePos = chunks[j].chunkIndex * _encryptedChunkSize;
        uint64_t checksumPos = chunks[j].chunkIndex * _hashList->getHashSize();

        while (j + 1 < chunks.size() && chunks[j + 1].chunkIndex == chunks[j].chunkIndex + 1) {
            ++j;
            fileData += chunks[j].chunk.data;
            checksumData += chunks[j].chunk.hmac;
        }

        bool isLast = (j == chunks.size() - 1);

        server::StoreFileRandomWriteOperation fileOp;
        fileOp.type = "file";
        fileOp.pos = static_cast<int64_t>(filePos);
        fileOp.data = Pson::BinaryString(fileData);
        fileOp.truncate = isLast ? truncate : false;

        server::StoreFileRandomWriteOperation checksumOp;
        checksumOp.type = "checksum";
        checksumOp.pos = static_cast<int64_t>(checksumPos);
        checksumOp.data = Pson::BinaryString(checksumData);
        checksumOp.truncate = isLast ? truncate : false;

        operations.push_back(std::move(fileOp));
        operations.push_back(std::move(checksumOp));

        i = j + 1;
    }

    server::StoreFileWriteModelByOperations writeRequest;
    writeRequest.fileId = _fileInfo.fileId;
    writeRequest.operations = std::move(operations);
    writeRequest.meta = updatedMeta;
    writeRequest.keyId = encKeyId;
    writeRequest.version = _version;
    writeRequest.force = false;
    _server->storeFileWrite(writeRequest);
    _version += 1;
}

void FileHandler::flush() {
    bool isTruncate = _pendingPlainfileSize < _plainfileSize;
    // hasMidTruncate: truncate happened mid-session but file was later extended beyond the truncate point;
    // chunks in [clearStart, numCommitted) are logically zero on the client but still have old data on the server
    bool hasMidTruncate = _pendingTruncateBoundary < _pendingPlainfileSize && _pendingTruncateBoundary < _plainfileSize;

    // For pure truncate: load and trim the boundary chunk if it's not already dirty
    if (isTruncate) {
        uint64_t boundaryChunk = _pendingPlainfileSize / _plainChunkSize;
        uint64_t offsetInChunk = _pendingPlainfileSize % _plainChunkSize;
        if (offsetInChunk > 0 && _dirtyChunks.find(boundaryChunk) == _dirtyChunks.end()) {
            loadChunkIntoDirty(boundaryChunk);
            _dirtyChunks[boundaryChunk].resize(offsetInChunk);
        }
    }
    // For mid-truncate: load and trim the boundary chunk of the truncate point if not already dirty
    if (hasMidTruncate) {
        uint64_t boundaryChunk = _pendingTruncateBoundary / _plainChunkSize;
        uint64_t offsetInChunk = _pendingTruncateBoundary % _plainChunkSize;
        if (offsetInChunk > 0 && _dirtyChunks.find(boundaryChunk) == _dirtyChunks.end()) {
            loadChunkIntoDirty(boundaryChunk);
            _dirtyChunks[boundaryChunk].resize(offsetInChunk);
        }
    }

    if (_dirtyChunks.empty() && _pendingPlainfileSize == _plainfileSize && !hasMidTruncate)
        return;

    uint64_t numCommitted = _plainfileSize == 0 ? 0 : (_plainfileSize + _plainChunkSize - 1) / _plainChunkSize;
    uint64_t numPending = _pendingPlainfileSize == 0 ? 0 :
                                                       (_pendingPlainfileSize + _plainChunkSize - 1) / _plainChunkSize;
    uint64_t newEncryptedFileSize = _chunkEncryptor->getEncryptedFileSize(_pendingPlainfileSize);

    // Extension: when the file grows but the last committed chunk is partial, load it into
    // dirty so it gets re-encrypted with the correct (larger) expectedSize at upload time.
    if (_pendingPlainfileSize > _plainfileSize && numCommitted > 0 && _plainfileSize % _plainChunkSize != 0) {
        uint64_t lastCommittedChunk = numCommitted - 1;
        if (_dirtyChunks.find(lastCommittedChunk) == _dirtyChunks.end()) {
            loadChunkIntoDirty(lastCommittedChunk);
        }
    }

    // Build ordered upload set: dirty chunks + gap chunks beyond committed range
    std::map<uint64_t, std::string> toUpload(_dirtyChunks);
    for (uint64_t ci = numCommitted; ci < numPending; ci++) {
        if (toUpload.find(ci) == toUpload.end()) {
            toUpload[ci] = std::string(); // gap chunk placeholder, sized in loop below
        }
    }
    // For mid-truncate: add chunks that the server still has but are now logically zero
    if (hasMidTruncate) {
        uint64_t clearStart = (_pendingTruncateBoundary + _plainChunkSize - 1) / _plainChunkSize;
        for (uint64_t ci = clearStart; ci < numCommitted; ci++) {
            if (toUpload.find(ci) == toUpload.end()) {
                toUpload[ci] = std::string(); // zero placeholder
            }
        }
    }
    // Special case: truncate to zero with no dirty chunks
    if (toUpload.empty() && isTruncate) {
        toUpload[0] = std::string();
    }

    auto savedHashList = _hashList->getAll();

    std::vector<UpdateChunkData> chunksToUpdate;
    chunksToUpdate.reserve(toUpload.size());
    for (auto& [ci, plain] : toUpload) {
        uint64_t expectedSize = (ci + 1) * _plainChunkSize <= _pendingPlainfileSize ?
            _plainChunkSize :
            (_pendingPlainfileSize > ci * _plainChunkSize ? _pendingPlainfileSize - ci * _plainChunkSize : 0);
        std::string plainData = plain;
        plainData.resize(expectedSize, '\0');

        auto chunk = _chunkEncryptor->encrypt(ci, plainData);
        bool isLast = (ci == toUpload.rbegin()->first);
        _hashList->set(ci, chunk.hmac, isTruncate && isLast);
        chunksToUpdate.push_back(UpdateChunkData{chunk, plainData, ci});
    }

    store::FileMeta newFileMeta = _fileMeta;
    newFileMeta.internalFileMeta.hmac = utils::Base64::from(_hashList->getTopHash());
    newFileMeta.internalFileMeta.size = static_cast<int64_t>(_pendingPlainfileSize);
    auto newMeta = _fileMetaEncryptor->encrypt(_fileInfo, newFileMeta, _fileEncKey, _fileEncKey.dataStructureVersion);
    try {
        updateOnServer(chunksToUpdate, newMeta, _fileEncKey.id, isTruncate);
    } catch (const core::Exception& e) {
        _hashList->setAll(savedHashList);
        e.rethrow();
    } catch (const privmx::utils::PrivmxException& e) {
        _hashList->setAll(savedHashList);
        e.rethrow();
    }

    _plainfileSize = _pendingPlainfileSize;
    _encryptedFileSize = newEncryptedFileSize;
    _fileMeta = newFileMeta;
    for (auto& upd : chunksToUpdate) {
        bool isLast = (&upd == &chunksToUpdate.back());
        _chunkDataProvider->update(_version, upd.chunkIndex, upd.chunk.data, _encryptedFileSize, isTruncate && isLast);
        _chunkDataProvider->cacheChunk(upd.chunkIndex, upd.chunk.data);
        _chunkReader->update(_version, upd.chunkIndex);
    }
    _pendingTruncateBoundary = UINT64_MAX;
    _dirtyChunks.clear();
    PRIVMX_DEBUG(
        "FileHandler", "flush",
        "_plainfileSize: " +
            std::to_string(_plainfileSize) +
            " | _encryptedFileSize: " +
            std::to_string(_encryptedFileSize)
    );
}

void FileHandler::close() {
    flush();
}

void FileHandler::sync(
    const FileMeta& fileMeta,
    const store::FileDecryptionParams& newParms,
    const core::DecryptedEncKey& fileEncKey
) {
    _hashList->sync(newParms.key, newParms.hmac, _chunkDataProvider->getCurrentChecksumsFromBridge());
    _chunkDataProvider->sync(_version, _encryptedFileSize);
    _chunkReader->sync(newParms);
    _fileMeta = fileMeta;
    _version = newParms.version;
    _plainfileSize = newParms.originalSize;
    _pendingPlainfileSize = newParms.originalSize;
    _encryptedFileSize = newParms.sizeOnServer;
    _fileEncKey = fileEncKey;
    _dirtyChunks.clear();
    _pendingTruncateBoundary = UINT64_MAX;
}

FileHandlerImpl::FileHandlerImpl(std::shared_ptr<FileHandler> file) : _file(file) {}

uint64_t FileHandlerImpl::size() {
    return _file->getFileSize();
}

void FileHandlerImpl::seekg(const uint64_t pos) {
    _readPos = pos;
}

void FileHandlerImpl::seekp(const uint64_t pos) {
    _writePos = pos;
}

core::Buffer FileHandlerImpl::read(const uint64_t length) {
    auto buf = _file->read(_readPos, length);
    _readPos += buf.size();
    return buf;
}

void FileHandlerImpl::write(const core::Buffer& chunk, bool truncate) {
    _file->write(_writePos, chunk, truncate);
    _writePos += chunk.size();
}