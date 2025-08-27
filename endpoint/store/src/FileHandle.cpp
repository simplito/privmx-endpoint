/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/FileHandle.hpp"

#include "privmx/endpoint/store/StoreException.hpp"

#include "privmx/endpoint/store/encryptors/fileData/ChunkEncryptor.hpp"
#include "privmx/endpoint/store/encryptors/fileData/HmacList.hpp"
#include "privmx/endpoint/store/encryptors/file/FileMetaEncryptor.hpp"
#include "privmx/endpoint/store/FileReader.hpp"
#include "privmx/endpoint/store/ChunkReader.hpp"
#include "privmx/endpoint/store/ChunkDataProvider.hpp"
#include "privmx/endpoint/store/FileHandler.hpp"
#include <privmx/endpoint/core/CoreException.hpp>

using namespace privmx::endpoint::store;
using namespace privmx::endpoint;

FileHandle::FileHandle(int64_t id, const std::string& storeId, const std::string& fileId, const std::string& resourceId, uint64_t fileSize, bool randomWriteSupport): 
    _id(id), _storeId(storeId), _fileId(fileId), _resourceId(resourceId), _size(fileSize), _randomWriteSupport(randomWriteSupport) {}

std::string FileHandle::getStoreId() {
    return _storeId;
}

std::string FileHandle::getFileId() {
    return _fileId;
}

std::string FileHandle::getResourceId() {
    return _resourceId;
}

uint64_t FileHandle::getSize() {
    return _size;
}

int64_t FileHandle::getId() {
    return _id;
}

bool FileHandle::getRandomWriteSupport() {
    return _randomWriteSupport;
}

FileReadHandle::FileReadHandle(
    int64_t id, 
    const store::FileDecryptionParams& decryptionParams,
    size_t serverChunkSize,
    std::shared_ptr<ServerApi> server
) 
    : FileHandle(id, std::string(), decryptionParams.fileId, decryptionParams.resourceId, decryptionParams.originalSize, false) 
{
    _chunkEncryptor = std::make_shared<ChunkEncryptor>(decryptionParams.key, decryptionParams.chunkSize);
    _chunkDataProvider = std::make_shared<ChunkDataProvider>(
        server, 
        _chunkEncryptor->getEncryptedChunkSize(), 
        serverChunkSize, 
        decryptionParams.fileId, 
        decryptionParams.sizeOnServer, 
        decryptionParams.version
    );
    _hashList = std::make_shared<HmacList>(
        decryptionParams.key, 
        decryptionParams.hmac, 
        _chunkDataProvider->getCurrentChecksumsFromBridge()
    );
    _chunkReader = std::make_shared<ChunkReader>(_chunkDataProvider, _chunkEncryptor, _hashList, decryptionParams);
    _fileReader = std::make_shared<FileReader>(_chunkReader, decryptionParams);
    _size = decryptionParams.originalSize;
}

void FileReadHandle::sync(
    const store::FileDecryptionParams& newDecryptionParams
) {
    if(newDecryptionParams.sizeOnServer != _chunkEncryptor->getEncryptedFileSize(newDecryptionParams.originalSize)) {
        throw FileCorruptedException();
    }
    _chunkEncryptor->sync(newDecryptionParams.key, newDecryptionParams.chunkSize);
    _hashList->sync(newDecryptionParams.key, newDecryptionParams.hmac, _chunkDataProvider->getCurrentChecksumsFromBridge());
    _chunkDataProvider->sync(newDecryptionParams.version, newDecryptionParams.sizeOnServer);
    _chunkReader->sync(newDecryptionParams);
    _fileReader->sync(newDecryptionParams);
    _size = newDecryptionParams.originalSize;
}

std::string FileReadHandle::read(uint64_t length) {
    if (length > SIZE_MAX) {
        throw NumberToBigForCPUArchitectureException("length to big for this CPU Architecture");
    }
    std::string result = _fileReader->read(_pos, length);
    _pos += length;
    return result;
}

void FileReadHandle::seek(uint64_t pos) {
    if(_size <= pos) {
        throw PosOutOfBoundsException();
    }
    _pos = pos;
}

FileWriteHandle::FileWriteHandle(
    int64_t id, 
    const std::string& storeId,
    const std::string& fileId,
    const std::string& resourceId, 
    uint64_t size,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    uint64_t chunkSize,
    uint64_t serverRequestChunkSize,
    std::shared_ptr<RequestApi> requestApi,
    bool randomWriteSupport
)
    : FileHandle(id, storeId, fileId, resourceId, size, randomWriteSupport),
    _publicMeta(publicMeta),
    _privateMeta(privateMeta),
    _stream(ChunkBufferedStream(chunkSize, size)),
    _streamer(ChunkStreamer(requestApi, chunkSize, size, serverRequestChunkSize))
{}

void FileWriteHandle::write(const std::string& data) {
    _stream.write(data);
    for(uint64_t i = 0; i < _stream.getNumberOfFullChunks(); i++) {
        _streamer.sendChunk(_stream.getFullChunk(i));
    }
    _stream.freeFullChunks();
}

privmx::endpoint::store::ChunksSentInfo FileWriteHandle::finalize() {
    if(!_stream.isFullyFilled()) {
        throw core::DataDifferentThanDeclaredException();
    }
    auto result = _streamer.finalize(_stream.readChunk());
    _size = _streamer.getUploadedFileSize();
    return result;
}

bool FileWriteHandle::isReadyToFinalize() {
    return _stream.isFullyFilled();
}

core::Buffer FileWriteHandle::getPublicMeta() {
    return _publicMeta;
}
core::Buffer FileWriteHandle::getPrivateMeta() {
    return _privateMeta;
}

privmx::endpoint::store::FileSizeResult FileWriteHandle::getEncryptedFileSize() {
    return _streamer.getFileSize();
}

void FileWriteHandle::createRequestData() {
    _streamer.createRequest(getRandomWriteSupport());
}

void FileWriteHandle::setRequestData(const std::string& requestId, const std::string& key, const Poco::Int64& fileIndex) {
    _streamer.setRequestData(requestId, key, fileIndex);
}

FileReadWriteHandle::FileReadWriteHandle(
    int64_t id,
    const store::FileInfo &fileInfo,
    const store::FileEncryptionParams& encryptionParams,
    size_t serverChunkSize,
    const privmx::crypto::PrivateKey &userPrivKey,
    const privmx::endpoint::core::Connection &connection,
    std::shared_ptr<privmx::endpoint::store::ServerApi> serverApi
) : FileHandle(id, fileInfo.storeId, encryptionParams.fileDecryptionParams.fileId, encryptionParams.fileDecryptionParams.resourceId, 0, true) {
    std::shared_ptr<FileMetaEncryptor> fileMetaEncryptor = std::make_shared<FileMetaEncryptor>(userPrivKey, connection);
    std::shared_ptr<ChunkEncryptor> chunkEncryptor = std::make_shared<ChunkEncryptor>(encryptionParams.fileDecryptionParams.key, encryptionParams.fileDecryptionParams.chunkSize);
    std::shared_ptr<ChunkDataProvider> chunkDataProvider = std::make_shared<ChunkDataProvider>(
        serverApi, 
        chunkEncryptor->getEncryptedChunkSize(),
        serverChunkSize, 
        encryptionParams.fileDecryptionParams.fileId, 
        encryptionParams.fileDecryptionParams.sizeOnServer, 
        encryptionParams.fileDecryptionParams.version
    );
    std::shared_ptr<IHashList> hashList = std::make_shared<HmacList>(
        encryptionParams.fileDecryptionParams.key, 
        encryptionParams.fileDecryptionParams.hmac, 
        chunkDataProvider->getCurrentChecksumsFromBridge()
    );
    std::shared_ptr<IChunkReader> chunkReader = std::make_shared<ChunkReader>(chunkDataProvider, chunkEncryptor, hashList, encryptionParams.fileDecryptionParams);
    std::shared_ptr<FileHandler> fileHandler = std::make_shared<FileHandler>(
        chunkDataProvider, chunkEncryptor, hashList, chunkReader, fileMetaEncryptor, 
        encryptionParams.fileDecryptionParams.originalSize,
        encryptionParams.fileDecryptionParams.sizeOnServer,
        encryptionParams.fileDecryptionParams.version,
        fileInfo,
        encryptionParams.fileMeta,
        encryptionParams.encKey,
        serverApi
    );
    file = std::make_shared<FileHandlerImpl>(fileHandler);
}

FileHandleManager::FileHandleManager(std::shared_ptr<core::HandleManager> handleManager, const std::string& labelPrefix) : 
    _handleManager(handleManager), _labelPrefix(labelPrefix) {}

std::shared_ptr<FileReadHandle> FileHandleManager::createFileReadHandle(
    const store::FileDecryptionParams& decryptionParams,
    size_t serverChunkSize,
    std::shared_ptr<ServerApi> server
) {
    int64_t id = _handleManager->createHandle((_labelPrefix.empty() ? "" : _labelPrefix + ":") + "FileRead");
    std::shared_ptr<FileReadHandle> result = std::make_shared<FileReadHandle>(id, decryptionParams, serverChunkSize, server);
    _map.set(id, result);
    return result;
}

std::shared_ptr<FileWriteHandle> FileHandleManager::createFileWriteHandle(
    const std::string& storeId,
    const std::string& fileId,
    const std::string& resourceId,
    uint64_t size,
    const core::Buffer& publicMeta,
    const core::Buffer& privateMeta,
    uint64_t chunkSize,
    uint64_t serverRequestChunkSize,
    std::shared_ptr<RequestApi> requestApi,
    bool randomWriteSupport
) {
    int64_t id = _handleManager->createHandle((_labelPrefix.empty() ? "" : _labelPrefix + ":") + "FileWrite");
    std::shared_ptr<FileWriteHandle> result = std::make_shared<FileWriteHandle>(id, storeId, fileId, resourceId, size, publicMeta, privateMeta, chunkSize, serverRequestChunkSize, requestApi, randomWriteSupport);
    _map.set(id, result);
    return result;
}

std::shared_ptr<FileReadWriteHandle> FileHandleManager::createFileReadWriteHandle(
    const store::FileInfo &fileInfo,
    const store::FileEncryptionParams& encryptionParams,
    size_t serverChunkSize,
    const privmx::crypto::PrivateKey &userPrivKey,
    const privmx::endpoint::core::Connection &connection,
    std::shared_ptr<privmx::endpoint::store::ServerApi> serverApi
) {
    int64_t id = _handleManager->createHandle("FileReadWrite");
    std::shared_ptr<FileReadWriteHandle> result = std::make_shared<FileReadWriteHandle>(id, fileInfo, encryptionParams, serverChunkSize, userPrivKey, connection, serverApi);
    _map.set(id, result);
    return result;
}

std::shared_ptr<FileReadHandle> FileHandleManager::getFileReadHandle(int64_t id) {
    std::shared_ptr<FileHandle> handle = getFileHandle(id);
    if (!handle->isReadHandle()) {
        throw InvalidFileReadHandleException();
    }
    return std::dynamic_pointer_cast<FileReadHandle>(handle);
}

std::shared_ptr<FileWriteHandle> FileHandleManager::getFileWriteHandle(int64_t id) {
    std::shared_ptr<FileHandle> handle = getFileHandle(id);
    if (!handle->isWriteHandle()) {
        throw InvalidFileWriteHandleException();
    }
    return std::dynamic_pointer_cast<FileWriteHandle>(handle);
}

std::shared_ptr<FileReadWriteHandle> FileHandleManager::tryGetFileReadWriteHandle(int64_t id) {
    std::shared_ptr<FileHandle> handle = getFileHandle(id);
    if (!handle->isFileReadWriteHandle()) {
        return std::shared_ptr<FileReadWriteHandle>();
    }
    return std::dynamic_pointer_cast<FileReadWriteHandle>(handle);
}

std::shared_ptr<FileHandle> FileHandleManager::getFileHandle(int64_t id) {
    auto optionalHandle = _map.get(id);
    if (!optionalHandle.has_value()) {
        throw InvalidFileHandleException();
    }
    std::shared_ptr<FileHandle> handle = optionalHandle.value();
    return handle;
}

void FileHandleManager::removeHandle(int64_t id) {
    auto handle = _map.get(id);
    if (!handle.has_value()) {
        throw InvalidFileHandleException();
    }
    _map.erase(id);
    _handleManager->removeHandle(id);
}
