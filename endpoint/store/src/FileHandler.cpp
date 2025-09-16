/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/FileHandler.hpp"
#include <privmx/utils/Debug.hpp>

using namespace privmx::endpoint::store;
using namespace privmx::endpoint;

FileHandler::FileHandler (
    std::shared_ptr<IChunkDataProvider> chunkDataProvider,
    std::shared_ptr<IChunkEncryptor> chunkEncryptor,
    std::shared_ptr<IHashList> hashList,
    std::shared_ptr<IChunkReader> chunkReader,
    std::shared_ptr<FileMetaEncryptor> metaEncryptor,
    size_t plainfileSize,
    size_t encryptedFileSize,
    int64_t version,
    FileInfo fileInfo,
    FileMeta fileMeta,
    core::DecryptedEncKey fileEncKey,
    std::shared_ptr<ServerApi> server
) : 
    _chunkDataProvider(chunkDataProvider),
    _chunkEncryptor(chunkEncryptor),
    _hashList(hashList),
    _chunkReader(chunkReader),
    _fileMetaEncryptor(metaEncryptor),
    _plainfileSize(plainfileSize),
    _encryptedFileSize(encryptedFileSize),
    _version(version),
    _fileInfo(fileInfo),
    _fileMeta(fileMeta),
    _fileEncKey(fileEncKey),
    _server(server),
    _plainChunkSize(chunkEncryptor->getPlainChunkSize()),
    _encryptedChunkSize(chunkEncryptor->getEncryptedChunkSize())
{}

void FileHandler::write(size_t offset, const core::Buffer& data, bool truncate) { // data = buf + size
    auto toSend = data.stdString();
    if (_plainfileSize < offset) { 
        // if fileSize smaller than offset fill here empty space with 0
        auto emptyChars = std::string(offset - _plainfileSize, (char)0x00);
        offset = _plainfileSize;
        toSend = emptyChars + toSend;
    }
    // start writing to offset chunk
    size_t startIndex = _chunkReader->filePosToFileChunkIndex(offset);
    size_t stopIndex = _chunkReader->filePosToFileChunkIndex(offset+toSend.size()-1);
    size_t dataSend = 0;
    std::vector<FileHandler::UpdateChunkData> chunksToUpdate;
    auto newPlainfileSize = _plainfileSize;
    auto newEncryptedFileSize = _encryptedFileSize;
    // prepare chunk to update
    for(size_t i = startIndex; i <= stopIndex; i++) {
        if(i == startIndex) {
            size_t chunkOffset = offset % _chunkEncryptor->getPlainChunkSize();
            std::string chunkData = toSend.substr(dataSend, _plainChunkSize -(offset % _plainChunkSize));
            chunksToUpdate.push_back(createUpdateChunk(i, chunkOffset, chunkData, i == stopIndex ? truncate: false));
            dataSend += chunkData.size();
        } else {
            size_t chunkOffset = 0;
            std::string chunkData = toSend.substr(dataSend, _plainChunkSize);
            chunksToUpdate.push_back(createUpdateChunk(i, chunkOffset, chunkData, i == stopIndex ? truncate: false));
            dataSend += chunkData.size();
        }
    }
    // prepare meta ChunksToUpdate and rollback HashList
    auto oldHashList = _hashList->getAll();
    for(size_t i = 0; i < chunksToUpdate.size(); i++) {
        //update _hashList, newPlainfileSize, newEncryptedFileSize
        auto& updateInfo = chunksToUpdate.at(i);
        _hashList->set(updateInfo.chunkIndex, updateInfo.chunk.hmac, i == chunksToUpdate.size()-1 ? truncate : false);
        newPlainfileSize += updateInfo.plainfileSizeChange;
        newEncryptedFileSize += updateInfo.encryptedFileSizeChange;
    }
    // squash chunksToUpdate 
    auto squashedChunksToUpdate = createListOfUpdateChangesFromUpdateChunkData(chunksToUpdate);
    // update meta
    store::FileMeta newFileMeta = {
        _fileMeta.publicMeta,
        _fileMeta.privateMeta,
        privmx::utils::TypedObjectFactory::createObjectFromVar<dynamic::InternalStoreFileMeta>(privmx::utils::Utils::jsonObjectDeepCopy(_fileMeta.internalFileMeta))
    };
    newFileMeta.internalFileMeta.hmac(utils::Base64::from(_hashList->getTopHash()));
    newFileMeta.internalFileMeta.size(newPlainfileSize);
    auto newMeta = _fileMetaEncryptor->encrypt(_fileInfo, newFileMeta, _fileEncKey, _fileEncKey.dataStructureVersion);
    try {
        updateOnServer(squashedChunksToUpdate, newMeta, _fileEncKey.id, truncate);
    } catch (const core::Exception& e) {
        //roll back all changes
        _hashList->setAll(oldHashList);
        e.rethrow();
    } catch (const privmx::utils::PrivmxException& e) {
        //roll back all changes
        _hashList->setAll(oldHashList);
        e.rethrow();
    }
    // update Info
    _version += 1;
    _fileMeta = newFileMeta;
    _plainfileSize = newPlainfileSize;
    _encryptedFileSize = newEncryptedFileSize;
    for(auto& updateInfo : chunksToUpdate) {
        _chunkDataProvider->update(_version, updateInfo.chunkIndex, updateInfo.chunk.data, _encryptedFileSize, truncate);
        _chunkReader->update(_version, updateInfo.chunkIndex);
    }
    PRIVMX_DEBUG("FileHandler", "write", "_plainfileSize: " + std::to_string(_plainfileSize)+ " | _encryptedFileSize: " + std::to_string(_encryptedFileSize)); 
}

core::Buffer FileHandler::read(size_t offset, size_t size) {
    if(offset >= _plainfileSize) return core::Buffer();
    if(offset+size > _plainfileSize) size = _plainfileSize-offset;
    if(size == 0) return core::Buffer();
    size_t startIndex = _chunkReader->filePosToFileChunkIndex(offset);
    size_t stopIndex = _chunkReader->filePosToFileChunkIndex(offset+size-1);
    std::string data = std::string();
    for(size_t i = startIndex; i <= stopIndex; i++) {
        data.append(_chunkReader->getDecryptedChunk(i));
    }
    return core::Buffer::from( data.substr(_chunkReader->filePosToPosInFileChunk(offset), size) );
}

size_t FileHandler::getFileSize() {
    return _plainfileSize;
}

FileHandler::UpdateChunkData FileHandler::createUpdateChunk(size_t index, size_t chunkOffset, const std::string& data, bool truncate){
    // check if new data fit in _plainChunkSize
    if ((chunkOffset + data.size()) > _plainChunkSize) {
        // "Given data with offset won't fit Chunk
        throw FileRandomWriteInternalException("Given data with offset won't fit Chunk");
        // throw
    }
    std::string newChunk = std::string();
    // read old chunk
    std::string prevEncryptedChunk = _chunkDataProvider->getChunk(index, _version);
    std::string prevChunk = "";
    if(prevEncryptedChunk.size() != 0) {
        prevChunk = _chunkEncryptor->decrypt(index, {.data = prevEncryptedChunk, .hmac = _hashList->getHash(index)});
    }
    // fill new chunk data to chunkOffset
    if(chunkOffset > 0) {
        newChunk.append(prevChunk.substr(0, chunkOffset));
        // fill empty space between chunkOffset and prevChunk with (char)0x00
        if (chunkOffset > prevChunk.size()) {
            newChunk.append(std::string(chunkOffset - prevChunk.size(), (char)0x00));
        }
    }
    // fill new chunk data from chunkOffset to data.size()
    newChunk.append(data);
    // fill new chunk data from chunkOffset + data.size() to end of chunk
    if(prevChunk.size() > chunkOffset + data.size() && !truncate) {
        newChunk.append(prevChunk.substr(chunkOffset + data.size()));
    }
    // set newChunk;
    auto chunk = _chunkEncryptor->encrypt(index, newChunk);

    return FileHandler::UpdateChunkData{
        chunk,
        index,
        truncate ? (int64_t)(index * _plainChunkSize + newChunk.size()) - (int64_t)_plainfileSize : (int64_t)newChunk.size() - (int64_t)prevChunk.size(),
        truncate ? (int64_t)(index * _encryptedChunkSize + chunk.data.size()) - (int64_t)_encryptedFileSize : (int64_t)chunk.data.size() - (int64_t)prevEncryptedChunk.size()
    };
}

void FileHandler::updateOnServer(const std::vector<FileHandler::UpdateChanges>& updatedChunks, Poco::Dynamic::Var updatedMeta, const std::string& encKeyId, bool truncate) {
    for(size_t i = 0; i < updatedChunks.size();) { 
        // update file by operation
        auto operations = utils::TypedObjectFactory::createNewList<server::StoreFileRandomWriteOperation>();
        for(size_t j = 0; j < (SERVER_OPERATIONS_LIMIT>>1) && i < updatedChunks.size(); ++j,++i) {
            auto& updatedChunk = updatedChunks.at(i);
            auto operation1 = utils::TypedObjectFactory::createNewObject<server::StoreFileRandomWriteOperation>();
            operation1.type("file");
            operation1.pos(updatedChunk.dataPos);
            operation1.data(updatedChunk.data);
            operation1.truncate(i == updatedChunks.size()-1 ? truncate : true);

            auto operation2 = utils::TypedObjectFactory::createNewObject<server::StoreFileRandomWriteOperation>();
            operation2.type("checksum");
            operation2.pos(updatedChunk.checksumPos);
            operation2.data(updatedChunk.checksum);
            operation2.truncate(i == updatedChunks.size()-1 ? truncate : true);

            operations.add(operation1);
            operations.add(operation2);
        }

        auto writeRequest = utils::TypedObjectFactory::createNewObject<server::StoreFileWriteModelByOperations>();
        writeRequest.fileId(_fileInfo.fileId);
        writeRequest.operations(operations);
        writeRequest.meta(updatedMeta);
        writeRequest.keyId(encKeyId);
        writeRequest.version(_version);
        writeRequest.force(false);
        _server->storeFileWrite(writeRequest);
    }
}

void FileHandler::sync(const FileMeta& fileMeta, const store::FileDecryptionParams& newParms, const core::DecryptedEncKey& fileEncKey) {
    _hashList->sync(newParms.key, newParms.hmac, _chunkDataProvider->getCurrentChecksumsFromBridge());
    _chunkDataProvider->sync(_version, _encryptedFileSize);
    _chunkReader->sync(newParms);
    _fileMeta = fileMeta;
    _version = newParms.version;
    _plainfileSize = newParms.originalSize;
    _encryptedFileSize = newParms.sizeOnServer;
    _fileEncKey = fileEncKey;
}

std::vector<FileHandler::UpdateChanges> FileHandler::createListOfUpdateChangesFromUpdateChunkData(const std::vector<FileHandler::UpdateChunkData>& updatedChunks) {
    if(updatedChunks.size() == 0) {
        return std::vector<FileHandler::UpdateChanges>();
    }
    auto updatedChunk = updatedChunks.begin();
    std::vector<FileHandler::UpdateChanges> result = {FileHandler::UpdateChanges{
        updatedChunk->chunk.data,
        updatedChunk->chunkIndex*_encryptedChunkSize,
        updatedChunk->chunk.hmac,
        updatedChunk->chunkIndex*_hashList->getHashSize()
    }};
    auto& squashedChanges = result.back();
    for(updatedChunk++; updatedChunk != updatedChunks.end(); updatedChunk++) {
        if (squashedChanges.dataPos + squashedChanges.data.size() == updatedChunk->chunkIndex*_encryptedChunkSize && 
            squashedChanges.data.size() + updatedChunk->chunk.data.size() < SERVER_OPERATION_SIZE_LIMIT
        ) {
            squashedChanges.data += updatedChunk->chunk.data;
            squashedChanges.checksum += updatedChunk->chunk.hmac;
        } else {
            result.push_back(FileHandler::UpdateChanges{
                updatedChunk->chunk.data,
                updatedChunk->chunkIndex*_encryptedChunkSize,
                updatedChunk->chunk.hmac,
                updatedChunk->chunkIndex*_hashList->getHashSize()
            });
            squashedChanges = result.back();
        }
    }
    return result;
}

FileHandlerImpl::FileHandlerImpl(std::shared_ptr<FileHandler> file) : _file(file) {}

size_t FileHandlerImpl::size() {
    return _file->getFileSize();
}

void FileHandlerImpl::seekg(const size_t pos) {
    if (pos > _file->getFileSize()) {
        throw PosOutOfBoundsException("seekg out of bounds");
    }
    _readPos = pos;
}

void FileHandlerImpl::seekp(const size_t pos) {
    if (pos > _file->getFileSize()) {
        throw PosOutOfBoundsException("seekg out of bounds");
    }
    _writePos = pos;
}

core::Buffer FileHandlerImpl::read(const size_t length) {
    auto buf = _file->read(_readPos, length);
    _readPos += buf.size();
    return buf;
}

void FileHandlerImpl::write(const core::Buffer& chunk, bool truncate) {
    _file->write(_writePos, chunk, truncate);
    _writePos += chunk.size();
}