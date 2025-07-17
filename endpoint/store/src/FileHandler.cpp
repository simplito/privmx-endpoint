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

void FileHandler::write(size_t offset, const core::Buffer& data) { // data = buf + size
    auto toSend = data.stdString();
    if (_plainfileSize < offset) { 
        // if fileSize smaller than offset fill here empty space with 0
        auto emptyChars = std::string(offset - _plainfileSize, (char)0x00);
        offset = _plainfileSize;
        toSend = emptyChars + toSend;
    }
    // start writing to offset chunk
    size_t startIndex = posToindex(offset);
    size_t stopIndex = posToindex(offset+toSend.size()-1);
    size_t dataSend = 0;
    for(size_t i = startIndex; i <= stopIndex; i++) {
        if(i == startIndex) {
            size_t chunkOffset = offset % _chunkEncryptor->getPlainChunkSize();
            std::string chunkData = toSend.substr(dataSend, _plainChunkSize -(offset % _plainChunkSize));
            setChunk(i, chunkOffset, chunkData);
            dataSend += chunkData.size();
        } else {
            size_t chunkOffset = 0;
            std::string chunkData = toSend.substr(dataSend, _plainChunkSize);
            setChunk(i, chunkOffset, chunkData);
            dataSend += chunkData.size();
        }
    }
    PRIVMX_DEBUG("FileHandler", "write", "_plainfileSize: " + std::to_string(_plainfileSize)+ " | _encryptedFileSize: " + std::to_string(_encryptedFileSize)); 
}

core::Buffer FileHandler::read(size_t offset, size_t size) {
    if(size > _plainfileSize) size = _plainfileSize;
    if(size == 0) return core::Buffer();
    size_t startIndex = posToindex(offset);
    size_t stopIndex = posToindex(offset+size-1);
    std::string data = std::string();
    for(size_t i = startIndex; i <= stopIndex; i++) {
        data.append(getDecryptedChunk(i));
    }
    return core::Buffer::from( data.substr(posInindex(offset), size) );
}

void FileHandler::truncate(size_t pos) {
    // update 
    size_t index = posToindex(pos);
    size_t chunkOffset = pos % _plainChunkSize;
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
    // set newChunk;
    auto chunk = _chunkEncryptor->encrypt(index, newChunk);
    _hashList->set(index, chunk.hmac, true);
    auto topHash = _hashList->getTopHash();
    // newSize
    auto newPlainfileSize = pos;
    auto newEncryptedFileSize = index *_encryptedChunkSize + chunk.data.size();
    // update meta
    _fileMeta.internalFileMeta.hmac(utils::Base64::from(topHash));
    _fileMeta.internalFileMeta.size(newPlainfileSize);
    
    auto newMeta = _fileMetaEncryptor->encrypt(_fileInfo, _fileMeta, _fileEncKey, _fileEncKey.dataStructureVersion);

    // update file by operation
    updateOnServer(chunk, index, newMeta, _fileEncKey.id, true);
    // update Info
    _version += 1;
    _plainfileSize = newPlainfileSize;
    _encryptedFileSize = newEncryptedFileSize;
    _chunkDataProvider->update(_version, index, chunk.data, _encryptedFileSize, true);
    PRIVMX_DEBUG("FileHandler", "truncate", "_plainfileSize: " + std::to_string(_plainfileSize)+ " | _encryptedFileSize: " + std::to_string(_encryptedFileSize)); 
}

size_t FileHandler::getFileSize() {
    return _plainfileSize;
}

void FileHandler::setChunk(size_t index, size_t chunkOffset, const std::string& data) {
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
    if(prevChunk.size() > chunkOffset + data.size()) {
        newChunk.append(prevChunk.substr(chunkOffset + data.size()));
    }
    // set newChunk;
    auto chunk = _chunkEncryptor->encrypt(index, newChunk);
    _hashList->set(index, chunk.hmac);
    auto topHash = _hashList->getTopHash();
    // newSize
    auto newPlainfileSize = _plainfileSize;
    auto newEncryptedFileSize = _encryptedFileSize;
    if(prevChunk.size() < chunkOffset + data.size()) {
        newPlainfileSize += newChunk.size() - prevChunk.size();
        newEncryptedFileSize += chunk.data.size() - prevEncryptedChunk.size();
    }
    // update meta
    _fileMeta.internalFileMeta.hmac(utils::Base64::from(topHash));
    _fileMeta.internalFileMeta.size(newPlainfileSize);
    
    auto newMeta = _fileMetaEncryptor->encrypt(_fileInfo, _fileMeta, _fileEncKey, _fileEncKey.dataStructureVersion);

    // update file by operation
    updateOnServer(chunk, index, newMeta, _fileEncKey.id, false);
    // update Info
    _version += 1;
    _plainfileSize = newPlainfileSize;
    _encryptedFileSize = newEncryptedFileSize;
    _chunkDataProvider->update(_version, index, chunk.data, _encryptedFileSize, false);
}

void FileHandler::updateOnServer(const store::IChunkEncryptor::Chunk& updatedChunk, size_t chunkIndex, Poco::Dynamic::Var updatedMeta, const std::string& encKeyId, bool truncate) {
    // update file by operation
    auto operation1 = utils::TypedObjectFactory::createNewObject<server::StoreFileRandomWriteOperation>();
    operation1.type("file");
    operation1.pos(_encryptedChunkSize * chunkIndex);
    operation1.data(updatedChunk.data);
    operation1.truncate(truncate);

    auto operation2 = utils::TypedObjectFactory::createNewObject<server::StoreFileRandomWriteOperation>();
    operation2.type("checksum");
    operation2.pos(_hashList->getHashSize() * chunkIndex);
    operation2.data(updatedChunk.hmac);
    operation2.truncate(truncate);

    auto operations = utils::TypedObjectFactory::createNewList<server::StoreFileRandomWriteOperation>();
    operations.add(operation1);
    operations.add(operation2);

    auto writeRequest = utils::TypedObjectFactory::createNewObject<server::StoreFileWriteModelByOperations>();
    writeRequest.fileId(_fileInfo.fileId);
    writeRequest.operations(operations);
    writeRequest.meta(updatedMeta);
    writeRequest.keyId(encKeyId);
    writeRequest.version(_version);
    writeRequest.force(false);
    _server->storeFileWrite(writeRequest);
}

std::string FileHandler::getDecryptedChunk(size_t index) {
    std::string chunk = _chunkDataProvider->getChunk(index, _version);
    std::string plain = _chunkEncryptor->decrypt(index, {.data = chunk, .hmac = _hashList->getHash(index)});
    return plain;
}
size_t FileHandler::posToindex(size_t position) {
    return position / _chunkEncryptor->getPlainChunkSize();
}

size_t FileHandler::posInindex(size_t position) {
    return position % _chunkEncryptor->getPlainChunkSize();
}

void FileHandler::sync(const FileMeta& fileMeta, const store::FileDecryptionParams& newParms, const core::DecryptedEncKey& fileEncKey) {
    _hashList->sync(newParms.key, newParms.hmac, _chunkDataProvider->getChecksums());
    _fileMeta = fileMeta;
    _version = newParms.version;
    _plainfileSize = newParms.originalSize;
    _encryptedFileSize = newParms.sizeOnServer;
    _fileEncKey = fileEncKey;
    _chunkDataProvider->sync(_version, _encryptedFileSize);
}

FileHandlerImpl::FileHandlerImpl(std::shared_ptr<FileHandler> file) : _file(file) {}

size_t FileHandlerImpl::size() {
    return _file->getFileSize();
}

void FileHandlerImpl::seekg(const size_t pos) {
    if (pos > _file->getFileSize()) {
        throw FileRandomWriteInternalException("seekg out of bounds");
    }
    _readPos = pos;
}

void FileHandlerImpl::seekp(const size_t pos) {
    if (pos > _file->getFileSize()) {
        throw FileRandomWriteInternalException("seekg out of bounds");
    }
    _writePos = pos;
}

core::Buffer FileHandlerImpl::read(const size_t length) {
    auto buf = _file->read(_readPos, length);
    _readPos += buf.size();
    return buf;
}

void FileHandlerImpl::write(const core::Buffer& chunk) {
    _file->write(_writePos, chunk);
    _writePos += chunk.size();
}

void FileHandlerImpl::truncate() {
    _file->truncate(_writePos);
}