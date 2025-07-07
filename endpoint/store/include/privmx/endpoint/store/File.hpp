/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_FILE_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_FILE_HPP_

#include <algorithm>
#include "Poco/ByteOrder.h"

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>


#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/store/interfaces/IChunkEncryptor.hpp"
#include "privmx/endpoint/store/interfaces/IHashList.hpp"

#include "privmx/endpoint/store/HmacList.hpp"
#include "privmx/endpoint/store/StoreException.hpp"
#include "privmx/endpoint/store/DynamicTypes.hpp"
#include "privmx/endpoint/core/Connection.hpp"
#include "privmx/endpoint/core/CoreTypes.hpp"
#include "privmx/endpoint/store/StoreTypes.hpp"
#include "privmx/endpoint/store/encryptors/file/FileMetaEncryptorV5.hpp"
#include "privmx/endpoint/core/ConnectionImpl.hpp"

namespace privmx {
namespace endpoint {
namespace store {

struct FileId
{
    std::string contextId;
    std::string storeId;
    std::string storeResourceId;
    std::string fileId;
    std::string resourceId;
};

struct FileMeta
{
    core::Buffer publicMeta;
    core::Buffer privateMeta;
    dynamic::InternalStoreFileMeta internalFileMeta;
};

class MetaEncryptor
{
public:

    struct EncryptedMeta
    {
        std::string keyId;
        Poco::Dynamic::Var meta;
    };

    MetaEncryptor(
        const privmx::crypto::PrivateKey& userPrivKey,
        const core::Connection& connection,
        const core::DecryptedEncKey& encKey
    ) : _userPrivKey(userPrivKey),
        _connection(connection),
        _encKey(encKey) {}

    EncryptedMeta encrypt(const FileId& fileId, const FileMeta& fileMeta) {
        store::FileMetaToEncryptV5 metaToEncrypt {
            .publicMeta = fileMeta.publicMeta,
            .privateMeta = fileMeta.privateMeta,
            .internalMeta = core::Buffer::from(utils::Utils::stringifyVar(fileMeta.internalFileMeta.asVar())),
            .dio = createDIO(fileId)
        };
        auto key = getEncKey(fileId);
        return {key.id, FileMetaEncryptorV5().encrypt(metaToEncrypt, _userPrivKey, key.key).asVar()};
    }

    FileMeta decrypt(const FileId& fileId, const EncryptedMeta& encryptedMeta) {
        auto key = getEncKey(fileId);
        auto decryptedFileMeta = FileMetaEncryptorV5().decrypt(encryptedMeta.meta, key.key);
        // TO DO validate decrypted data
        return FileMeta{
            decryptedFileMeta.publicMeta,
            decryptedFileMeta.privateMeta,
            utils::TypedObjectFactory::createObjectFromVar<dynamic::InternalStoreFileMeta>(
                utils::Utils::parseJson(decryptedFileMeta.internalMeta.stdString())
            )
        };
    }

private:
    privmx::endpoint::core::DataIntegrityObject createDIO(const FileId& fileId) {
        privmx::endpoint::core::DataIntegrityObject fileDIO = _connection.getImpl()->createDIO(
            fileId.contextId,
            fileId.resourceId,
            fileId.storeId,
            fileId.storeResourceId
        );
        return fileDIO;
    }

    core::DecryptedEncKey getEncKey(const FileId& fileId) {
        return _encKey;
    }

    privmx::crypto::PrivateKey _userPrivKey;
    core::Connection _connection;
    core::DecryptedEncKey _encKey;
};

class ServerSliceProvider
{
public:
    ServerSliceProvider(std::shared_ptr<ServerApi> server, const std::string& fileId) : _server(std::move(server)), _fileId(fileId) {}
    std::string get(int64_t start, int64_t end, int64_t version) {
        auto range = utils::TypedObjectFactory::createNewObject<server::BufferReadRangeSlice>();
        range.from(start);
        range.to(end);

        auto fileDataModel = utils::TypedObjectFactory::createNewObject<server::StoreFileReadModel>();
        fileDataModel.fileId(_fileId);
        fileDataModel.version(version);
        fileDataModel.range(range);
        fileDataModel.thumb(false);
        auto fileData = _server->storeFileRead(fileDataModel);
        return fileData.data();
    }

private:
    std::shared_ptr<ServerApi> _server;
    std::string _fileId;
};

class SliceProvider
{
public:
    SliceProvider(std::shared_ptr<ServerSliceProvider> serverSliceProvider) : _serverSliceProvider(std::move(serverSliceProvider)) {}
    std::string get(size_t start, size_t end, int64_t version) {
        return _serverSliceProvider->get(start, end, version);
    }

private:
    std::shared_ptr<ServerSliceProvider> _serverSliceProvider;
};

class BlockProvider
{
public:
    BlockProvider(std::shared_ptr<SliceProvider> sliceProvider)
        : _sliceProvider(std::move(sliceProvider)) {}
    std::string get(size_t blockIndex, int64_t version, size_t encryptedFileSize,  size_t encryptedBlockSize) { // warning: last chunk can be smaller than other!!
        size_t start = blockIndex * encryptedBlockSize;
        size_t end = (blockIndex + 1) * encryptedBlockSize;
        if (start > encryptedFileSize) {
            throw FileRandomWriteInternalException("seekg out of bounds");
        }
        if (end > encryptedFileSize) {
            end = encryptedFileSize;
        }
        return _sliceProvider->get(start, end, version);
    }

private:
    std::shared_ptr<SliceProvider> _sliceProvider;
    size_t _blockSize;
};

class ChunkEncryptor : public IChunkEncryptor
{
public:
    ChunkEncryptor(std::string key, size_t chunkSize) : _key(key), _chunkSize(chunkSize) {}
    Chunk encrypt(const size_t index, const std::string& data) override {
        std::string chunkKey = privmx::crypto::Crypto::sha256(_key + chunkIndexToBE(index));
        std::string iv = privmx::crypto::Crypto::randomBytes(IV_SIZE);
        std::string cipher = privmx::crypto::Crypto::aes256CbcPkcs7Encrypt(data, chunkKey, iv);
        std::string ivWithCipher = iv + cipher;
        std::string hmac = privmx::crypto::Crypto::hmacSha256(chunkKey, ivWithCipher);
        return {
            .data = hmac + ivWithCipher,
            .hmac = hmac
        };
    }
    std::string decrypt(const size_t index, const Chunk& chunk) override {
        std::string chunkKey = privmx::crypto::Crypto::sha256(_key + chunkIndexToBE(index));
        std::string hmac = chunk.data.substr(0, HMAC_SIZE);
        if (chunk.hmac != hmac) {
            throw FileChunkInvalidChecksumException();
        }
        std::string hmac2 = crypto::Crypto::hmacSha256(chunkKey, chunk.data.substr(HMAC_SIZE));
        if (hmac != hmac2) {
            throw FileChunkInvalidCipherChecksumException();
        }
        std::string iv = chunk.data.substr(HMAC_SIZE, IV_SIZE);
        std::string plain = crypto::Crypto::aes256CbcPkcs7Decrypt(chunk.data.substr(HMAC_SIZE + IV_SIZE), chunkKey, iv);
        return plain;
    }
    size_t getPlainChunkSize() override {
        return _chunkSize;
    }
    size_t getEncryptedChunkSize() override {
        Poco::Int64 CHUNK_PADDINGSize = CHUNK_PADDING - (_chunkSize % CHUNK_PADDING);
        return _chunkSize + CHUNK_PADDINGSize + HMAC_SIZE + IV_SIZE;
    }
    size_t getEncryptedFileSize(const size_t& fileSize) override {
        size_t numberOfChunks = (fileSize + getPlainChunkSize() - 1) / getPlainChunkSize();
        return numberOfChunks * getEncryptedChunkSize();
    }
    size_t getChunkIndex(const size_t& pos) override {
        return pos / getPlainChunkSize();
    }

private:
    std::string chunkIndexToBE(const size_t index) {
        uint32_t index_be = Poco::ByteOrder::toBigEndian(index);
        return std::string((char *)&index_be, 4);
    }

    std::string _key;
    size_t _chunkSize;
};

class File2
{
public:
    File2 (
        std::shared_ptr<BlockProvider> blockProvider,
        std::shared_ptr<IChunkEncryptor> chunkEncryptor,
        std::shared_ptr<IHashList> hashList,
        std::shared_ptr<MetaEncryptor> metaEncryptor,
        size_t fileSize,
        size_t encryptedFileSize,
        int64_t version,
        size_t chunksize,
        FileId fileId,
        FileMeta fileMeta,
        std::shared_ptr<ServerApi> server
    ) : 
        _blockProvider(std::move(blockProvider)),
        _chunkEncryptor(chunkEncryptor),
        _hashList(hashList),
        _fileMetaEncryptor(metaEncryptor),
        _fileSize(fileSize),
        _encryptedFileSize(encryptedFileSize),
        _version(version),
        _chunksize(chunksize),
        _fileId(fileId),
        _fileMeta(fileMeta),
        _server(server)
    {}
    void write(size_t offset, const core::Buffer& data) { // data = buf + size
        auto toSend = data.stdString();
        if (_fileSize < offset) { 
            // if fileSize smaller than offset fill here empty space with 0
            auto emptyChars = std::string(offset - _fileSize, (char)0x00);
            offset = _fileSize;
            toSend = emptyChars + toSend;
        }
        // start writing to offset chunk
        size_t startIndex = posToindex(offset);
        size_t stopIndex = posToindex(offset+toSend.size());
        size_t dataSend = 0;
        for(size_t i = startIndex; i <= stopIndex; i++) {
            if(i == startIndex) {
                size_t chunkOffset =offset % _chunksize;
                std::string chunkData = toSend.substr(dataSend, _chunksize -(offset % _chunksize));
                setChunk(i, chunkOffset, chunkData);
            } else {
                size_t chunkOffset = 0;
                std::string chunkData = toSend.substr(dataSend, _chunksize);
                setChunk(i, chunkOffset, chunkData);
            }
        }
    }
    void sync() {
        throw NotImplementedException();
    }
    core::Buffer read(size_t offset, size_t size) {
        size_t startIndex = posToindex(offset);
        size_t stopIndex = posToindex(offset+size);
        std::string data = std::string();
        for(size_t i = startIndex; i <= stopIndex; i++) {
            data.append(getDecryptedChunk(i));
        }
        return core::Buffer::from( data.substr(posInindex(offset), size) );
    }
    size_t getFileSize() {
        return _fileSize;
    }
    void truncate(size_t length) {
        throw NotImplementedException(); // TODO
    }
    void close() {
        throw NotImplementedException();
    }

private:
    void setChunk(size_t index, size_t chunkOffset, const std::string& data) {
        // check if new data fit in _chunksize
        if ((chunkOffset + data.size()) > _chunksize) {
            // "Given data with offset won't fit Chunk
            throw FileRandomWriteInternalException("Given data with offset won't fit Chunk");
            // throw
        }
        std::string newChunk = std::string();
        // read old chunk
        std::string prevEncryptedChunk = _blockProvider->get(index, _version, _encryptedFileSize, _chunkEncryptor->getEncryptedChunkSize());
        std::string prevChunk = _chunkEncryptor->decrypt(index, {.data = prevEncryptedChunk, .hmac = _hashList->getHash(index)});
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

        // update meta
        _fileMeta.internalFileMeta.hmac(topHash);
        // _fileMeta.internalFileMeta.size(newSize);

        auto newMeta = _fileMetaEncryptor->encrypt(_fileId, _fileMeta);

        // update file by operation
        auto operation1 = utils::TypedObjectFactory::createNewObject<server::StoreFileRandomWriteOperation>();
        operation1.type("file");
        operation1.pos(_chunksize * index);
        operation1.data(chunk.data);
        operation1.truncate(false);

        auto operation2 = utils::TypedObjectFactory::createNewObject<server::StoreFileRandomWriteOperation>();
        operation2.type("checksum");
        operation2.pos(_hashList->getHashSize() * index);
        operation2.data(chunk.hmac);
        operation2.truncate(false);

        auto operations = utils::TypedObjectFactory::createNewList<server::StoreFileRandomWriteOperation>();
        operations.add(operation1);
        operations.add(operation2);

        auto writeRequest = utils::TypedObjectFactory::createNewObject<server::StoreFileWriteModelByOperations>();
        writeRequest.fileId(_fileId.fileId);
        writeRequest.operations(operations);
        writeRequest.meta(newMeta.meta);
        writeRequest.keyId(newMeta.keyId);
        writeRequest.version(_version);
        writeRequest.force(false);

        _server->storeFileWrite(writeRequest);

        _version += 1;
        // update _fileSize;
        if(prevChunk.size() < chunkOffset + data.size()) {
            // new data added
            _fileSize += (chunkOffset + data.size()) - prevChunk.size();
            _encryptedFileSize += chunk.data.size() - prevEncryptedChunk.size();
        }
        
    }

    std::string getDecryptedChunk(size_t index) {
        std::string chunk = _blockProvider->get(index, _version, _encryptedFileSize, _chunkEncryptor->getEncryptedChunkSize());
        std::string plain = _chunkEncryptor->decrypt(index, {.data = chunk, .hmac = _hashList->getHash(index)});
        return plain;
    }
    size_t posToindex(size_t position) {
        return position / _chunkEncryptor->getPlainChunkSize();
    }

    size_t posInindex(size_t position) {
        return position % _chunkEncryptor->getPlainChunkSize();
    }

    std::shared_ptr<BlockProvider> _blockProvider;
    std::shared_ptr<IChunkEncryptor> _chunkEncryptor;
    std::shared_ptr<IHashList> _hashList;
    std::shared_ptr<MetaEncryptor> _fileMetaEncryptor;
    size_t _fileSize = 0;
    size_t _encryptedFileSize = 0;
    int64_t _version = 0;
    size_t _chunksize = 0; // TODO
    FileId _fileId;
    FileMeta _fileMeta;
    std::shared_ptr<ServerApi> _server;
};

class FileInterface
{
public:
    virtual size_t size() = 0;
    virtual void seekg(const size_t pos) = 0;
    virtual void seekp(const size_t pos) = 0;
    virtual core::Buffer read(const size_t length) = 0;
    virtual void write(const core::Buffer& chunk) = 0;
    virtual void truncate(const size_t length) = 0;
    virtual void close() = 0;
    virtual void sync() = 0;
    virtual void flush() = 0;
};


class FileImpl : public FileInterface
{
public:
    FileImpl(std::shared_ptr<File2> file) : _file(file) {}

    size_t size() override {
        return _file->getFileSize();
    }
    void seekg(const size_t pos) override {
        if (pos > _file->getFileSize()) {
            throw FileRandomWriteInternalException("seekg out of bounds");
        }
        _readPos = pos;
    }
    void seekp(const size_t pos) override {
        if (pos > _file->getFileSize()) {
            throw FileRandomWriteInternalException("seekg out of bounds");
        }
        _writePos = pos;
    }

    core::Buffer read(const size_t length) override {
        auto buf = _file->read(_readPos, length);
        _readPos += buf.size();
        return buf;
    }

    void write(const core::Buffer& chunk) override {
        _file->write(_writePos, chunk);
        _writePos += chunk.size();
    }

    void truncate(const size_t length) override {
        _file->truncate(length);
    }

    void close() override {
        _file->close();
    }

    void sync() override {
        throw NotImplementedException();
    }

    void flush() override {
        throw NotImplementedException();
    }

private:
    std::shared_ptr<File2> _file;
    size_t _readPos = 0;
    size_t _writePos = 0;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_FILE_HPP_
