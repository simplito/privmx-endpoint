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
    // FileMeta decrypt(const FileId& fileId, const EncryptedMeta& encryptedMeta) {}

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
    std::string get(int64_t start, int64_t end, int64_t version) {
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
    std::string get(int64_t index, int64_t version, int64_t fileSize,  int64_t blockSize) { // warning: last chunk can be smaller than other!!
        int64_t start = index * blockSize;
        int64_t end = (index + 1) * blockSize;
        if (start > fileSize) {
            throw EndpointStoreException(); // TODO
        }
        if (end > fileSize) {
            end = fileSize;
        }
        return _sliceProvider->get(start, end, version);
    }

private:
    std::shared_ptr<SliceProvider> _sliceProvider;
    int64_t _blockSize;
};

class ChunkEncryptor : public IChunkEncryptor
{
public:
    ChunkEncryptor(std::string key, int64_t chunkSize) : _key(key), _chunkSize(chunkSize) {}
    Chunk encrypt(const int64_t index, const std::string& data) override {
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
    std::string decrypt(const int64_t index, const Chunk& chunk) override {
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
    int64_t getPlainChunkSize() override {
        return _chunkSize;
    }
    int64_t getEncryptedChunkSize() override {
        Poco::Int64 CHUNK_PADDINGSize = CHUNK_PADDING - (_chunkSize % CHUNK_PADDING);
        return _chunkSize + CHUNK_PADDINGSize + HMAC_SIZE + IV_SIZE;
    }
    int64_t getEncryptedFileSize(const int64_t& fileSize) override {
        int64_t numberOfChunks = (fileSize + getPlainChunkSize() - 1) / getPlainChunkSize();
        return numberOfChunks * getEncryptedChunkSize();
    }
    int64_t getChunkIndex(const int64_t& pos) override {
        return pos / getPlainChunkSize();
    }

private:
    std::string chunkIndexToBE(const int64_t index) {
        uint32_t index_be = Poco::ByteOrder::toBigEndian(index);
        return std::string((char *)&index_be, 4);
    }

    std::string _key;
    int64_t _chunkSize;
};

class File2
{
public:
    File2 (
        std::shared_ptr<BlockProvider> blockProvider,
        std::shared_ptr<IChunkEncryptor> chunkEncryptor,
        std::shared_ptr<IHashList> hashList,
        std::shared_ptr<MetaEncryptor> metaEncryptor,
        int64_t fileSize,
        int64_t version,
        int64_t chunksize,
        FileId fileId,
        FileMeta fileMeta,
        std::shared_ptr<ServerApi> server
    ) : 
        _blockProvider(std::move(blockProvider)),
        _chunkEncryptor(chunkEncryptor),
        _hashList(hashList),
        _fileMetaEncryptor(metaEncryptor),
        _fileSize(fileSize),
        _version(version),
        _chunksize(chunksize),
        _fileId(fileId),
        _fileMeta(fileMeta),
        _server(server)
    {}
    void write(int64_t offset, const core::Buffer& data) { // data = buf + size
        auto toSend = data.stdString();
        if (_fileSize < offset) { 
            // if fileSize smaller than offset fill here empty space with 0
            auto emptyChars = std::string(offset - _fileSize, (char)0x00);
            offset = _fileSize;
            toSend = emptyChars + toSend;
        }
        // start writing to offset chunk
        int64_t index = pos2index(offset);
        int64_t dataSend = 0;
        for(int i = 0; i <  pos2index(offset + toSend.size()); i++) {
            if(i == 0) {
                int64_t chunkOffset =offset % _chunksize;
                std::string chunkData = toSend.substr(dataSend, _chunksize -(offset % _chunksize));
                setChunk(index+i, chunkOffset, chunkData);
            } else {
                int64_t chunkOffset = 0;
                std::string chunkData = toSend.substr(dataSend, _chunksize);
                setChunk(index+i, chunkOffset, chunkData);
            }
        }
    }
    void sync() {
        throw NotImplementedException();
    }
    core::Buffer read(int64_t offset, int64_t size) {
        throw NotImplementedException();
    }
    int64_t getFileSize() {
        return _fileSize;
    }
    void truncate(int64_t length) {
        throw NotImplementedException(); // TODO
    }
    void close() {
        throw NotImplementedException();
    }

private:
    void setChunk(int64_t index, int64_t chunkOffset, const std::string& data) {
        if (chunkOffset + data.size() > _chunksize) {
            // "Given data with offset won't fit Chunk
            throw FileRandomWriteInternalException("Given data with offset won't fit Chunk");
            // throw
        }
        std::string newChunk;
        if (chunkOffset > 0 || data.size() < _chunksize) {
            // TODO: check if exists or return ""
            // get oldChunk (decrypted), _blockProvider->get return encrypted data
            std::string prevChunk = getChunk(index, _version);

            newChunk = prevChunk.substr(0, chunkOffset);
            if (chunkOffset > prevChunk.size()) {
                newChunk += std::string(chunkOffset - prevChunk.size(), (char)0x00);
            }
            newChunk += data;
            if (chunkOffset + data.size() < prevChunk.size() ) {
                newChunk += prevChunk.substr(chunkOffset + data.size());
            }
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
        _fileSize = std::max(_fileSize, int64_t(chunkOffset + data.size()));
        
    }

    std::string getChunk(int64_t index, int64_t version) {
        std::string chunk = _blockProvider->get(index, version, _fileSize, _chunkEncryptor->getEncryptedChunkSize());
        std::string plain = _chunkEncryptor->decrypt(index, {.data = chunk, .hmac = _hashList->getHash(index)});
        return plain;
    }
    int64_t pos2index(int64_t position) {
        throw NotImplementedException();
    }

    std::shared_ptr<BlockProvider> _blockProvider;
    std::shared_ptr<IChunkEncryptor> _chunkEncryptor;
    std::shared_ptr<IHashList> _hashList;
    std::shared_ptr<MetaEncryptor> _fileMetaEncryptor;
    int64_t _fileSize = 0;
    int64_t _version = 0;
    int64_t _chunksize = 0; // TODO
    FileId _fileId;
    FileMeta _fileMeta;
    std::shared_ptr<ServerApi> _server;
};

class FileInterface
{
public:
    virtual int64_t size() = 0;
    virtual void seekg(const int64_t pos) = 0;
    virtual void seekp(const int64_t pos) = 0;
    virtual core::Buffer read(const int64_t length) = 0;
    virtual void write(const core::Buffer& chunk) = 0;
    virtual void truncate(const int64_t length) = 0;
    virtual void close() = 0;
    // virtual void sync() = 0;
    // virtual void flush() = 0;
};


class FileImpl : public FileInterface
{
public:
    FileImpl(std::shared_ptr<File2> file) : _file(file) {}

    int64_t size() override {
        return _file->getFileSize();
    }
    void seekg(const int64_t pos) override {
        if (pos > _file->getFileSize()) {
            throw EndpointStoreException(); // TODO
        }
        _readPos = pos;
    }
    void seekp(const int64_t pos) override {
        if (pos > _file->getFileSize()) {
            throw EndpointStoreException(); // TODO
        }
        _writePos = pos;
    }

    core::Buffer read(const int64_t length) override {
        auto buf = _file->read(_readPos, length);
        _readPos += buf.size();
        return buf;
    }

    void write(const core::Buffer& chunk) override {
        _file->write(_writePos, chunk);
        _writePos += chunk.size();
    }

    void truncate(const int64_t length) override {
        _file->truncate(length);
    }

    void close() override {
        _file->close();
    }

private:
    std::shared_ptr<File2> _file;
    int64_t _readPos = 0;
    int64_t _writePos = 0;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_FILE_HPP_
