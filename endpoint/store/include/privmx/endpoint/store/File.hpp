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

#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/store/interfaces/IChunkEncryptor.hpp"
#include "privmx/endpoint/store/interfaces/IHashList.hpp"

namespace privmx {
namespace endpoint {
namespace store {

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
    BlockProvider(std::shared_ptr<SliceProvider> sliceProvider, int64_t blockSize)
        : _sliceProvider(std::move(sliceProvider)), _blockSize(blockSize) {}
    std::string get(int64_t index, int64_t version, int64_t fileSize) { // warning: last chunk can be smaller than other!!
        int64_t start = index * _blockSize;
        int64_t end = (index + 1) * _blockSize;
        if (start > fileSize) {
            // throw;
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


class File2
{
public:
    static std::shared_ptr<File2> create(std::shared_ptr<ServerApi> server, const std::string& fileId, const int64_t blockSize) {
        std::shared_ptr<ServerSliceProvider> serverSliceProvider = std::make_shared<ServerSliceProvider>(server, fileId);
        std::shared_ptr<SliceProvider> sliceProvider = std::make_shared<SliceProvider>(serverSliceProvider);
        std::shared_ptr<BlockProvider> blockProvider = std::make_shared<BlockProvider>(sliceProvider, blockSize);
        return std::make_shared<File2>(blockProvider);
    }
    File2(std::shared_ptr<BlockProvider> blockProvider) : _blockProvider(std::move(blockProvider)) {}
    void write(int64_t offset, const core::Buffer& data) { // data = buf + size
        if (_filesize < offset) { // if fileSize smaller than offset fill here empty space with 0
            // TODO
        }
        int64_t index = pos2index(offset);
        int64_t end = offset + data.size() - 1;
        if (end >= _filesize) {
            // ...
        }
        int64_t index2 = pos2index(offset + data.size() - 1);
        auto chunk = _blockProvider->get(index, _version, _fileSize);
    }
    void sync(); // void flush();
    void read(int64_t offset, int64_t size) {

    }

private:
    void setChunk(int64_t index, int64_t chunkOffset, const std::string& data, int64_t version) {
        if (chunkOffset + data.size() > chunkSize) {
            // throw
        }
        std::string newData;
        if (chunkOffset > 0 || data.size() < chunkSize) {
            // TODO: check if exists or return ""
            std::string prevChunk = _blockProvider->get(index, version, _filesize);
            newData.append(prevChunk.substr(0, chunkOffset)); // prevChunk can be smaller than offset, then fill 0
        }

        newData.append(data);

        // set newData;
        auto chunk = _chunkEncryptor->encrypt(index, newData);

        _hashList->set(index, chunk.hmac);
        auto topHash = _hashList->getTopHash();

         
    }
    // void addChunk(int64_t index, const std::string& data, int64_t version) {
    //     auto chunk = _chunkEncryptor->encrypt(index, data);

    //     _hashList->set(index, chunk.hmac);
    //     auto topHash = _hashList->getTopHash();
    // }
    std::string getChunk(int64_t index, int64_t version) {
        std::string chunk = _blockProvider->get(index, version, _filesize);
        std::string plain = _chunkEncryptor->decrypt(index, {.data = chunk, .hmac = _hashList->getHash(index)});
        return plain;
    }

    std::shared_ptr<BlockProvider> _blockProvider;
    server::File _file;
    core::DecryptedEncKey _encKey;
    std::shared_ptr<IChunkEncryptor> _chunkEncryptor;
    std::shared_ptr<IHashList> _hashList;
    int64_t _filesize = 0;
    int64_t _version = 0;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_FILE_HPP_
