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

#include "privmx/endpoint/store/interfaces/IHashList.hpp"
#include "privmx/endpoint/store/StoreException.hpp"
#include "privmx/endpoint/store/DynamicTypes.hpp"
#include "privmx/endpoint/core/Connection.hpp"
#include "privmx/endpoint/core/CoreTypes.hpp"
#include "privmx/endpoint/store/StoreTypes.hpp"


#include "privmx/endpoint/store/encryptors/file/FileMetaEncryptor.hpp"
#include "privmx/endpoint/store/interfaces/IFileHandler.hpp"

namespace privmx {
namespace endpoint {
namespace store {

class ServerFileSliceProvider
{
public:
    ServerFileSliceProvider(std::shared_ptr<ServerApi> server, const std::string& fileId) : _server(std::move(server)), _fileId(fileId) {}
    std::string get(int64_t start, int64_t end, int64_t version) {
        // Place implement serwerChunk 
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
    std::shared_ptr<ServerApi> _server;
    std::string _fileId;
};

class FileSliceProvider
{
public:
    FileSliceProvider(std::shared_ptr<ServerFileSliceProvider> serverFileSliceProvider) : _serverFileSliceProvider(serverFileSliceProvider) {}
    std::string get(size_t start, size_t end, int64_t version) {
        // place to implement Cache logic
        return _serverFileSliceProvider->get(start, end, version);
    }
private:
    std::shared_ptr<ServerFileSliceProvider> _serverFileSliceProvider;
};

class FileChunkProvider
{
public:
    FileChunkProvider(std::shared_ptr<FileSliceProvider> sliceProvider)
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
    std::shared_ptr<FileSliceProvider> _sliceProvider;
    size_t _blockSize;
};



} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_FILE_HPP_
