/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_FILEHANDLE_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_FILEHANDLE_HPP_

#include <string>

#include <privmx/utils/ThreadSaveMap.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/endpoint/core/HandleManager.hpp>
#include <privmx/endpoint/core/Buffer.hpp>
#include <privmx/endpoint/core/Connection.hpp>

#include "privmx/endpoint/store/ChunkBufferedStream.hpp"
#include "privmx/endpoint/store/ChunkStreamer.hpp"
#include "privmx/endpoint/store/interfaces/IFileReader.hpp"
#include "privmx/endpoint/store/interfaces/IFileHandler.hpp"
#include "privmx/endpoint/store/interfaces/IChunkEncryptor.hpp"
#include "privmx/endpoint/store/interfaces/IHashList.hpp"
#include "privmx/endpoint/store/interfaces/IChunkDataProvider.hpp"
#include "privmx/endpoint/store/interfaces/IChunkReader.hpp"
#include "privmx/endpoint/store/ServerApi.hpp"


namespace privmx {
namespace endpoint {
namespace store {

class FileHandle
{
public:
    FileHandle(int64_t id, const std::string& storeId, const std::string& fileId, const std::string& resourceId, uint64_t fileSize, bool randomWriteSupport);
    virtual ~FileHandle() = default;
    virtual bool isReadHandle() const { return false; }
    virtual bool isWriteHandle() const { return false; }
    virtual bool isFileReadWriteHandle() const { return false; }
    int64_t getId();
    std::string getStoreId();
    std::string getFileId();
    std::string getResourceId();
    uint64_t getSize();
    bool getRandomWriteSupport();
protected:
    const int64_t _id;
    std::string _storeId;
    std::string _fileId;
    std::string _resourceId;
    uint64_t _size;
    bool _randomWriteSupport;
};

class FileReadHandle : public FileHandle
{
public:
    FileReadHandle(
        int64_t id, 
        const store::FileDecryptionParams& decryptionParams,
        size_t serverChunkSize,
        std::shared_ptr<ServerApi> server
    );
    void sync(
        const store::FileDecryptionParams& newDecryptionParams
    );
    bool isReadHandle() const override { return true; }
    std::string read(uint64_t length);
    void seek(uint64_t pos);
private:
    std::shared_ptr<IChunkEncryptor> _chunkEncryptor;
    std::shared_ptr<IChunkDataProvider> _chunkDataProvider;
    std::shared_ptr<IHashList> _hashList;
    std::shared_ptr<IChunkReader> _chunkReader;
    std::shared_ptr<store::IFileReader> _fileReader;
    uint64_t _pos = 0;
};

class FileWriteHandle : public FileHandle
{
public:
    FileWriteHandle(
        int64_t id,
        const std::string& storeId,
        const std::string& fileId,
        const std::string& resourceId,
        uint64_t size,
        const core::Buffer& publicMeta,
        const core::Buffer& privateMeta,
        uint64_t chunkSize,
        uint64_t serverRequestChunkSize,
        std::shared_ptr<privmx::endpoint::store::RequestApi> requestApi,
        bool randomWriteSupport
    );
    void write(const std::string& data);
    privmx::endpoint::store::ChunksSentInfo finalize();
    bool isReadyToFinalize();
    core::Buffer getPublicMeta();
    core::Buffer getPrivateMeta();
    privmx::endpoint::store::FileSizeResult getEncryptedFileSize();
    void createRequestData();
    void setRequestData(const std::string& requestId, const std::string& key, const Poco::Int64& fileIndex);
    bool isWriteHandle() const override { return true; }
private:
    core::Buffer _publicMeta;
    core::Buffer _privateMeta;
    ChunkBufferedStream _stream;
    ChunkStreamer _streamer;
};


class FileReadWriteHandle : public FileHandle
{
public:
    FileReadWriteHandle(
        int64_t id,
        const store::FileInfo &fileInfo,
        const store::FileEncryptionParams& encryptionParams,
        size_t serverChunkSize,
        const privmx::crypto::PrivateKey &userPrivKey,
        const privmx::endpoint::core::Connection &connection,
        std::shared_ptr<privmx::endpoint::store::ServerApi> serverApi
    );
    bool isFileReadWriteHandle() const override { return true; }
    std::shared_ptr<IFileHandler> file;
};


class FileHandleManager
{
public:
    FileHandleManager(std::shared_ptr<core::HandleManager> handleManager, const std::string& labelPrefix = "");
    std::shared_ptr<FileReadHandle> createFileReadHandle(
        const store::FileDecryptionParams& decryptionParams,
        size_t serverChunkSize,
        std::shared_ptr<ServerApi> server
    );
    std::shared_ptr<FileWriteHandle> createFileWriteHandle(
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
    );
    std::shared_ptr<FileReadWriteHandle> createFileReadWriteHandle(
        const store::FileInfo &fileInfo,
        const store::FileEncryptionParams& encryptionParams,
        size_t serverChunkSize,
        const privmx::crypto::PrivateKey &userPrivKey,
        const privmx::endpoint::core::Connection &connection,
        std::shared_ptr<privmx::endpoint::store::ServerApi> serverApi
    );
    std::shared_ptr<FileReadHandle> getFileReadHandle(int64_t id);
    std::shared_ptr<FileWriteHandle> getFileWriteHandle(int64_t id);
    std::shared_ptr<FileReadWriteHandle> tryGetFileReadWriteHandle(int64_t id);
    std::shared_ptr<FileHandle> getFileHandle(int64_t id);
    void removeHandle(int64_t id);

private:
    std::shared_ptr<core::HandleManager> _handleManager;
    std::string _labelPrefix;
    utils::ThreadSaveMap<int64_t, std::shared_ptr<FileHandle>> _map;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_FILEHANDLE_HPP_
