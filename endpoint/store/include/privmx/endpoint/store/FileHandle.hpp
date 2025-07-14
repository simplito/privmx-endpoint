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
#include <privmx/endpoint/core/HandleManager.hpp>

#include "privmx/endpoint/store/ChunkBufferedStream.hpp"
#include "privmx/endpoint/store/ChunkStreamer.hpp"
#include "privmx/endpoint/store/interfaces/IFileReader.hpp"
#include "privmx/endpoint/store/interfaces/IFileHandler.hpp"
#include "privmx/endpoint/core/Buffer.hpp"
#include "privmx/endpoint/store/ServerApi.hpp"

namespace privmx {
namespace endpoint {
namespace store {

class FileHandle
{
public:
    FileHandle(int64_t id, const std::string& storeId, const std::string& fileId, const std::string& resourceId, uint64_t fileSize);
    virtual ~FileHandle() = default;
    virtual bool isReadHandle() const { return false; }
    virtual bool isWriteHandle() const { return false; }
    virtual bool isRandomWriteHandle() const { return false; }
    int64_t getId();
    std::string getStoreId();
    std::string getFileId();
    std::string getResourceId();
    uint64_t getSize();
protected:
    const int64_t _id;
    std::string _storeId;
    std::string _fileId;
    std::string _resourceId;
    uint64_t _size;
};

class FileReadHandle : public FileHandle
{
public:
    FileReadHandle(
        int64_t id, 
        const std::string& fileId,
        const std::string& resourceId, 
        uint64_t fileSize,
        uint64_t serverFileSize,
        size_t chunkSize,
        size_t serverChunkSize,
        int64_t fileVersion,
        const std::string& fileKey,
        const std::string& fileHmac,
        std::shared_ptr<ServerApi> server
    );
    bool isReadHandle() const override { return true; }
    std::string read(uint64_t length);
    void seek(uint64_t pos);
private:
    std::shared_ptr<store::IFileReader> _reader;
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
        std::shared_ptr<privmx::endpoint::store::RequestApi> requestApi
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


class FileRandomWriteHandle : public FileHandle
{
public:
    FileRandomWriteHandle(
        int64_t id,
        const std::string &fileId,
        std::shared_ptr<IFileHandler> file
    ) : FileHandle(id, "", fileId, "", 0), file(file) {}
    bool isRandomWriteHandle() const override { return true; }

    std::shared_ptr<IFileHandler> file;
};


class FileHandleManager
{
public:
    FileHandleManager(std::shared_ptr<core::HandleManager> handleManager, const std::string& labelPrefix = "");
    std::shared_ptr<FileReadHandle> createFileReadHandle(
        const std::string& fileId,
        const std::string& resourceId, 
        uint64_t fileSize,
        uint64_t serverFileSize,
        size_t chunkSize,
        size_t serverChunkSize,
        int64_t fileVersion,
        const std::string& fileKey,
        const std::string& fileHmac,
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
        std::shared_ptr<RequestApi> requestApi
    );
    std::shared_ptr<FileRandomWriteHandle> createFileRandomWriteHandle(
        const std::string &fileId,
        std::shared_ptr<IFileHandler> file
    );
    std::shared_ptr<FileReadHandle> getFileReadHandle(int64_t id);
    std::shared_ptr<FileWriteHandle> getFileWriteHandle(int64_t id);
    std::shared_ptr<FileRandomWriteHandle> tryGetFileRandomWriteHandle(int64_t id);
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
