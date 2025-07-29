/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_FILE_HANDLER_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_FILE_HANDLER_HPP_

#include <cstdint>
#include <string>
#include <privmx/endpoint/core/Buffer.hpp>
#include <privmx/endpoint/core/CoreTypes.hpp>
#include "privmx/endpoint/store/StoreException.hpp"
#include "privmx/endpoint/store/DynamicTypes.hpp"
#include "privmx/endpoint/store/StoreTypes.hpp"
#include "privmx/endpoint/store/ServerApi.hpp"

#include "privmx/endpoint/store/interfaces/IChunkEncryptor.hpp"
#include "privmx/endpoint/store/interfaces/IHashList.hpp"
#include "privmx/endpoint/store/encryptors/file/FileMetaEncryptor.hpp"
#include "privmx/endpoint/store/interfaces/IFileHandler.hpp"
#include "privmx/endpoint/store/interfaces/IChunkDataProvider.hpp"


namespace privmx {
namespace endpoint {
namespace store {

class FileHandler
{
public:
    FileHandler (
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
    );

    void write(size_t offset, const core::Buffer& data, bool truncate = false);
    core::Buffer read(size_t offset, size_t size);
    size_t getFileSize();
    void sync(const FileMeta& fileMeta, const store::FileDecryptionParams& newParms, const core::DecryptedEncKey& fileEncKey);
    void close();
    void flush();

private:
    struct UpdateChunkData {
        store::IChunkEncryptor::Chunk chunk;
        size_t chunkIndex;
        int64_t plainfileSizeChange;
        int64_t encryptedFileSizeChange;
    };
    struct UpdateChanges {
        std::string data;
        size_t dataPos;
        std::string checksum;
        size_t checksumPos;
    };

    UpdateChunkData createUpdateChunk(size_t index, size_t chunkOffset, const std::string& data, bool truncate = false);
    void updateOnServer(const std::vector<UpdateChanges>& updatedChunks, Poco::Dynamic::Var updatedMeta, const std::string& encKeyId, bool truncate);
    std::string getDecryptedChunk(size_t index);
    std::vector<UpdateChanges> createListOfUpdateChangesFromUpdateChunkData(const std::vector<UpdateChunkData>& updatedChunks);
    size_t posToindex(size_t position);
    size_t posInindex(size_t position);

    std::shared_ptr<IChunkDataProvider> _chunkDataProvider;
    std::shared_ptr<IChunkEncryptor> _chunkEncryptor;
    std::shared_ptr<IHashList> _hashList;
    std::shared_ptr<store::FileMetaEncryptor> _fileMetaEncryptor;
    size_t _plainfileSize = 0;
    size_t _encryptedFileSize = 0;
    int64_t _version = 0;
    FileInfo _fileInfo;
    FileMeta _fileMeta;
    core::DecryptedEncKey _fileEncKey;
    std::shared_ptr<ServerApi> _server;
    size_t _plainChunkSize;
    size_t _encryptedChunkSize;
    static constexpr size_t SERVER_OPERATIONS_LIMIT = 4;
    static constexpr size_t SERVER_OPERATION_SIZE_LIMIT = 512*1024; // 512KiB
};

class FileHandlerImpl : public IFileHandler
{
public:
    FileHandlerImpl(std::shared_ptr<FileHandler> file);

    size_t size() override;
    void seekg(const size_t pos) override;
    void seekp(const size_t pos) override;
    core::Buffer read(const size_t length) override;
    void write(const core::Buffer& chunk, bool truncate = false) override;

    inline void close() override {}
    inline void sync(const FileMeta& fileMeta, const store::FileDecryptionParams& newParms, const core::DecryptedEncKey& fileEncKey) override {
        return _file->sync(fileMeta, newParms, fileEncKey);
    }
    inline void flush() override {throw NotImplementedException();}

private:
    std::shared_ptr<FileHandler> _file;
    size_t _readPos = 0;
    size_t _writePos = 0;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_FILE_HANDLER_HPP_
