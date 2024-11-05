/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_CHUNKSTREAMER_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_CHUNKSTREAMER_HPP_

#include <string>

#include <memory>
#include <Poco/Types.h>

#include "privmx/endpoint/store/RequestApi.hpp"
#include "privmx/endpoint/store/ChunkBufferedStream.hpp"

namespace privmx {
namespace endpoint {
namespace store {

struct FileSizeResult
{
    uint64_t size;
    uint64_t checksumSize;
};

struct ChunksSentInfo
    {
        int64_t cipherType;
        std::string key;
        std::string hmac;
        size_t chunkSize;
        std::string requestId;
    };

class ChunkStreamer
{
public:
    

    ChunkStreamer() = default;
    ChunkStreamer(const std::shared_ptr<store::RequestApi>& requestApi, size_t chunkSize, uint64_t fileSize, size_t serverRequestChunkSize);
    void createRequest();
    void setRequestData(const std::string& requestId, const std::string& key, const uint64_t& fileIndex);
    void sendChunk(const std::string& data);
    ChunksSentInfo finalize(const std::string& data);    
    FileSizeResult getFileSize() const;
    uint64_t getUploadedFileSize();
private:
    struct PreparedChunk
    {
        std::string data;
        std::string hmac;
    };
    
    void prepareAndSendChunk(const std::string& data);
    PreparedChunk prepareChunk(const std::string& data);
    void commitFile();
    std::string getSeqBE();
    void sendFullChunksWhileCollected();
    void sendLastChunkIfNonEmpty();
    void sendChunkToServer(std::string&& data);

    std::shared_ptr<RequestApi> _requestApi;
    size_t _chunkSize;
    uint64_t _fileSize;
    ChunkBufferedStream _chunkBufferedStream;
    std::string _key;
    std::string _requestId;
    uint64_t _uploadedFileSize = 0;
    uint32_t _seq = 0;
    uint64_t _dataProcessed = 0;
    std::string _checksums;
    uint64_t _fileIndex = 0;
    uint64_t _serverSeq = 0;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_CHUNKSTREAMER_HPP_
