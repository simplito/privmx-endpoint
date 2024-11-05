/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_CHUNK_DATA_PROVIDER_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_CHUNK_DATA_PROVIDER_HPP_

#include <memory>
#include <string>
#include <optional>

#include <Poco/Types.h>
#include "privmx/endpoint/store/interfaces/IChunkDataProvider.hpp"
#include "privmx/endpoint/store/ServerApi.hpp"
#include "privmx/endpoint/store/ServerTypes.hpp"

namespace privmx {
namespace endpoint {
namespace store {

class ChunkDataProvider : public IChunkDataProvider
{
public:
    ChunkDataProvider() = default;
    ChunkDataProvider(
        std::shared_ptr<ServerApi> server,
        size_t encryptedChunkSize,
        size_t severChunkSize,
        const std::string& fileId,
        uint64_t serverFileSize,
        int64_t fileVersion
    );
    virtual std::string getChunk(uint32_t chunkNumber) override;
    virtual std::string getChecksums() override;
private:
    static int64_t getServerReadDataSize(int64_t encryptedChunkSize, int64_t severChunkSize);
    std::string requestServerChunk(uint32_t serverChunkNumber);

    std::shared_ptr<ServerApi> _server;
    size_t _encryptedChunkSize;
    size_t _serverChunkSize;
    std::string _fileId;
    uint64_t _serverFileSize;
    int64_t _fileVersion;

    std::string _lastServerChunk;
    std::optional<uint32_t> _lastServerChunkNumber = -1;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_CHUNK_DATA_PROVIDER_HPP_