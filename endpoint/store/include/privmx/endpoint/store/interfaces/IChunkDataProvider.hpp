/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_CHUNK_DATA_PROVIDER_INTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_CHUNK_DATA_PROVIDER_INTERFACE_HPP_

namespace privmx {
namespace endpoint {
namespace store {

class IChunkDataProvider
{
public:
    virtual ~IChunkDataProvider() = default;
    virtual std::string getChunk(uint32_t chunkNumber) = 0;
    virtual std::string getChunk(uint32_t chunkNumber, int64_t fileVersion) = 0;
    virtual void update(int64_t newfileVersion, uint32_t chunkNumber, const std::string newChunkEncryptedData, int64_t encryptedFileSize, bool truncate) = 0;
    virtual std::string getChecksums() = 0;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_CHUNK_DATA_PROVIDER_INTERFACE_HPP_