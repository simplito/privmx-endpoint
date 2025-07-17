/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_CHUNKREADER_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_CHUNKREADER_HPP_

#include <memory>
#include <string>
#include <optional>

#include <Poco/Types.h>

#include "privmx/endpoint/store/interfaces/IChunkDataProvider.hpp"
#include "privmx/endpoint/store/interfaces/IChunkReader.hpp"

namespace privmx {
namespace endpoint {
namespace store {

class ChunkReader : public IChunkReader
{
public:
    ChunkReader(
        std::shared_ptr<store::IChunkDataProvider> chunkDataProvider,
        size_t chunkSize,
        const std::string& key,
        const std::string& hmac
    );
    virtual void sync(
        int64_t newfileVersion, 
        uint64_t encryptedFileSize, 
        const std::string& hmac, 
        std::optional<size_t> chunkSize = std::nullopt, 
        std::optional<size_t> encryptedChunkSize = std::nullopt, 
        const std::optional<std::string>& key = std::nullopt,
        std::optional<size_t> serverChunkSize = std::nullopt
    ) override;
    virtual std::string getChunk(uint32_t chunkNumber) override;
    virtual size_t getChunkSize() override;
    virtual uint64_t getEncryptedFileSize(uint64_t fileSize) override;
    static size_t getEncryptedChunkSize(size_t chunkSize);
private:
    std::string decryptChunk(std::string encryptedChunk, uint32_t chunkNumber);
    std::string chunkNumberToBE(uint32_t chunkNumber);

    std::shared_ptr<IChunkDataProvider> _chunkDataProvider;
    size_t _chunkSize;
    uint64_t _encryptedFileSize;
    std::string _key;
    std::string _checksums;

    std::string _lastChunkDecrypted;
    std::optional<uint32_t> _lastChunkNumber;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_CHUNKREADER_HPP_
