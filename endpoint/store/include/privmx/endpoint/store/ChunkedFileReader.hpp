/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_CHUNKEDFILEREADER_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_CHUNKEDFILEREADER_HPP_

#include <memory>
#include <string>

#include <Poco/Types.h>
#include "privmx/endpoint/store/interfaces/IFileReader.hpp"
#include "privmx/endpoint/store/interfaces/IChunkReader.hpp"

namespace privmx {
namespace endpoint {
namespace store {

class ChunkedFileReader : public IFileReader
{
public:
    ChunkedFileReader(
        std::shared_ptr<IChunkReader> chunkReader,
        uint64_t originalFileSize,
        uint64_t encryptedFileSize
    );
    virtual void sync(
        int64_t newfileVersion, 
        uint64_t originalFileSize,
        uint64_t encryptedFileSize, 
        const std::string& hmac,
        std::optional<size_t> chunkSize, 
        std::optional<size_t> encryptedChunkSize = std::nullopt, 
        const std::optional<std::string>& key = std::nullopt,
        std::optional<size_t> serverChunkSize = std::nullopt
    ) override;
    virtual std::string read(uint64_t pos, size_t length) override;
    
private:
    std::shared_ptr<IChunkReader> _chunkReader;
    uint64_t _chunkSize;
    uint64_t _totalChunks;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_CHUNKEDFILEREADER_HPP_
