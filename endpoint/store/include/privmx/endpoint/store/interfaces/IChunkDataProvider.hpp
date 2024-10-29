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
    virtual std::string getChecksums() = 0;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_CHUNK_DATA_PROVIDER_INTERFACE_HPP_