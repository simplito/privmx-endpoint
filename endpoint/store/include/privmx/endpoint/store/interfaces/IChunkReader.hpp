#ifndef _PRIVMXLIB_ENDPOINT_STORE_CHUNKREADER_INTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_CHUNKREADER_INTERFACE_HPP_

namespace privmx {
namespace endpoint {
namespace store {

class IChunkReader
{
public:
    virtual ~IChunkReader() = default;
    virtual std::string getChunk(uint32_t chunkNumber) = 0;
    virtual size_t getChunkSize() = 0;
    virtual uint64_t getEncryptedFileSize(uint64_t originalFileSize) = 0;
};


} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_CHUNKREADER_INTERFACE_HPP_