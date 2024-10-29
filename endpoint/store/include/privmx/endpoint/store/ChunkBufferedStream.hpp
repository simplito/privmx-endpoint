#ifndef _PRIVMXLIB_ENDPOINT_STORE_CHUNKBUFFEREDSTREAM_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_CHUNKBUFFEREDSTREAM_HPP_

#include <string>
#include <optional>
#include <privmx/utils/Debug.hpp>

namespace privmx {
namespace endpoint {
namespace store {

class ChunkBufferedStream
{
public:
    ChunkBufferedStream() = default;
    ChunkBufferedStream(size_t chunkSize, std::optional<uint64_t> maxStreamLength = std::nullopt);
    bool isEmpty() const;
    bool hasFullChunk() const;
    bool isFullyFilled();
    std::string readChunk();
    uint64_t getNumberOfFullChunks() const;
    std::string getFullChunk(uint64_t pos);
    void freeFullChunks();
    void write(const std::string& data);
private:
    size_t _chunkSize;
    std::string _buf;
    bool _sizeControl;
    uint64_t _maxTotalDataSize;
    uint64_t _totalDataSize = 0;
    size_t _bufSize = 0;
};

inline bool ChunkBufferedStream::isEmpty() const {
    return _bufSize == 0;
}

inline bool ChunkBufferedStream::hasFullChunk() const {
    return _bufSize > _chunkSize;
}

inline uint64_t ChunkBufferedStream::getNumberOfFullChunks() const {
    return _bufSize / _chunkSize;
}

inline bool ChunkBufferedStream::isFullyFilled() {
    PRIVMX_DEBUG("DEBUG", "ChunkBufferedStream::isFullyFilled", std::to_string(_totalDataSize) + " == " + std::to_string(_maxTotalDataSize));
    return _sizeControl ? _totalDataSize == _maxTotalDataSize : false;
}

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_CHUNKBUFFEREDSTREAM_HPP_
