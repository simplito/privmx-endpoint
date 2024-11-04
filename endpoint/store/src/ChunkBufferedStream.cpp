/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/ChunkBufferedStream.hpp"
#include <privmx/endpoint/core/CoreException.hpp>
#include <vector>

using namespace privmx::endpoint::store;

ChunkBufferedStream::ChunkBufferedStream(size_t chunkSize, std::optional<uint64_t> maxStreamLength) : 
    _chunkSize(chunkSize), _sizeControl(maxStreamLength.has_value()),
    _maxTotalDataSize(maxStreamLength.has_value() ? maxStreamLength.value() : 0), _totalDataSize(0) {}

std::string ChunkBufferedStream::readChunk() {
    size_t chunkSize = std::min(_bufSize, _chunkSize);
    std::string res = _buf.substr(0, _chunkSize);
    _buf = _buf.substr(chunkSize);
    _bufSize -= chunkSize;
    return res;
}

void ChunkBufferedStream::write(const std::string& data) {
    if(_sizeControl && _totalDataSize+data.length() > _maxTotalDataSize) {
        throw core::DataBiggerThanDeclaredException();
    }
    _buf.append(data);
    _bufSize += data.size();
    _totalDataSize+=data.length();
}

std::string ChunkBufferedStream::getFullChunk(uint64_t pos) {
    return _buf.substr(_chunkSize*pos, _chunkSize);
}
void ChunkBufferedStream::freeFullChunks() {
    _buf = _buf.substr(_chunkSize*getNumberOfFullChunks());
    _bufSize = _bufSize - (_chunkSize*getNumberOfFullChunks());
}