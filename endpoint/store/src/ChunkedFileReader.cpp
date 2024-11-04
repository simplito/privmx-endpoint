/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/ChunkedFileReader.hpp"
#include "privmx/endpoint/store/StoreException.hpp"

using namespace privmx::endpoint::store;

ChunkedFileReader::ChunkedFileReader(
    std::shared_ptr<store::IChunkReader> chunkReader,
    uint64_t originalFileSize,
    uint64_t encryptedFileSize
) 
    : _chunkReader(chunkReader)
{
    if(encryptedFileSize != chunkReader->getEncryptedFileSize(originalFileSize)) {
        throw FileCorruptedException();
    }
    _chunkSize = chunkReader->getChunkSize();
    _totalChunks = (originalFileSize + _chunkSize -1) / _chunkSize;
}

std::string ChunkedFileReader::read(uint64_t pos, size_t length) {
    uint64_t chunkIndex =  pos / _chunkSize;
    uint64_t numberOfChunks = ((pos + length + _chunkSize - 1 ) / _chunkSize) - chunkIndex;
    if(chunkIndex >= _totalChunks || length == 0) {
        return std::string();
    }
    if(numberOfChunks + chunkIndex > _totalChunks) {
        numberOfChunks = _totalChunks - chunkIndex;
    }
    std::string data;
    data.reserve(length);
    size_t insertPos = 0;
    data.insert(insertPos, _chunkReader->getChunk(chunkIndex).substr(pos % _chunkSize, length));
    insertPos += _chunkSize - (pos % _chunkSize);
    for(uint64_t i = 1; i < numberOfChunks-1; i++) {
        data.insert(insertPos, _chunkReader->getChunk(chunkIndex+i));
        insertPos += _chunkSize;
    }
    if (numberOfChunks != 1) {
        size_t lastChunkLength = length - insertPos;
        data.insert(insertPos, _chunkReader->getChunk(chunkIndex+numberOfChunks-1).substr(0, lastChunkLength));
    }
    return data;
}
