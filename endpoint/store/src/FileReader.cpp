/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/FileReader.hpp"
#include "privmx/endpoint/store/StoreException.hpp"

using namespace privmx::endpoint::store;

FileReader::FileReader(
    std::shared_ptr<IChunkReader> chunkReader,
    const store::FileDecryptionParams& decryptionParams
) 
    : _chunkReader(chunkReader),
    _plainfileSize(decryptionParams.originalSize),
    _version(decryptionParams.version)
{}

void FileReader::sync(const store::FileDecryptionParams& newParms) {
    _plainfileSize = newParms.originalSize;
    _version = newParms.version;
}

std::string FileReader::read(uint64_t pos, size_t length) {
    if(pos >= _plainfileSize) return std::string();
    if(pos+length > _plainfileSize) length = _plainfileSize-pos;
    if(length == 0) return std::string();
    auto startIndex = _chunkReader->filePosToFileChunkIndex(pos);
    auto stopIndex = _chunkReader->filePosToFileChunkIndex(pos+length-1);
    std::string data = std::string();
    for(auto i = startIndex; i <= stopIndex; i++) {
        data.append(_chunkReader->getDecryptedChunk(i));
    }
    return data.substr(_chunkReader->filePosToPosInFileChunk(pos), length);
}