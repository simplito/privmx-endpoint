/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/ChunkReader.hpp"
#include "privmx/endpoint/store/StoreException.hpp"

using namespace privmx::endpoint::store;

ChunkReader::ChunkReader(
    std::shared_ptr<IChunkDataProvider> chunkDataProvider,
    std::shared_ptr<IChunkEncryptor> chunkEncryptor,
    std::shared_ptr<IHashList> hashList,
    const store::FileDecryptionParams& decryptionParams
)
    : _chunkDataProvider(chunkDataProvider),
    _chunkEncryptor(chunkEncryptor),
    _hashList(hashList),
    _chunkSize(chunkEncryptor->getPlainChunkSize()),
    _version(decryptionParams.version),
    _lastChunk(std::nullopt)
{
    if(decryptionParams.sizeOnServer != _chunkEncryptor->getEncryptedFileSize(decryptionParams.originalSize)) {
        throw FileCorruptedException();
    }
}

size_t ChunkReader::filePosToFileChunkIndex(size_t position) {
    return position / _chunkEncryptor->getPlainChunkSize();
}

size_t ChunkReader::filePosToPosInFileChunk(size_t position) {
    return position % _chunkEncryptor->getPlainChunkSize();
}

std::string ChunkReader::getDecryptedChunk(size_t index) {
    if(!_lastChunk.has_value() || _lastChunk->index != index) {
        std::string chunk = _chunkDataProvider->getChunk(index, _version);
        std::string plain = _chunkEncryptor->decrypt(index, {.data = chunk, .hmac = _hashList->getHash(index)});
        _lastChunk = ChunkReader::DecryptedChunk{plain, index};
    }
    return _lastChunk->decryptedData;
}

void ChunkReader::sync(const store::FileDecryptionParams& newParms) {
    if(newParms.sizeOnServer != _chunkEncryptor->getEncryptedFileSize(newParms.originalSize)) {
        throw FileCorruptedException();
    }
    _hashList->sync(newParms.key, newParms.hmac, _chunkDataProvider->getCurrentChecksumsFromBridge());
    _chunkDataProvider->sync(_version, newParms.sizeOnServer);
    _version = newParms.version;
    _lastChunk = std::nullopt;
}

void ChunkReader::update(int64_t newfileVersion, size_t index) {
    if(!_lastChunk.has_value() || _lastChunk->index != index) {
        _lastChunk = std::nullopt;
    }
}
