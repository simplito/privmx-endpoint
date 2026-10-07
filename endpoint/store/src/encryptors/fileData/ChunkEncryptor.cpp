/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/encryptors/fileData/ChunkEncryptor.hpp"

#include <privmx/endpoint/store/StoreException.hpp>

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

ChunkEncryptor::ChunkEncryptor(std::string key, size_t chunkSize, FileCipher cipher)
    : _key(key), _chunkSize(chunkSize), _cipher(cipher) {}

IChunkEncryptor::Chunk ChunkEncryptor::encrypt(const uint64_t index, const std::string& data) {
    return _cipher.encryptChunk(_cipher.chunkKey(_key, index), data);
}

bool ChunkEncryptor::hasHash(const std::string& chunkData, const std::string& hash) const {
    return chunkData.size() >= _cipher.hashLength() && chunkData.substr(0, _cipher.hashLength()) == hash;
}

std::string ChunkEncryptor::decrypt(const uint64_t index, const Chunk& chunk) {
    // Dwa rozne bledy, bo wskazuja na co innego. Ten pierwszy znaczy, ze skrot z tablicy skrotow
    // nie pasuje do ramki, czyli ze serwer podal chunk z innego miejsca pliku. Dopiero drugi,
    // w `FileCipher`, znaczy, ze sama ramka jest naruszona.
    if (!hasHash(chunk.data, chunk.hmac)) {
        throw FileChunkInvalidChecksumException();
    }
    return _cipher.decryptChunk(_cipher.chunkKey(_key, index), chunk);
}

size_t ChunkEncryptor::getPlainChunkSize() {
    return _chunkSize;
}

size_t ChunkEncryptor::getEncryptedChunkSize() {
    return _cipher.encryptedChunkSize(_chunkSize);
}

uint64_t ChunkEncryptor::getEncryptedFileSize(const uint64_t& fileSize) {
    return _cipher.encryptedFileSize(fileSize, _chunkSize);
}

void ChunkEncryptor::sync(std::string key, size_t chunkSize) {
    _key = key;
    _chunkSize = chunkSize;
}
