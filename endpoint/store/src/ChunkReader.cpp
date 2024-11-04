/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/ChunkReader.hpp"

#include <privmx/crypto/Crypto.hpp>
#include <Poco/ByteOrder.h>

#include "privmx/endpoint/store/StoreException.hpp"
#include "privmx/endpoint/store/StoreTypes.hpp"
#include <privmx/utils/Utils.hpp>
#include <iostream>

using namespace privmx::endpoint::store;

ChunkReader::ChunkReader(
    std::shared_ptr<store::IChunkDataProvider> chunkDataProvider,
    size_t chunkSize,
    const std::string& key,
    const std::string& hmac
)
    : _chunkDataProvider(chunkDataProvider),
    _chunkSize(chunkSize),
    _key(key)
{
    _checksums = _chunkDataProvider->getChecksums();
    if (hmac != crypto::Crypto::hmacSha256(_key, _checksums)) {
        throw FileInvalidChecksumException();
    }
}

std::string ChunkReader::getChunk(uint32_t chunkNumber) {
    if(!_lastChunkNumber.has_value() || _lastChunkNumber.value() != chunkNumber) {
        _lastChunkDecrypted = decryptChunk(_chunkDataProvider->getChunk(chunkNumber), chunkNumber);
        _lastChunkNumber = chunkNumber;
    }
    return _lastChunkDecrypted;
}

size_t ChunkReader::getChunkSize() {
    return _chunkSize;
}

std::string ChunkReader::decryptChunk(std::string encryptedChunk, uint32_t chunkNumber) {
    std::string chunkKey = privmx::crypto::Crypto::sha256(_key + chunkNumberToBE(chunkNumber));
    std::string hmac = encryptedChunk.substr(0, HMAC_SIZE);
    if (_checksums.substr(chunkNumber * HMAC_SIZE, HMAC_SIZE) != hmac) {
        throw FileChunkInvalidChecksumException();
    }
    std::string hmac2 = crypto::Crypto::hmacSha256(chunkKey, encryptedChunk.substr(HMAC_SIZE));
    if (hmac != hmac2) {
        throw FileChunkInvalidCipherChecksumException();
    }
    std::string iv = encryptedChunk.substr(HMAC_SIZE, IV_SIZE);
    std::string chunk = crypto::Crypto::aes256CbcPkcs7Decrypt(encryptedChunk.substr(HMAC_SIZE + IV_SIZE), chunkKey, iv);
    return chunk;
}

std::string ChunkReader::chunkNumberToBE(uint32_t chunkNumber) {
    uint32_t seq_be = Poco::ByteOrder::toBigEndian(chunkNumber);
    return std::string((char *)&seq_be, 4);
}

uint64_t ChunkReader::getEncryptedFileSize(uint64_t fileSize) {
    if (fileSize == 0) {
        return 0;
    }
    Poco::Int64 parts = (fileSize + _chunkSize - 1) / _chunkSize;
    Poco::Int64 lastChunkSize = fileSize % _chunkSize;
    if (lastChunkSize == 0) {
        lastChunkSize = _chunkSize;
    }
    // 16 iv + 32 hmac + max 16 padding
    Poco::Int64 fullChunkPaddingSize = CHUNK_PADDING - (_chunkSize % CHUNK_PADDING);
    Poco::Int64 lastChunkPaddingSize = CHUNK_PADDING - (lastChunkSize % CHUNK_PADDING);
    Poco::Int64 encryptedFileSize = (parts - 1) * (_chunkSize + HMAC_SIZE + IV_SIZE + fullChunkPaddingSize) + lastChunkSize + HMAC_SIZE + IV_SIZE + lastChunkPaddingSize;
    return encryptedFileSize;
}

size_t ChunkReader::getEncryptedChunkSize(size_t chunkSize) {
    Poco::Int64 CHUNK_PADDINGSize = CHUNK_PADDING - (chunkSize % CHUNK_PADDING);
    return chunkSize + CHUNK_PADDINGSize + HMAC_SIZE + IV_SIZE;
}