/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/encryptors/fileData/ChunkEncryptor.hpp"

#include <Poco/ByteOrder.h>
#include <privmx/crypto/Crypto.hpp>
#include "privmx/endpoint/store/StoreException.hpp"
#include "privmx/endpoint/store/StoreTypes.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

ChunkEncryptor::ChunkEncryptor(std::string key, size_t chunkSize) : _key(key), _chunkSize(chunkSize) {}

IChunkEncryptor::Chunk ChunkEncryptor::encrypt(const size_t index, const std::string& data) {
    std::string chunkKey = privmx::crypto::Crypto::sha256(_key + chunkIndexToBE(index));
    std::string iv = privmx::crypto::Crypto::randomBytes(IV_SIZE);
    std::string cipher = privmx::crypto::Crypto::aes256CbcPkcs7Encrypt(data, chunkKey, iv);
    std::string ivWithCipher = iv + cipher;
    std::string hmac = privmx::crypto::Crypto::hmacSha256(chunkKey, ivWithCipher);
    return {
        .data = hmac + ivWithCipher,
        .hmac = hmac
    };
}

std::string ChunkEncryptor::decrypt(const size_t index, const Chunk& chunk) {
    std::string chunkKey = privmx::crypto::Crypto::sha256(_key + chunkIndexToBE(index));
    std::string hmac = chunk.data.substr(0, HMAC_SIZE);
    if (chunk.hmac != hmac) {
        throw FileChunkInvalidChecksumException();
    }
    std::string hmac2 = crypto::Crypto::hmacSha256(chunkKey, chunk.data.substr(HMAC_SIZE));
    if (hmac != hmac2) {
        throw FileChunkInvalidCipherChecksumException();
    }
    std::string iv = chunk.data.substr(HMAC_SIZE, IV_SIZE);
    std::string plain = crypto::Crypto::aes256CbcPkcs7Decrypt(chunk.data.substr(HMAC_SIZE + IV_SIZE), chunkKey, iv);
    return plain;
}

size_t ChunkEncryptor::getPlainChunkSize() {
    return _chunkSize;
}

size_t ChunkEncryptor::getEncryptedChunkSize() {
    Poco::Int64 CHUNK_PADDINGSize = CHUNK_PADDING - (_chunkSize % CHUNK_PADDING);
    return _chunkSize + CHUNK_PADDINGSize + HMAC_SIZE + IV_SIZE;
}

size_t ChunkEncryptor::getEncryptedFileSize(const size_t& fileSize) {
    size_t numberOfChunks = (fileSize + getPlainChunkSize() - 1) / getPlainChunkSize();
    return numberOfChunks * getEncryptedChunkSize();
}

size_t ChunkEncryptor::getChunkIndex(const size_t& pos) {
    return pos / getPlainChunkSize();
}

std::string ChunkEncryptor::chunkIndexToBE(const size_t index) {
    uint32_t index_be = Poco::ByteOrder::toBigEndian(static_cast<uint32_t>(index));
    return std::string((char *)&index_be, 4);
}