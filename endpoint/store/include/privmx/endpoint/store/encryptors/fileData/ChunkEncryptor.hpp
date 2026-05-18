/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_CHUNKENCRYPTOR_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_CHUNKENCRYPTOR_HPP_

#include "privmx/endpoint/store/interfaces/IChunkEncryptor.hpp"
#include <cstdint>
#include <string>

namespace privmx {
namespace endpoint {
namespace store {

class ChunkEncryptor : public IChunkEncryptor {
public:
    ChunkEncryptor(std::string key, size_t chunkSize);
    IChunkEncryptor::Chunk encrypt(const uint64_t index, const std::string& data) override;
    std::string decrypt(const uint64_t index, const Chunk& chunk) override;
    bool hasHash(const std::string& chunkData, const std::string& hash) const override;
    size_t getPlainChunkSize() override;
    size_t getEncryptedChunkSize() override;
    uint64_t getEncryptedFileSize(const uint64_t& fileSize) override;
    void sync(std::string key, size_t chunkSize) override;

private:
    std::string chunkIndexToBE(const uint64_t index);

    std::string _key;
    size_t _chunkSize;
};
} // namespace store
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_CHUNKENCRYPTOR_HPP_
