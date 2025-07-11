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


#include <cstdint>
#include <string>
#include "privmx/endpoint/store/interfaces/IChunkEncryptor.hpp"

namespace privmx {
namespace endpoint {
namespace store {

class ChunkEncryptor : public IChunkEncryptor
{
public:
    ChunkEncryptor(std::string key, size_t chunkSize);
    IChunkEncryptor::Chunk encrypt(const size_t index, const std::string& data) override;
    std::string decrypt(const size_t index, const Chunk& chunk) override;
    size_t getPlainChunkSize() override;
    size_t getEncryptedChunkSize() override;
    size_t getEncryptedFileSize(const size_t& fileSize) override;
    size_t getChunkIndex(const size_t& pos) override;
private:
    std::string chunkIndexToBE(const size_t index);

    std::string _key;
    size_t _chunkSize;
};
} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_CHUNKENCRYPTOR_HPP_
