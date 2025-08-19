/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_CHUNKENCRYPTOR_INTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_CHUNKENCRYPTOR_INTERFACE_HPP_

namespace privmx {
namespace endpoint {
namespace store {

#include <string>

class IChunkEncryptor
{
public:
    struct Chunk
    {
        std::string data;
        std::string hmac;
    };

    virtual ~IChunkEncryptor() = default;
    virtual Chunk encrypt(const size_t index, const std::string& data) = 0;
    virtual std::string decrypt(const size_t index, const Chunk& chunk) = 0;
    virtual size_t getPlainChunkSize() = 0;
    virtual size_t getEncryptedChunkSize() = 0;
    virtual size_t getEncryptedFileSize(const size_t& fileSize) = 0;

};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_CHUNKENCRYPTOR_INTERFACE_HPP_
