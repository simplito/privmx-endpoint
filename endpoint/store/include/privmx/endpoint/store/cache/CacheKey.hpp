/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_CACHE_KEY_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_CACHE_KEY_HPP_

#include <string>
#include <cstdint>

namespace privmx {
namespace endpoint {
namespace store {

/**
 * Factory for cache keys used with CacheInterface.
 *
 * Keys follow the pattern: type + SEP + entity_id + SEP + sub_key
 * where SEP is ';', which never appears in UUIDs, Base58, or Base64.
 *
 * Extend this class with new static methods as the cache grows
 * to cover additional entity types (files, messages, keys, etc.).
 */
class CacheKey
{
public:
    CacheKey() = delete;

    static std::string chunk(const std::string& fileId, uint32_t chunkNumber) {
        return "chunk;" + fileId + ";" + std::to_string(chunkNumber);
    }

};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_CACHE_KEY_HPP_