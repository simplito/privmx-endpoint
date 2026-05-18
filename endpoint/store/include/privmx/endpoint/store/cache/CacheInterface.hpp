/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_CACHE_INTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_CACHE_INTERFACE_HPP_

#include <string>
#include <optional>
#include <Pson/BinaryString.hpp>

namespace privmx {
namespace endpoint {
namespace store {

/**
 * Interface for chunk data cache shared across all active connections within a single runtime.
 *
 * A single instance serves multiple Bridge servers, Contexts, and users simultaneously.
 * Keys are namespaced externally (per Bridge instance URL and user public key) before reaching this interface,
 * so implementations do not need to handle isolation between connections themselves.
 *
 * Implementations are responsible for enforcing a maximum size limit and an eviction policy
 * (e.g. LRU) to prevent unbounded memory growth.
 */
class CacheInterface
{
public:
    virtual ~CacheInterface() = default;

    /**
     * Returns the cached value for the given key, or std::nullopt if not present.
     */
    virtual std::optional<Pson::BinaryString> get(const std::string& key) = 0;

    /**
     * Inserts or replaces the value for the given key.
     */
    virtual void put(const std::string& key, Pson::BinaryString data) = 0;

    /**
     * Removes the entry for the given key. No-op if the key does not exist.
     */
    virtual void del(const std::string& key) = 0;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_CACHE_INTERFACE_HPP_
