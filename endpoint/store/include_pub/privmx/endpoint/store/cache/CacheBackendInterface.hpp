/*
PrivMX Endpoint.
Copyright © 2026 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_CACHE_BACKEND_INTERFACE_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_CACHE_BACKEND_INTERFACE_HPP_

#include <cstddef>
#include <memory>
#include <optional>
#include <string>

#include <privmx/endpoint/core/Buffer.hpp>

namespace privmx {
namespace endpoint {
namespace store {

/**
 * Low-level storage backend for cache implementations.
 *
 * CacheInterface implementations delegate raw persistence to this backend.
 * The backend operates on plain string keys and binary values; any namespacing,
 * eviction, or size accounting is handled by the CacheInterface layer above.
 */
class CacheBackendInterface {
public:
    /** Default maximum total size of cached data (512 MB) used by backend-backed cache implementations. */
    static constexpr size_t DEFAULT_MAX_BYTES = 512ULL * 1024 * 1024;

    /**
     * Forward-only iterator over a range of entries sharing a common key prefix.
     * Obtained via CacheBackendInterface::seek().
     */
    class Iterator {
    public:
        virtual ~Iterator() = default;

        /**
         * Returns true if the iterator points to a valid entry.
         * Must be checked before calling key(), value(), or next().
         */
        virtual bool valid() const = 0;

        /**
         * Advances the iterator to the next matching entry.
         * Calling next() when valid() is false is undefined behaviour.
         */
        virtual void next() = 0;

        /**
         * Returns the key of the current entry.
         * Calling key() when valid() is false is undefined behaviour.
         */
        virtual const std::string& key() const = 0;

        /**
         * Returns the value of the current entry.
         * Calling value() when valid() is false is undefined behaviour.
         */
        virtual core::Buffer value() const = 0;
    };

    virtual ~CacheBackendInterface() = default;

    /**
     * Returns the stored value for the given key, or std::nullopt if absent.
     */
    virtual std::optional<core::Buffer> get(const std::string& key) = 0;

    /**
     * Inserts or replaces the value for the given key.
     */
    virtual void put(const std::string& key, const core::Buffer& value) = 0;

    /**
     * Removes the entry for the given key. No-op if the key does not exist.
     */
    virtual void del(const std::string& key) = 0;

    /**
     * Removes all entries from the backend.
     */
    virtual void clear() = 0;

    /**
     * Returns an iterator positioned at the first entry whose key is >= @p prefix,
     * iterating in key order until the end of all entries.
     * An empty prefix iterates over all entries from the beginning.
     */
    virtual std::unique_ptr<Iterator> seek(const std::string& prefix) = 0;
};

} // namespace store
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_CACHE_BACKEND_INTERFACE_HPP_
