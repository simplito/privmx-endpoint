/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_STORE_GLOBAL_CACHE_HPP_
#define _PRIVMXLIB_ENDPOINT_STORE_GLOBAL_CACHE_HPP_

#include <memory>
#include <mutex>
#include <privmx/endpoint/store/cache/CacheInterface.hpp>

namespace privmx {
namespace endpoint {
namespace store {

/**
 * Runtime-wide singleton holding the shared chunk data cache.
 *
 * To configure the cache, call exactly one of the following before the first
 * call to Connection::connect():
 *   - setChunksCache()        — provide a custom CacheInterface implementation
 *   - setChunksCacheEnabled() — enable or disable the built-in in-memory cache
 *
 * Calling both is not supported: setChunksCache() takes precedence and
 * setChunksCacheEnabled() will have no effect once an instance is set.
 * After the first connect(), the cache instance is frozen and further calls
 * to either method have no effect.
 */
class GlobalCache
{
public:
    /**
     * Enables or disables the built-in in-memory cache.
     * Must be called before Connection::connect(). Has no effect if setChunksCache() was already called.
     *
     * @param enabled true to use the built-in CacheInMemory (default), false to use a no-op cache
     */
    static void setChunksCacheEnabled(bool enabled);

    /**
     * Sets a custom cache implementation for the entire runtime.
     * Must be called before Connection::connect(). Takes precedence over setChunksCacheEnabled().
     *
     * @param cache custom CacheInterface implementation (e.g. disk-backed or Redis cache)
     */
    static void setChunksCache(std::shared_ptr<CacheInterface> cache);

    /**
     * Returns the shared cache instance, initializing it on the first call.
     * After the first call the instance is frozen — subsequent setChunksCache()
     * and setChunksCacheEnabled() calls have no effect.
     */
    static std::shared_ptr<CacheInterface> getChunksCacheInstance();
    
    GlobalCache() = delete;

private:
    static bool _isChunksCacheEnabled;
    static std::shared_ptr<CacheInterface> _chunksCacheImpl;
    static std::once_flag _chunksCacheInitFlag;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_GLOBAL_CACHE_HPP_
