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
#include <privmx/endpoint/store/cache/CacheInterface.hpp>

namespace privmx {
namespace endpoint {
namespace store {

class GlobalCache
{
public:
    static std::shared_ptr<CacheInterface> getInstance();
    static void freeInstance();
    GlobalCache() = delete;

private:
    static std::shared_ptr<CacheInterface> impl;
};

} // store
} // endpoint
} // privmx

#endif // _PRIVMXLIB_ENDPOINT_STORE_GLOBAL_CACHE_HPP_
