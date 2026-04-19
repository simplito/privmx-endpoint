/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/store/cache/GlobalCache.hpp>
#include <privmx/endpoint/store/cache/CacheInMemory.hpp>
// #include <privmx/endpoint/store/cache/CacheNoOp.hpp>

using namespace privmx::endpoint::store;

std::shared_ptr<CacheInterface> GlobalCache::impl = nullptr;

std::shared_ptr<CacheInterface> GlobalCache::getInstance() {
    if (impl == nullptr) {
        impl = std::make_shared<CacheInMemory>();
        // impl = std::make_shared<CacheNoOp>();
    }
    return impl;
}

void GlobalCache::freeInstance() {
    if (impl) {
        impl.reset();
    }
}
