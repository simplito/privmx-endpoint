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
#include <privmx/endpoint/store/cache/CacheNoOp.hpp>

using namespace privmx::endpoint::store;

bool GlobalCache::_isChunksCacheEnabled = true;

std::shared_ptr<CacheInterface> GlobalCache::_chunksCacheImpl = nullptr;
std::once_flag GlobalCache::_chunksCacheInitFlag;

void GlobalCache::setChunksCacheEnabled(bool enabled) {
    _isChunksCacheEnabled = enabled;
}

void GlobalCache::setChunksCache(std::shared_ptr<CacheInterface> cache) {
    _chunksCacheImpl = std::move(cache);
}

std::shared_ptr<CacheInterface> GlobalCache::getChunksCacheInstance() {
    std::call_once(_chunksCacheInitFlag, []() {
        if (_chunksCacheImpl) return;
        if (_isChunksCacheEnabled) {
            _chunksCacheImpl = std::make_shared<CacheInMemory>();
        } else {
            _chunksCacheImpl = std::make_shared<CacheNoOp>();
        }
    });
    return _chunksCacheImpl;
}
