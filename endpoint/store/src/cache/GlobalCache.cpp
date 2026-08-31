/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/store/cache/CacheBackendInMemory.hpp>
#include <privmx/endpoint/store/cache/CacheNoOp.hpp>
#include <privmx/endpoint/store/cache/GlobalCache.hpp>
#include <privmx/endpoint/store/cache/SlruBackedCache.hpp>

using namespace privmx::endpoint::store;

bool GlobalCache::_isChunksCacheEnabled = true;

std::shared_ptr<CacheInterface> GlobalCache::_chunksCacheImpl = nullptr;
std::shared_ptr<CacheBackendInterface> GlobalCache::_chunksCacheBackend = nullptr;
size_t GlobalCache::_chunksCacheMaxBytes = CacheBackendInterface::DEFAULT_MAX_BYTES;
std::once_flag GlobalCache::_chunksCacheInitFlag;

void GlobalCache::setChunksCacheEnabled(bool enabled) {
    _isChunksCacheEnabled = enabled;
}

void GlobalCache::setChunksCache(std::shared_ptr<CacheInterface> cache) {
    _chunksCacheImpl = std::move(cache);
}

void GlobalCache::setChunksCacheBackend(std::shared_ptr<CacheBackendInterface> backend, size_t maxBytes) {
    _chunksCacheBackend = std::move(backend);
    _chunksCacheMaxBytes = maxBytes;
}

std::shared_ptr<CacheInterface> GlobalCache::getChunksCacheInstance() {
    std::call_once(_chunksCacheInitFlag, []() {
        if (_chunksCacheImpl)
            return;
        if (_chunksCacheBackend) {
            _chunksCacheImpl = std::make_shared<SlruBackedCache>(*_chunksCacheBackend, _chunksCacheMaxBytes);
            return;
        }
        if (_isChunksCacheEnabled) {
            auto backend = std::make_shared<CacheBackendInMemory>();
            _chunksCacheBackend = backend;
            _chunksCacheImpl = std::make_shared<SlruBackedCache>(*backend, _chunksCacheMaxBytes);
        } else {
            _chunksCacheImpl = std::make_shared<CacheNoOp>();
        }
    });
    return _chunksCacheImpl;
}
