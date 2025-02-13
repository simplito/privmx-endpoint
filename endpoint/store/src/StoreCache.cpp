/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/store/StoreCache.hpp"

using namespace privmx::endpoint;
using namespace privmx::endpoint::store;

StoreCache::StoreCache(std::function<server::Store(std::string)> getStore) : core::Cache<std::string, server::Store>(getStore) {}
    
void StoreCache::update(const std::string& id, const server::Store& value) {
    if(id != value.id()) {
        throw CachedStoreIdMismatchException();
    }
    auto cached = _storage.get(id);
    if(!cached.has_value()) {
        _storage.set(id, value);
        return;
    }
    auto cached_value = cached.value();
    if(value.version() > cached_value.version()) {
        _storage.set(id, value);
    } else if (value.version() == cached_value.version() && value.lastModificationDate() > cached_value.lastModificationDate()) {
        _storage.set(id, value);
    }
}