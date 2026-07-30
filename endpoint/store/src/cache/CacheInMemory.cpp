/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/endpoint/store/cache/CacheInMemory.hpp>

namespace privmx {
namespace endpoint {
namespace store {

std::optional<core::Buffer> CacheInMemory::get(const std::string& key) {
    auto it = _store.find(key);
    if (it == _store.end()) {
        return std::nullopt;
    }
    return it->second;
}

void CacheInMemory::put(const std::string& key, const core::Buffer& data) {
    _store[key] = data;
}

void CacheInMemory::del(const std::string& key) {
    _store.erase(key);
}

} // namespace store
} // namespace endpoint
} // namespace privmx
