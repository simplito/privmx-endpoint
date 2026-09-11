/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/keytree/TreeKeyCacheRegistry.hpp"

#include <mutex>
#include <shared_mutex>

using namespace privmx::endpoint::group::keytree;

std::shared_ptr<TreeKeyCache> TreeKeyCacheRegistry::get(const std::string& groupId) {
    // A unique_lock throughout, so get-or-create is atomic. A shared_lock fast path would let two threads racing
    // on the same group each build a store, and one of them would then keep filling an orphan nobody reads.
    std::unique_lock lock(_mutex);
    const auto it = _stores.find(groupId);
    if (it != _stores.end()) {
        return it->second;
    }
    auto store = std::make_shared<TreeKeyCache>();
    _stores.emplace(groupId, store);
    return store;
}

void TreeKeyCacheRegistry::drop(const std::string& groupId) {
    std::unique_lock lock(_mutex);
    _stores.erase(groupId);
}

void TreeKeyCacheRegistry::dropAll() {
    std::unique_lock lock(_mutex);
    _stores.clear();
}

std::size_t TreeKeyCacheRegistry::groupCount() const {
    std::shared_lock lock(_mutex);
    return _stores.size();
}
