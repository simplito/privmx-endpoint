/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/checkpoint/ChainCheckpointRegistry.hpp"

#include <mutex>
#include <shared_mutex>

using namespace privmx::endpoint::group::checkpoint;

std::shared_ptr<ChainCheckpoint> ChainCheckpointRegistry::get(const std::string& groupId) {
    std::unique_lock lock(_mutex);
    const auto it = _stores.find(groupId);
    if (it != _stores.end()) {
        return it->second;
    }
    auto store = std::make_shared<ChainCheckpoint>();
    _stores.emplace(groupId, store);
    return store;
}

std::shared_ptr<ChainCheckpoint> ChainCheckpointRegistry::tryGet(const std::string& groupId) const {
    std::shared_lock lock(_mutex);
    const auto it = _stores.find(groupId);
    return it != _stores.end() ? it->second : nullptr;
}

void ChainCheckpointRegistry::drop(const std::string& groupId) {
    std::unique_lock lock(_mutex);
    _stores.erase(groupId);
}

void ChainCheckpointRegistry::dropAll() {
    std::unique_lock lock(_mutex);
    _stores.clear();
}

std::size_t ChainCheckpointRegistry::groupCount() const {
    std::shared_lock lock(_mutex);
    return _stores.size();
}
