/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/keytree/TreeKeyCache.hpp"

#include <algorithm>
#include <mutex>
#include <shared_mutex>

using namespace privmx::endpoint::group::keytree;

void TreeKeyCache::putGrantKey(std::uint32_t epoch, const privmx::crypto::PrivateKey& key) {
    std::unique_lock lock(_mutex);
    // `insert_or_assign`, not `operator[]`: subscripting default-constructs the value, and a default-constructed EC key
    // generates a fresh keypair (`ECC::ECC()` calls `genPair()`).
    _grantKeys.insert_or_assign(epoch, key);
}

std::optional<privmx::crypto::PrivateKey> TreeKeyCache::getGrantKey(std::uint32_t epoch) const {
    std::shared_lock lock(_mutex);
    const auto it = _grantKeys.find(epoch);
    if (it == _grantKeys.end()) {
        return std::nullopt;
    }
    return it->second;
}

void TreeKeyCache::forgetGrantKey(std::uint32_t epoch) {
    std::unique_lock lock(_mutex);
    _grantKeys.erase(epoch);
}

void TreeKeyCache::clear() {
    std::unique_lock lock(_mutex);
    _grantKeys.clear();
}

std::uint32_t TreeKeyCache::raiseFloor(std::uint32_t seen) {
    std::unique_lock lock(_mutex);
    _floor = std::max(_floor, seen);
    return _floor;
}
