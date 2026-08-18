/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include "privmx/endpoint/group/keytree/TreeKeyCache.hpp"

#include <mutex>
#include <shared_mutex>

using namespace privmx::endpoint::group::keytree;

void TreeKeyCache::putNodeKey(
    std::uint32_t nodeIndex,
    std::uint32_t generation,
    const privmx::crypto::PrivateKey& key
) {
    std::unique_lock lock(_mutex);
    // `insert_or_assign`, not `operator[]`: subscripting default-constructs the value first, and a
    // default-constructed EC key **generates a fresh keypair** (`ECC::ECC()` calls `genPair()`). That is ~225 us
    // of thrown-away work per insertion — a thousand times the cost of the insertion itself.
    _nodeKeys.insert_or_assign(std::make_pair(nodeIndex, generation), key);
}

std::optional<privmx::crypto::PrivateKey> TreeKeyCache::getNodeKey(
    std::uint32_t nodeIndex,
    std::uint32_t generation
) const {
    std::shared_lock lock(_mutex);
    const auto it = _nodeKeys.find(std::make_pair(nodeIndex, generation));
    if (it == _nodeKeys.end()) {
        return std::nullopt;
    }
    // By value, deliberately: a reference would outlive the lock.
    return it->second;
}

void TreeKeyCache::putGrantKey(std::uint32_t epoch, const privmx::crypto::PrivateKey& key) {
    std::unique_lock lock(_mutex);
    _grantKeys.insert_or_assign(epoch, key); // see putNodeKey: subscripting would mint a throwaway keypair
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

void TreeKeyCache::clearNodeKeys() {
    std::unique_lock lock(_mutex);
    _nodeKeys.clear();
}

std::optional<std::uint32_t> TreeKeyCache::highestGrantEpoch() const {
    std::shared_lock lock(_mutex);
    if (_grantKeys.empty()) {
        return std::nullopt;
    }
    return _grantKeys.rbegin()->first;
}

std::size_t TreeKeyCache::nodeKeyCount() const {
    std::shared_lock lock(_mutex);
    return _nodeKeys.size();
}

void TreeKeyCache::clear() {
    std::unique_lock lock(_mutex);
    // Both containers cleared here rather than by calling clearNodeKeys(): the mutex is not recursive.
    _nodeKeys.clear();
    _grantKeys.clear();
}
