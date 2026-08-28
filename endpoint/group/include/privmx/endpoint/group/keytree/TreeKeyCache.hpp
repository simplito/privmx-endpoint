/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEKEYCACHE_HPP_
#define _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEKEYCACHE_HPP_

#include <cstdint>
#include <map>
#include <optional>
#include <shared_mutex>
#include <utility>

#include <privmx/crypto/ecc/PrivateKey.hpp>

namespace privmx {
namespace endpoint {
namespace group {
namespace keytree {

// Cache of node keys and per-epoch grant keys for one group — never shared between groups, since nothing here is
// keyed by group and two of them would collide on their first entries. The mutex is not recursive: never nest.
class TreeKeyCache {
public:
    void putNodeKey(std::uint32_t nodeIndex, std::uint32_t generation, const privmx::crypto::PrivateKey& key);
    std::optional<privmx::crypto::PrivateKey> getNodeKey(std::uint32_t nodeIndex, std::uint32_t generation) const;

    void putGrantKey(std::uint32_t epoch, const privmx::crypto::PrivateKey& key);
    std::optional<privmx::crypto::PrivateKey> getGrantKey(std::uint32_t epoch) const;

    // Evicts an entry that failed verification against the served tree.
    void forgetGrantKey(std::uint32_t epoch);

    // Exactly what a removal invalidates. Grant keys stay: within a group `epoch -> key` is immutable, and
    // `LadderKeys::buildRungs` reads the older ones to publish skip rungs at the next removal.
    void clearNodeKeys();

    // Lets a caller tell a newer epoch from one it already has.
    std::optional<std::uint32_t> highestGrantEpoch() const;

    // For tests and diagnostics.
    std::size_t nodeKeyCount() const;

    void clear();

private:
    mutable std::shared_mutex _mutex;
    // Unbounded by design: entries accumulate for the lifetime of the connection. Keyed by (nodeIndex, generation),
    // never by node alone — a refresh makes the old key a different key.
    std::map<std::pair<std::uint32_t, std::uint32_t>, privmx::crypto::PrivateKey> _nodeKeys;
    std::map<std::uint32_t, privmx::crypto::PrivateKey> _grantKeys;
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEKEYCACHE_HPP_
