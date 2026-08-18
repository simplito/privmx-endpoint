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

/**
 * Local cache of tree node keys and per-epoch grant keys, for **one group**.
 *
 * Caching is an **optimisation, not a correctness requirement**. Losing it costs bandwidth, not access: the
 * client re-fetches the tree and climbs again. That is the property the whole design protects, and it is why
 * this store has no persistence contract.
 *
 * One store per group, handed out by `TreeKeyCacheRegistry`. Nothing here is keyed by group, so sharing one
 * store between groups would alias them: epochs start at 1 everywhere and node indices are small integers, so
 * two groups collide on their very first entries.
 *
 * Reachable from the app thread and from several `Executor` pool threads at once, hence the lock. **The mutex is
 * not recursive**: every public method takes it and then touches a container directly — never call one public
 * method from another.
 *
 * Unbounded by design for now: entries accumulate for the lifetime of the connection. Bounding it (LRU, or a cap
 * on epochs per group) is a known future improvement, not yet implemented.
 */
class TreeKeyCache {
public:
    void putNodeKey(std::uint32_t nodeIndex, std::uint32_t generation, const privmx::crypto::PrivateKey& key);
    std::optional<privmx::crypto::PrivateKey> getNodeKey(std::uint32_t nodeIndex, std::uint32_t generation) const;

    void putGrantKey(std::uint32_t epoch, const privmx::crypto::PrivateKey& key);
    std::optional<privmx::crypto::PrivateKey> getGrantKey(std::uint32_t epoch) const;

    /** Drops one epoch's grant key. Used to evict an entry that failed verification against the served tree. */
    void forgetGrantKey(std::uint32_t epoch);

    /**
     * Drops the node keys, keeping the grant keys.
     *
     * What a removal invalidates: it refreshes every node on the departing leaf's path, so those generations are
     * dead. Grant keys are not touched, because within one group `epoch -> key` is immutable — and
     * `LadderKeys::buildRungs` reads the older ones to publish skip rungs at the *next* removal.
     */
    void clearNodeKeys();

    /** Highest epoch with a cached grant key, if any. Lets a caller tell a newer epoch from one it already has. */
    std::optional<std::uint32_t> highestGrantEpoch() const;

    /** Number of cached node keys. For tests and diagnostics. */
    std::size_t nodeKeyCount() const;

    void clear();

private:
    mutable std::shared_mutex _mutex;
    /** Keyed by (nodeIndex, generation) — never by node alone: a refresh makes the old key a different key. */
    std::map<std::pair<std::uint32_t, std::uint32_t>, privmx::crypto::PrivateKey> _nodeKeys;
    std::map<std::uint32_t, privmx::crypto::PrivateKey> _grantKeys;
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEKEYCACHE_HPP_
