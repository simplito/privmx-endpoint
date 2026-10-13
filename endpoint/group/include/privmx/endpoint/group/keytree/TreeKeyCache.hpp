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

#include <privmx/crypto/ecc/PrivateKey.hpp>

namespace privmx {
namespace endpoint {
namespace group {
namespace keytree {

// Cache of per-epoch grant keys for one group — never shared between groups, since nothing here is keyed by group and
// two of them would collide on their first entries. Node keys are not kept: nothing reads them back (T4-22), and a
// private key held for nothing is one more to leak. The mutex is not recursive: never nest.
class TreeKeyCache {
public:
    void putGrantKey(std::uint32_t epoch, const privmx::crypto::PrivateKey& key);
    std::optional<privmx::crypto::PrivateKey> getGrantKey(std::uint32_t epoch) const;

    // For an entry that failed verification against the served tree.
    void forgetGrantKey(std::uint32_t epoch);

    void clear();

private:
    mutable std::shared_mutex _mutex;
    // Within a group `epoch -> key` is immutable; `LadderKeys::buildRungs` reads the older ones.
    std::map<std::uint32_t, privmx::crypto::PrivateKey> _grantKeys;
};

} // namespace keytree
} // namespace group
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_GROUP_KEYTREE_TREEKEYCACHE_HPP_
