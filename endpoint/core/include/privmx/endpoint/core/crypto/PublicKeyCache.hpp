/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_CRYPTO_PUBLICKEYCACHE_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CRYPTO_PUBLICKEYCACHE_HPP_

#include <cstddef>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>

#include <privmx/endpoint/core/crypto/PublicKey.hpp>

namespace privmx {
namespace endpoint {
namespace core {

// Memoises `PublicKey::fromBase58DER`, whose cost is the subgroup check — a full scalar
// multiplication, as expensive as an ECDH — while a verification pass parses the same handful of
// author keys over and over, once per object.
class PublicKeyCache {
public:
    static std::shared_ptr<PublicKeyCache> getInstance();
    static void freeInstance();
    PublicKeyCache(const PublicKeyCache& obj) = delete;
    void operator=(const PublicKeyCache&) = delete;

    // The same result and the same exceptions as `PublicKey::fromBase58DER`. A key that does not
    // parse is never cached. One table across all threads, so a key parsed on the event pool's
    // thread is a hit on the caller's thread too.
    PublicKey fromBase58DER(const std::string& base58DER);

    void clear();
    std::size_t size() const;

protected:
    PublicKeyCache() {};

private:
    // The instance handle lives in a `SingletonSlot` in the source file rather than here — see
    // privmx/utils/SingletonSlot.hpp for why (static destruction order).

    // The bridge is the one party the threat model admits as hostile, and it decides how many
    // distinct author keys it serves. Without an upper bound this would be unbounded allocation
    // under its control.
    static constexpr std::size_t MAX_ENTRIES_PER_GENERATION = 128;

    mutable std::shared_mutex _mutex;
    // Two generations instead of an LRU: eviction is a single move, and `_previous` keeps a key
    // reachable for one more round, so entries that are actually in use do not have to be parsed
    // again right after a swap.
    std::unordered_map<std::string, PublicKey> _current;
    std::unordered_map<std::string, PublicKey> _previous;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_CRYPTO_PUBLICKEYCACHE_HPP_
