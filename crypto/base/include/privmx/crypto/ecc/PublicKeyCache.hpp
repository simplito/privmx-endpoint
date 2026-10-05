/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTO_PUBLICKEYCACHE_HPP_
#define _PRIVMXLIB_CRYPTO_PUBLICKEYCACHE_HPP_

#include <cstddef>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>

#include <privmx/crypto/ecc/PublicKey.hpp>

namespace privmx {
namespace crypto {

// Memoizes `PublicKey::fromBase58DER`, whose cost is the subgroup check — a full scalar multiplication, as
// expensive as an ECDH — while a verification pass re-parses the same few author keys for every object.
class PublicKeyCache {
public:
    static std::shared_ptr<PublicKeyCache> getInstance();
    static void freeInstance();
    PublicKeyCache(const PublicKeyCache& obj) = delete;
    void operator=(const PublicKeyCache&) = delete;

    // Same result and same exceptions as `PublicKey::fromBase58DER`. A key that fails to parse is not cached.
    // One table for every thread, so a key parsed on an event-pool thread is a hit on the caller's thread too.
    PublicKey fromBase58DER(const std::string& base58DER);

    void clear();
    std::size_t size() const;

protected:
    PublicKeyCache() {};

private:
    static std::shared_ptr<PublicKeyCache> impl;
    // The bridge is the one party the threat model assumes may be hostile, and it chooses how many distinct
    // author keys it serves. Without a ceiling that is an unbounded allocation it controls.
    static constexpr std::size_t MAX_ENTRIES_PER_GENERATION = 128;

    mutable std::shared_mutex _mutex;
    // Two generations rather than an LRU: eviction is one move, and `_previous` keeps a key reachable for one
    // more round so the entries actually in use do not have to be re-parsed right after a swap.
    std::unordered_map<std::string, PublicKey> _current;
    std::unordered_map<std::string, PublicKey> _previous;
};

} // namespace crypto
} // namespace privmx

#endif // _PRIVMXLIB_CRYPTO_PUBLICKEYCACHE_HPP_
