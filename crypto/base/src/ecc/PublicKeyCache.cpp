/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <mutex>
#include <optional>
#include <utility>

#include <privmx/crypto/ecc/PublicKeyCache.hpp>

using namespace privmx;
using namespace privmx::crypto;

std::shared_ptr<PublicKeyCache> PublicKeyCache::impl = nullptr;

std::shared_ptr<PublicKeyCache> PublicKeyCache::getInstance() {
    if(!impl) {
        impl = std::shared_ptr<PublicKeyCache>(new PublicKeyCache());
    }
    return impl;
}

void PublicKeyCache::freeInstance() {
    if(impl) {
        impl.reset();
    }
}

// A hit hands every thread the same backend handle. That is sound only because nothing here ever writes
// through it: the ECC backend's verify and derive read the key and leave it unchanged.
PublicKey PublicKeyCache::fromBase58DER(const std::string& base58DER) {
    std::optional<PublicKey> demoted;
    {
        std::shared_lock<std::shared_mutex> lock(_mutex);
        if (auto it = _current.find(base58DER); it != _current.end()) {
            return it->second;
        }
        if (auto it = _previous.find(base58DER); it != _previous.end()) {
            demoted = it->second;
        }
    }
    // Parsed with no lock held, so one slow parse never blocks the readers. Two threads racing on the same
    // miss cost one wasted parse, which is cheaper than putting every caller behind the write lock.
    PublicKey key = demoted.has_value() ? demoted.value() : PublicKey::fromBase58DER(base58DER);

    std::unique_lock<std::shared_mutex> lock(_mutex);
    _previous.erase(base58DER);
    if (_current.size() >= MAX_ENTRIES_PER_GENERATION) {
        _previous = std::move(_current);
        _current = {};
    }
    // `emplace`, so a thread that lost the race keeps using the entry already published rather than
    // replacing it with its own equivalent copy.
    return _current.emplace(base58DER, key).first->second;
}

void PublicKeyCache::clear() {
    std::unique_lock<std::shared_mutex> lock(_mutex);
    _current.clear();
    _previous.clear();
}

std::size_t PublicKeyCache::size() const {
    std::shared_lock<std::shared_mutex> lock(_mutex);
    return _current.size() + _previous.size();
}
