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

#include <privmx/utils/SingletonSlot.hpp>

#include <privmx/endpoint/core/crypto/PublicKeyCache.hpp>

using namespace privmx::endpoint::core;

namespace {

/**
 * Guards the slot itself, which is not the same thing as the cache's own `_mutex`.
 *
 * Declared **before** `slot`, so it outlives it: objects in a translation unit are destroyed in
 * reverse order of definition, and `freeInstance` may run during static destruction.
 *
 * The slot needs a lock because `getInstance` reads a `std::shared_ptr` and then writes it, and
 * `freeInstance` resets the same one. Two threads reaching a cold cache at once — which is the
 * ordinary case, since the event-queue thread and the calling thread both decrypt — would otherwise
 * race on that pointer, and each walk away with a cache of its own. This is cheap next to what a
 * miss costs: one uncontended lock against parsing an EC point.
 */
std::mutex slotMutex;

privmx::utils::SingletonSlot<PublicKeyCache> slot;

} // namespace

std::shared_ptr<PublicKeyCache> PublicKeyCache::getInstance() {
    std::lock_guard<std::mutex> lock(slotMutex);
    if (!slot.ref()) {
        slot.ref() = std::shared_ptr<PublicKeyCache>(new PublicKeyCache());
    }
    return slot.ref();
}

void PublicKeyCache::freeInstance() {
    // The flag is checked before the slot is touched - see SingletonSlot.
    if (!privmx::utils::SingletonSlot<PublicKeyCache>::alive()) {
        return;
    }
    std::lock_guard<std::mutex> lock(slotMutex);
    slot.ref().reset();
}

// A hit hands every thread the same backend handle. That is correct only because nothing here writes
// through it: verification and derivation read the key and leave it unchanged.
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
    // Parsed without holding the lock, so one slow parse never blocks the readers. Two threads racing
    // on the same miss cost one wasted parse, which is cheaper than putting every caller through the
    // write lock.
    PublicKey key = demoted.has_value() ? demoted.value() : PublicKey::fromBase58DER(base58DER);

    std::unique_lock<std::shared_mutex> lock(_mutex);
    _previous.erase(base58DER);
    if (_current.size() >= MAX_ENTRIES_PER_GENERATION) {
        _previous = std::move(_current);
        _current = {};
    }
    // `emplace`, so the thread that lost the race uses the entry already published instead of
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
