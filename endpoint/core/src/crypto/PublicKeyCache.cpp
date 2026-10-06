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

#include <privmx/endpoint/core/crypto/PublicKeyCache.hpp>

using namespace privmx::endpoint::core;

std::shared_ptr<PublicKeyCache> PublicKeyCache::impl = nullptr;

std::shared_ptr<PublicKeyCache> PublicKeyCache::getInstance() {
    if (!impl) {
        impl = std::shared_ptr<PublicKeyCache>(new PublicKeyCache());
    }
    return impl;
}

void PublicKeyCache::freeInstance() {
    if (impl) {
        impl.reset();
    }
}

// Trafienie oddaje kazdemu watkowi ten sam uchwyt backendu. Jest to poprawne tylko dlatego, ze nic tutaj
// przez niego nie zapisuje: weryfikacja i derywacja czytaja klucz i zostawiaja go niezmienionym.
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
    // Parsowanie bez trzymania blokady, wiec jedno wolne parsowanie nigdy nie blokuje czytelnikow. Dwa watki
    // scigajace sie o to samo chybienie kosztuja jedno zmarnowane parsowanie, co jest tansze niz wpuszczanie
    // kazdego wolajacego pod blokade zapisu.
    PublicKey key = demoted.has_value() ? demoted.value() : PublicKey::fromBase58DER(base58DER);

    std::unique_lock<std::shared_mutex> lock(_mutex);
    _previous.erase(base58DER);
    if (_current.size() >= MAX_ENTRIES_PER_GENERATION) {
        _previous = std::move(_current);
        _current = {};
    }
    // `emplace`, wiec watek, ktory przegral wyscig, uzywa wpisu juz opublikowanego zamiast zastepowac go
    // wlasna rownowazna kopia.
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
