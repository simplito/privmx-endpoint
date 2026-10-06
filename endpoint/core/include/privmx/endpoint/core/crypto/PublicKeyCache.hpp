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

// Memoizuje `PublicKey::fromBase58DER`, ktorego kosztem jest sprawdzenie podgrupy - pelne mnozenie
// skalarne, tak drogie jak ECDH - podczas gdy przebieg weryfikacji parsuje w kolko te same kilka
// kluczy autorow dla kazdego obiektu.
class PublicKeyCache {
public:
    static std::shared_ptr<PublicKeyCache> getInstance();
    static void freeInstance();
    PublicKeyCache(const PublicKeyCache& obj) = delete;
    void operator=(const PublicKeyCache&) = delete;

    // Ten sam wynik i te same wyjatki co `PublicKey::fromBase58DER`. Klucz, ktorego nie da sie
    // sparsowac, nie trafia do cache'u. Jedna tablica dla wszystkich watkow, wiec klucz sparsowany
    // na watku puli zdarzen jest trafieniem rowniez na watku wolajacego.
    PublicKey fromBase58DER(const std::string& base58DER);

    void clear();
    std::size_t size() const;

protected:
    PublicKeyCache() {};

private:
    static std::shared_ptr<PublicKeyCache> impl;
    // Bridge jest jedyna strona, ktora model zagrozen dopuszcza jako wroga, i to on decyduje, ile
    // roznych kluczy autorow poda. Bez gornego ograniczenia bylaby to nieograniczona alokacja
    // pod jego kontrola.
    static constexpr std::size_t MAX_ENTRIES_PER_GENERATION = 128;

    mutable std::shared_mutex _mutex;
    // Dwie generacje zamiast LRU: eksmisja to jedno przeniesienie, a `_previous` utrzymuje klucz
    // osiagalnym przez jeszcze jedna runde, wiec wpisy faktycznie uzywane nie musza byc parsowane
    // ponownie zaraz po zamianie.
    std::unordered_map<std::string, PublicKey> _current;
    std::unordered_map<std::string, PublicKey> _previous;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_CRYPTO_PUBLICKEYCACHE_HPP_
