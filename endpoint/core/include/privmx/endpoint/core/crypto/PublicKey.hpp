/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_CRYPTO_PUBLICKEY_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CRYPTO_PUBLICKEY_HPP_

#include <memory>
#include <string>

#include <privmx/cryptoservice/base/CoreInterfaces.hpp>

namespace privmx {
namespace endpoint {
namespace core {

/**
 * @brief Klucz publiczny jako **typ wartosciowy**.
 *
 * `pmx-crypto` oddaje klucze jako `std::shared_ptr<IPublicKey>`, a interfejs nie ma ani
 * porownania, ani konstruktora domyslnego. Endpoint opiera sie na semantyce wartosciowej
 * w `group/keytree` (`std::map`, `std::optional`, leniwe parsowanie) oraz w `ConnectionImpl`.
 * Ten wrapper ja przywraca, dzieki czemu migracja nie rozlewa sie na logike drzewa kluczy.
 *
 * Kopiowanie jest tanie i **nie** klonuje klucza - instancje wspoldziela ten sam uchwyt.
 * Klucze sa niezmienne, wiec wspoldzielenie jest bezpieczne.
 */
class PublicKey {
public:
    /// @throws privmx::cryptoservice::Exception gdy dane nie sa poprawnym kluczem
    static PublicKey fromBase58DER(const std::string& base58DER);
    /// @throws privmx::cryptoservice::Exception gdy dane nie sa poprawnym kluczem
    static PublicKey fromDER(const std::string& der);

    /// @brief Pusty uchwyt. Operacje poza `empty()` i porownaniem rzucaja wyjatek.
    PublicKey() = default;

    explicit PublicKey(std::shared_ptr<privmx::cryptoservice::IPublicKey> key) : _key(std::move(key)) {}

    bool empty() const { return _key == nullptr; }

    /// Porownanie po postaci kanonicznej (Base58DER), a nie po tozsamosci uchwytu.
    bool operator==(const PublicKey& other) const;
    bool operator!=(const PublicKey& other) const { return !(*this == other); }

    std::string toDER() const;
    std::string toBase58DER() const;

    /**
     * @brief Weryfikuje podpis zlozony nad skrotem SHA-256 wiadomosci.
     *
     * Mapuje sie na `SigScheme::Compact`, a **nie** na `CompactWithHash`: ten drugi liczy
     * `sha256` dodatkowo, dajac ECDSA nad `sha256(sha256(m))`. Nazwa myli - nie "poprawiac".
     * Dowod pomiarowy: crypto-update/B1-podpisy-compact.md
     */
    bool verifyCompactSignatureWithHash(const std::string& message, const std::string& signature) const;

    std::shared_ptr<privmx::cryptoservice::IPublicKey> impl() const { return _key; }

private:
    const privmx::cryptoservice::IPublicKey& require() const;

    std::shared_ptr<privmx::cryptoservice::IPublicKey> _key;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_CRYPTO_PUBLICKEY_HPP_
