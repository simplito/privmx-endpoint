/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_CRYPTO_PRIVATEKEY_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CRYPTO_PRIVATEKEY_HPP_

#include <memory>
#include <string>

#include <privmx/cryptoservice/base/CoreInterfaces.hpp>

#include <privmx/endpoint/core/crypto/PublicKey.hpp>

namespace privmx {
namespace endpoint {
namespace core {

/**
 * @brief Klucz prywatny jako **typ wartosciowy**. Uzasadnienie: patrz `core::PublicKey`.
 *
 * Kopiowanie wspoldzieli uchwyt, nie klonuje klucza.
 */
class PrivateKey {
public:
    /// @throws privmx::cryptoservice::Exception gdy WIF jest niepoprawny
    static PrivateKey fromWIF(const std::string& wif);

    /**
     * @brief Klucz z surowych 32 bajtow czesci prywatnej.
     *
     * Odpowiednik dotychczasowego `ECC::fromPrivateKey` - uzywany tam, gdzie klucz kontenera
     * pelni role klucza asymetrycznego (inbox, konwersja kluczy).
     */
    static PrivateKey fromRaw(const std::string& raw);

    static PrivateKey generateRandom();

    /// @brief Pusty uchwyt. Operacje poza `empty()` rzucaja wyjatek.
    PrivateKey() = default;

    explicit PrivateKey(std::shared_ptr<privmx::cryptoservice::IPrivateKey> key) : _key(std::move(key)) {}

    bool empty() const { return _key == nullptr; }

    PublicKey getPublicKey() const;

    /// @brief Surowe 32 bajty czesci prywatnej.
    std::string getPrivateEncKey() const;

    std::string toWIF() const;

    /**
     * @brief Podpisuje skrot SHA-256 wiadomosci.
     *
     * Mapuje sie na `SigScheme::Compact` - patrz uwaga przy
     * `PublicKey::verifyCompactSignatureWithHash`.
     */
    std::string signToCompactSignatureWithHash(const std::string& message) const;

    /// @brief Wspolny sekret ECDH z podanym kluczem publicznym.
    std::string derive(const PublicKey& publicKey) const;

    std::shared_ptr<privmx::cryptoservice::IPrivateKey> impl() const { return _key; }

private:
    const privmx::cryptoservice::IPrivateKey& require() const;

    std::shared_ptr<privmx::cryptoservice::IPrivateKey> _key;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_CRYPTO_PRIVATEKEY_HPP_
