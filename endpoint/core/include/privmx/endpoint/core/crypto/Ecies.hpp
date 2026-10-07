/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_CRYPTO_ECIES_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CRYPTO_ECIES_HPP_

#include <optional>
#include <string>

#include <Poco/JSON/Object.h>

#include <privmx/endpoint/core/crypto/PrivateKey.hpp>
#include <privmx/endpoint/core/crypto/PublicKey.hpp>

namespace privmx {
namespace endpoint {
namespace core {

/**
 * @brief Szyfrowanie do klucza publicznego odbiorcy, podpisane kluczem nadawcy.
 *
 * Cienka warstwa nad `seal` / `open` z pmx-crypto: dokłada Base64 i JSON, a sama nie liczy
 * nic kryptograficznego. Ramka jest ta sama co dotychczas:
 * @code
 *   'e' || pub33(nadawca) || pub33(odbiorca) || iv || ciphertext || tag4
 * @endcode
 */
class Ecies {
public:
    /// @brief Zapieczetowuje dane do `pub`, podpisujac kluczem `privForSignature`.
    static std::string encrypt(const PublicKey& pub, const std::string& data, const PrivateKey& privForSignature);

    /**
     * @brief Otwiera dane zapieczetowane do `priv`.
     * @param pubOfSignature gdy podany, nadawca musi sie z nim zgadzac
     */
    static std::string decrypt(
        const PrivateKey& priv,
        const std::string& cipher,
        const std::optional<PublicKey>& pubOfSignature = std::nullopt
    );

    static std::string encryptToBase64(
        const PublicKey& pub,
        const std::string& data,
        const PrivateKey& privForSignature
    );

    static std::string decryptFromBase64(
        const PrivateKey& priv,
        const std::string& cipherBase64,
        const std::optional<PublicKey>& pubOfSignature = std::nullopt
    );

    static std::string encryptObjectToBase64(
        const PublicKey& pub,
        Poco::JSON::Object::Ptr data,
        const PrivateKey& privForSignature
    );

    static Poco::JSON::Object::Ptr decryptObjectFromBase64(
        const PrivateKey& priv,
        const std::string& cipherBase64,
        const std::optional<PublicKey>& pubOfSignature = std::nullopt
    );
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_CRYPTO_ECIES_HPP_
