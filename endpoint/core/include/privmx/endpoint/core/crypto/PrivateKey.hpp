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
 * @brief A private key as a **value type**. For the rationale see `core::PublicKey`.
 *
 * Copying shares the handle, it does not clone the key.
 */
class PrivateKey {
public:
    /// @throws privmx::cryptoservice::Exception when the WIF is invalid
    static PrivateKey fromWIF(const std::string& wif);

    /**
     * @brief A key from the raw 32 bytes of the private part.
     *
     * The equivalent of the former `ECC::fromPrivateKey` — used where a container key plays the role
     * of an asymmetric key (inbox, key conversion).
     */
    static PrivateKey fromRaw(const std::string& raw);

    static PrivateKey generateRandom();

    /// @brief An empty handle. Anything beyond `empty()` throws.
    PrivateKey() = default;

    /// @brief A handle together with its algorithm. For the rationale see `core::PublicKey`.
    explicit PrivateKey(
        std::shared_ptr<privmx::cryptoservice::IPrivateKey> key,
        privmx::cryptoservice::AsymAlg algorithm = DEFAULT_KEY_ALGORITHM
    )
        : _key(std::move(key)), _algorithm(algorithm) {}

    bool empty() const { return _key == nullptr; }

    /// @brief This key's algorithm. An empty handle reports the default and is not usable.
    privmx::cryptoservice::AsymAlg algorithm() const { return _algorithm; }

    PublicKey getPublicKey() const;

    /// @brief The raw 32 bytes of the private part.
    std::string getPrivateEncKey() const;

    std::string toWIF() const;

    /**
     * @brief Signs the message's SHA-256 digest.
     *
     * Maps to `SigScheme::Compact` — see the note on
     * `PublicKey::verifyCompactSignatureWithHash`.
     */
    std::string signToCompactSignatureWithHash(const std::string& message) const;

    /// @brief The shared ECDH secret with the given public key.
    std::string derive(const PublicKey& publicKey) const;

    std::shared_ptr<privmx::cryptoservice::IPrivateKey> impl() const { return _key; }

private:
    const privmx::cryptoservice::IPrivateKey& require() const;

    std::shared_ptr<privmx::cryptoservice::IPrivateKey> _key;
    privmx::cryptoservice::AsymAlg _algorithm = DEFAULT_KEY_ALGORITHM;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_CRYPTO_PRIVATEKEY_HPP_
