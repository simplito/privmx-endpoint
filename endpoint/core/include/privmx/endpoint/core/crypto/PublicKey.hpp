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

#include <privmx/endpoint/core/crypto/KeyFormats.hpp>

namespace privmx {
namespace endpoint {
namespace core {

/**
 * @brief A public key as a **value type**.
 *
 * `pmx-crypto` hands keys back as `std::shared_ptr<IPublicKey>`, and that interface has neither
 * comparison nor a default constructor. The endpoint relies on value semantics in `group/keytree`
 * (`std::map`, `std::optional`, lazy parsing) and in `ConnectionImpl`. This wrapper restores them,
 * so the migration does not spill over into the key-tree logic.
 *
 * Copying is cheap and does **not** clone the key — instances share the same handle. Keys are
 * immutable, so sharing is safe.
 */
class PublicKey {
public:
    /// @throws privmx::cryptoservice::Exception when the data is not a valid key
    static PublicKey fromBase58DER(const std::string& base58DER);
    /// @throws privmx::cryptoservice::Exception when the data is not a valid key
    static PublicKey fromDER(const std::string& der);

    /// @brief An empty handle. Anything beyond `empty()` and comparison throws.
    PublicKey() = default;

    /**
     * @brief A handle together with the algorithm it corresponds to.
     *
     * The algorithm is passed in because `pmx-crypto` does not expose it from the key, while the
     * endpoint always knows what it imported or generated. Users' keys may be of any algorithm, so
     * operations (signing, verification) have to follow **this** field, not a compile-time constant.
     */
    explicit PublicKey(
        std::shared_ptr<privmx::cryptoservice::IPublicKey> key,
        privmx::cryptoservice::AsymAlg algorithm = defaultKeyAlgorithm(),
        std::shared_ptr<privmx::cryptoservice::IPublicKey> agreementKey = nullptr,
        std::shared_ptr<privmx::cryptoservice::IPublicKey> kemKey = nullptr
    )
        : _key(std::move(key)),
          _algorithm(algorithm),
          _agreementKey(std::move(agreementKey)),
          _kemKey(std::move(kemKey)) {}

    bool empty() const { return _key == nullptr; }

    /// @brief This key's algorithm. An empty handle reports the default and is not usable.
    privmx::cryptoservice::AsymAlg algorithm() const { return _algorithm; }

    /// Compares canonical forms (Base58DER), not handle identity.
    bool operator==(const PublicKey& other) const;
    bool operator!=(const PublicKey& other) const { return !(*this == other); }

    std::string toDER() const;
    std::string toBase58DER() const;

    /**
     * @brief Verifies a signature made over the message's SHA-256 digest.
     *
     * Maps to `SigScheme::Compact`, **not** `CompactWithHash`: the latter computes a further
     * `sha256`, giving ECDSA over `sha256(sha256(m))`. The name misleads — do not "fix" this.
     * Measured proof: crypto-update/sigcompat.cpp
     */
    bool verifyCompactSignatureWithHash(const std::string& message, const std::string& signature) const;

    std::shared_ptr<privmx::cryptoservice::IPublicKey> impl() const { return _key; }

    /**
     * @brief The half a shared secret is agreed with, which is not always the half that signs.
     *
     * An Ed25519 identity cannot do Diffie-Hellman, so it carries a second X25519 key and this is it.
     * For an algorithm that does both jobs this is the same handle as `impl()`, so callers that wrap
     * keys (`Ecies`, `derive`) can use it unconditionally.
     */
    std::shared_ptr<privmx::cryptoservice::IPublicKey> agreementImpl() const {
        return _agreementKey != nullptr ? _agreementKey : _key;
    }

    /**
     * @brief The half a sender encapsulates to, or null when the identity has no post-quantum one.
     *
     * Unlike `agreementImpl()` this has no fallback: a key encapsulation is a different operation
     * from a Diffie-Hellman and there is nothing sensible to substitute. Callers ask
     * `keyAlgorithmNeedsKemKey(algorithm())` and leave the post-quantum term out when there is none.
     */
    std::shared_ptr<privmx::cryptoservice::IPublicKey> kemImpl() const { return _kemKey; }

private:
    const privmx::cryptoservice::IPublicKey& require() const;

    std::shared_ptr<privmx::cryptoservice::IPublicKey> _key;
    privmx::cryptoservice::AsymAlg _algorithm = defaultKeyAlgorithm();
    /// Null unless the algorithm signs but cannot agree keys; see `agreementImpl()`.
    std::shared_ptr<privmx::cryptoservice::IPublicKey> _agreementKey;
    /// Null unless the algorithm has a key-encapsulation half; see `kemImpl()`.
    std::shared_ptr<privmx::cryptoservice::IPublicKey> _kemKey;
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_CRYPTO_PUBLICKEY_HPP_
