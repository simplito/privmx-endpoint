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
 * @brief Encryption to a recipient's public key, attributed to a sender's.
 *
 * A thin layer over pmx-crypto's `seal` / `open`: it adds Base64 and JSON and computes nothing
 * cryptographic of its own. There are two frames, chosen by the recipient's algorithm, and they
 * differ in more than layout — see `sealedBy`.
 *
 * A composed identity (ed25519, ed25519x25519mlkem768) uses `seal(SealParams, ...)`, which carries
 * a signature over the message by the sender's signing half.
 *
 * secp256k1 uses the older two-argument `seal`, whose frame is
 * @code
 *   'e' || pub33(sender) || pub33(recipient) || iv || ciphertext || tag4
 * @endcode
 * and which carries no signature: the sender field is plaintext, and authentication is implicit in
 * the agreement — only a holder of the sender's or the recipient's private key can produce a frame
 * that opens.
 */
class Ecies {
public:
    /// @brief Seals data to `pub`, attributed to `privForSignature`.
    static std::string encrypt(const PublicKey& pub, const std::string& data, const PrivateKey& privForSignature);

    /**
     * @brief Opens data sealed to `priv`.
     * @param pubOfSignature when given, the sender must match it
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

    /**
     * @brief Whether `cipherBase64` names `senderBase58DER` as its sender.
     *
     * **How much this proves depends on the sender's algorithm, and the difference matters.**
     *
     * For a composed identity the frame carries a signature, and this verifies it. A `true` means
     * the holder of that private key sealed this ciphertext.
     *
     * For secp256k1 the frame carries no signature, so this compares the plaintext sender field and
     * nothing else. A `true` means only *the frame says so*. Anyone who can hand us a frame can put
     * any public key in that field — the key is public — so on its own this is not evidence of
     * authorship. What it is good for is filtering: combined with the ciphertext actually opening to
     * something expected, it narrows a candidate down without opening it first.
     *
     * Callers that use the answer to attribute something to a person must therefore either require a
     * signing identity, or pair this with an open that succeeded. `GroupKeyResolver::authenticated`
     * does the latter — it only pre-sorts on this, and `LadderKeys` sets `blame` from a rung that
     * opened.
     *
     * It asks whether the frame matches a given key, rather than returning the sender's key, because
     * for a composed identity the frame carries only the agreement half: that cannot be turned back
     * into the tagged identity key, but it can be compared against one.
     *
     * Returns `false` for a frame that does not parse and for a key that does not parse — no
     * attribution is the safe answer here.
     */
    static bool sealedBy(const std::string& cipherBase64, const std::string& senderBase58DER);
};

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_CRYPTO_ECIES_HPP_
