/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_ENDPOINT_CORE_CRYPTO_KEYFORMATS_HPP_
#define _PRIVMXLIB_ENDPOINT_CORE_CRYPTO_KEYFORMATS_HPP_

#include <cstdint>
#include <string>

#include <privmx/cryptoservice/base/CoreTypes.hpp>

namespace privmx {
namespace endpoint {
namespace core {

/**
 * @brief The algorithm **new** identity keys are generated with.
 *
 * Generation only. A key that already exists carries its own algorithm (`PublicKey::algorithm()`,
 * `PrivateKey::algorithm()`) and operations on it follow **that**, not this constant — because
 * users' keys may be of any algorithm, not only the one we happen to generate with.
 *
 * `PrivmxSecp256k1` is secp256k1 with PrivMX's data formats: the private part as a bare 32 B, the
 * public key as 33 B compressed. Plain `secp256k1` uses different, longer forms, so it is not a
 * drop-in replacement.
 *
 * Chosen at build configuration time by `PRIVMX_DEFAULT_KEY_ALGORITHM`, expressed as the algorithm's
 * wire tag so that the build option and the encoding cannot drift apart. It affects **generation
 * only** — the registry stays complete whatever this is, or clients built differently could not read
 * each other's keys.
 */
/**
 * A function, not a macro-driven constant: `PRIVMX_DEFAULT_KEY_ALGORITHM_TAG` is defined for the
 * library's own translation units only. A constant in this header would read the fallback in every
 * consumer — including the tests — and quietly describe a different build from the one linked in.
 * `CryptoSuite::defaultForWrite()` is a function for the same reason.
 */
privmx::cryptoservice::AsymAlg defaultKeyAlgorithm();

/**
 * @brief The signature scheme matching a key's algorithm.
 *
 * Derived from the key rather than taken from a constant: adding another algorithm (Ed25519 is
 * planned) should be one more row here, not a sweep through every place that signs and verifies.
 *
 * For ECDSA curves this is **`Compact`**, not `CompactWithHash`. `Compact` gives ECDSA over
 * `sha256(m)`; `CompactWithHash` computes a further `sha256`, i.e. ECDSA over `sha256(sha256(m))`.
 * The name suggests the opposite — switching to `CompactWithHash` produces signatures that verify
 * only among themselves, with no compile-time or run-time error.
 * Measured proof: crypto-update/sigcompat.cpp
 *
 * @throws UnsupportedKeyAlgorithmException when the algorithm has no scheme assigned here
 */
privmx::cryptoservice::SigScheme signatureSchemeFor(privmx::cryptoservice::AsymAlg algorithm);

/// @brief Whether the endpoint can work with keys of this algorithm.
bool isSupportedKeyAlgorithm(privmx::cryptoservice::AsymAlg algorithm);

/**
 * @brief The bytes to hand the key, so that every algorithm signs the message's SHA-256 digest.
 *
 * `signToCompactSignatureWithHash` promises a signature over that digest. secp256k1's `Compact`
 * scheme computes it inside the provider; Ed25519's `Default` signs whatever it is given. Without
 * this the two would sign different things and a bridge verifying over the digest — as it does —
 * would reject every Ed25519 signature.
 *
 * @throws UnsupportedKeyAlgorithmException when the algorithm is not in the registry
 */
std::string messageToSignFor(privmx::cryptoservice::AsymAlg algorithm, const std::string& message);

/// @brief A private key as it travels: the algorithm the encoding named, and the secret itself.
struct TaggedPrivateKey {
    privmx::cryptoservice::AsymAlg algorithm;
    /// The 32 secret bytes the identity is built from.
    std::string secret;
    /// True when it arrived as a WIF, which names secp256k1 by being one.
    bool wasWif;
};

/**
 * @brief Encodes a private key as `Base58Check(tag || secret)`.
 *
 * A private key has to name its algorithm for the same reason a public one does: otherwise the same
 * string means different identities on differently configured builds, and a build option stops being
 * a default and starts deciding which keys work at all.
 *
 * The tag is the algorithm's, the same byte its public key carries — a public and a private key are
 * never read by the same function, and their lengths differ anyway (a secret is 32 bytes, a public
 * key 33 or 64).
 *
 * @throws UnsupportedKeyAlgorithmException when the algorithm has no encoding of its own
 * @throws MalformedEncryptionKeyException when the secret is not 32 bytes
 */
std::string encodePrivateKey(const std::string& secret, privmx::cryptoservice::AsymAlg algorithm);

/**
 * @brief Reads a private key, taking the algorithm from the key rather than from this build.
 *
 * Accepts both the tagged encoding and a plain WIF. A WIF needs no tag: it *is* a secp256k1 private
 * key, so it reads the same on every build.
 *
 * @throws MalformedEncryptionKeyException when the encoding names no algorithm this build can read
 */
TaggedPrivateKey decodePrivateKey(const std::string& base58);

/// @brief A public key as it travels: the algorithm its tag named, and the bytes behind the tag.
struct TaggedPublicKey {
    privmx::cryptoservice::AsymAlg algorithm;
    /// The signing half, or the whole key when the algorithm does both jobs.
    std::string rawKey;
    /// The key-agreement half, empty unless the algorithm needs a separate one.
    std::string rawAgreementKey;
};

/**
 * @brief Whether an identity of this algorithm needs a second key to agree container keys with.
 *
 * True for Ed25519, which signs but has no Diffie-Hellman. See `KeyAlgorithmSpec::agreementAlgorithm`.
 */
bool keyAlgorithmNeedsAgreementKey(privmx::cryptoservice::AsymAlg algorithm);

/**
 * @brief The algorithm of the agreement half.
 * @throws UnsupportedKeyAlgorithmException when the algorithm needs no separate agreement key
 */
privmx::cryptoservice::AsymAlg agreementAlgorithmFor(privmx::cryptoservice::AsymAlg algorithm);

/**
 * @brief The 32-byte sub-secret one half of a composed identity is built from.
 *
 * Both halves come from one secret — what a WIF already carries — so an identity still travels as a
 * single private key. The halves are domain-separated, never the same bytes twice.
 */
std::string deriveIdentitySeed(const std::string& secret, bool forAgreement);

/**
 * @brief Encodes a public key as `Base58Check(tag || rawKey || rawAgreementKey)`.
 *
 * This is the only encoding a key travels in. It exists because a key has to say which algorithm it
 * is — contract point 2 — and because the bridge now refuses anything untagged. The tags are shared
 * wire format with the bridge (`src/utils/crypto/VerifyKey.ts`) and must not drift from it.
 *
 * Both halves live behind one tag so that an identity stays **one string**: `UserWithPubKey.pubKey`
 * and the bridge's `contextUser.userPubKey` are single fields, and a key compares equal to itself.
 *
 * @param rawAgreementKey empty unless `keyAlgorithmNeedsAgreementKey(algorithm)`
 * @throws UnsupportedKeyAlgorithmException when the algorithm has no encoding of its own
 * @throws MalformedEncryptionKeyException when either half is not the length the algorithm requires
 */
std::string encodeTaggedPublicKey(
    const std::string& rawKey,
    privmx::cryptoservice::AsymAlg algorithm,
    const std::string& rawAgreementKey = ""
);

/**
 * @brief Reads a tagged public key, taking the algorithm from the tag rather than assuming one.
 *
 * @throws MalformedEncryptionKeyException when the encoding, the tag or the length is wrong
 */
TaggedPublicKey decodeTaggedPublicKey(const std::string& base58);

/**
 * @brief Whether a string is a well-formed tagged key, **without building the curve point**.
 *
 * For `Validator::validatePubKeyFormat`, which screens a wholesale list of keys where the operation
 * uses only a handful; the expensive subgroup check happens when a key is actually turned into a point.
 */
bool isTaggedPublicKeyFormat(const std::string& base58);

inline privmx::cryptoservice::BytesView keyBytes(const std::string& data) {
    return privmx::cryptoservice::BytesView(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
}

inline std::string keyString(const privmx::cryptoservice::Bytes& data) {
    return std::string(reinterpret_cast<const char*>(data.data()), data.size());
}

} // namespace core
} // namespace endpoint
} // namespace privmx

#endif // _PRIVMXLIB_ENDPOINT_CORE_CRYPTO_KEYFORMATS_HPP_
