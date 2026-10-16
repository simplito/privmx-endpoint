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
 */
constexpr privmx::cryptoservice::AsymAlg DEFAULT_KEY_ALGORITHM = privmx::cryptoservice::AsymAlg::PrivmxSecp256k1;

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

/// @brief A public key as it travels: the algorithm its tag named, and the bytes behind the tag.
struct TaggedPublicKey {
    privmx::cryptoservice::AsymAlg algorithm;
    std::string rawKey;
};

/**
 * @brief Encodes a public key as `Base58Check(tag || rawKey)`.
 *
 * This is the only encoding a key travels in. It exists because a key has to say which algorithm it
 * is — contract point 2 — and because the bridge now refuses anything untagged. The tags are shared
 * wire format with the bridge (`src/utils/crypto/VerifyKey.ts`) and must not drift from it.
 *
 * @throws UnsupportedKeyAlgorithmException when the algorithm has no encoding of its own
 * @throws MalformedEncryptionKeyException when the raw key is not the length the algorithm requires
 */
std::string encodeTaggedPublicKey(const std::string& rawKey, privmx::cryptoservice::AsymAlg algorithm);

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
