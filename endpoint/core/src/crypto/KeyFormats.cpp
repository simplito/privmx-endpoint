/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <array>
#include <cstddef>
#include <cstdint>

#include <privmx/utils/Base58.hpp>

#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/crypto/FormatHash.hpp>
#include <privmx/endpoint/core/crypto/KeyFormats.hpp>

using namespace privmx::endpoint::core;

namespace cs = privmx::cryptoservice;

namespace {

struct KeyAlgorithmSpec {
    cs::AsymAlg algorithm;
    cs::SigScheme signatureScheme;
    /**
     * The algorithm's byte in the tagged public-key encoding, or `UNTAGGED` when the algorithm has no
     * encoding of its own.
     *
     * `secp256k1` gets `UNTAGGED` rather than a second tag: it is the same curve as `PrivmxSecp256k1`,
     * reached only by importing an uncompressed point, and an export always comes back compressed. One
     * curve, one tag — or a key would have two spellings and no longer compare equal to itself.
     */
    std::uint8_t keyTag;
    /** Length of the raw key behind the tag, in bytes. */
    std::size_t publicKeyLength;
};

constexpr std::uint8_t UNTAGGED = 0x00;

/**
 * The identity-key algorithms the endpoint works with.
 *
 * Users' keys may be of any algorithm, so this is a registry of **support**, not of choice: an entry
 * here means "we can sign and verify with such a key". Adding Ed25519 will be one more row.
 *
 * `PrivmxSecp256k1` and `secp256k1` are the same curve in two data formats — both sign identically.
 * The second one only shows up when importing an uncompressed public key.
 *
 * The tags are shared wire format with the bridge (`src/utils/crypto/VerifyKey.ts`) and must not drift.
 * They sit at 0x80 and above, where a SEC1 point prefix cannot be (0x02/0x03 compressed, 0x04/0x06/0x07
 * uncompressed), so a key in the old untagged encoding fails as an unknown tag instead of being misread.
 */
constexpr std::array<KeyAlgorithmSpec, 2> KEY_ALGORITHMS{{
    {cs::AsymAlg::PrivmxSecp256k1, cs::SigScheme::Compact, 0x81, 33},
    {cs::AsymAlg::secp256k1, cs::SigScheme::Compact, UNTAGGED, 33},
}};

const KeyAlgorithmSpec* findSpecByTag(std::uint8_t tag) {
    if (tag == UNTAGGED) {
        return nullptr;
    }
    for (const auto& spec : KEY_ALGORITHMS) {
        if (spec.keyTag == tag) {
            return &spec;
        }
    }
    return nullptr;
}

const KeyAlgorithmSpec* findSpec(cs::AsymAlg algorithm) {
    for (const auto& spec : KEY_ALGORITHMS) {
        if (spec.algorithm == algorithm) {
            return &spec;
        }
    }
    return nullptr;
}

constexpr bool defaultAlgorithmIsSupported() {
    for (const auto& spec : KEY_ALGORITHMS) {
        if (spec.algorithm == DEFAULT_KEY_ALGORITHM) {
            return true;
        }
    }
    return false;
}
static_assert(defaultAlgorithmIsSupported(), "DEFAULT_KEY_ALGORITHM has no entry in KEY_ALGORITHMS");

} // namespace

namespace privmx {
namespace endpoint {
namespace core {

bool isSupportedKeyAlgorithm(cs::AsymAlg algorithm) {
    return findSpec(algorithm) != nullptr;
}

cs::SigScheme signatureSchemeFor(cs::AsymAlg algorithm) {
    const KeyAlgorithmSpec* spec = findSpec(algorithm);
    if (spec == nullptr) {
        throw UnsupportedKeyAlgorithmException("asymmetric algorithm: " + std::to_string(static_cast<int>(algorithm)));
    }
    return spec->signatureScheme;
}

std::string encodeTaggedPublicKey(const std::string& rawKey, cs::AsymAlg algorithm) {
    const KeyAlgorithmSpec* spec = findSpec(algorithm);
    if (spec == nullptr || spec->keyTag == UNTAGGED) {
        // `secp256k1` lands here: it is an import-only spelling of `PrivmxSecp256k1`, and the caller is
        // expected to have normalised it before asking for an encoding.
        throw UnsupportedKeyAlgorithmException(
            "no tagged encoding for asymmetric algorithm: " + std::to_string(static_cast<int>(algorithm))
        );
    }
    if (rawKey.size() != spec->publicKeyLength) {
        throw MalformedEncryptionKeyException(
            "public key of " + std::to_string(rawKey.size()) + " bytes, expected " +
            std::to_string(spec->publicKeyLength)
        );
    }
    return privmx::utils::Base58::encodeWithChecksum(
        std::string(1, static_cast<char>(spec->keyTag)) + rawKey, FormatHash::sha256
    );
}

TaggedPublicKey decodeTaggedPublicKey(const std::string& base58) {
    std::string payload;
    try {
        payload = privmx::utils::Base58::decodeWithChecksum(base58, FormatHash::sha256);
    } catch (...) {
        throw MalformedEncryptionKeyException("public key is not valid Base58Check");
    }
    if (payload.empty()) {
        throw MalformedEncryptionKeyException("public key is empty");
    }
    const KeyAlgorithmSpec* spec = findSpecByTag(static_cast<std::uint8_t>(payload[0]));
    if (spec == nullptr) {
        // Deliberately not a fallback to "assume secp256k1": the old untagged encoding is no longer
        // accepted, so a key from before the cut fails here by name instead of being guessed at.
        throw MalformedEncryptionKeyException(
            "unknown public key tag: 0x" + std::to_string(static_cast<int>(static_cast<std::uint8_t>(payload[0])))
        );
    }
    if (payload.size() != 1 + spec->publicKeyLength) {
        throw MalformedEncryptionKeyException(
            "tagged public key of " + std::to_string(payload.size() - 1) + " bytes, expected " +
            std::to_string(spec->publicKeyLength)
        );
    }
    return TaggedPublicKey{.algorithm = spec->algorithm, .rawKey = payload.substr(1)};
}

bool isTaggedPublicKeyFormat(const std::string& base58) {
    std::string payload;
    try {
        payload = privmx::utils::Base58::decodeWithChecksum(base58, FormatHash::sha256);
    } catch (...) {
        return false;
    }
    if (payload.empty()) {
        return false;
    }
    const KeyAlgorithmSpec* spec = findSpecByTag(static_cast<std::uint8_t>(payload[0]));
    return spec != nullptr && payload.size() == 1 + spec->publicKeyLength;
}

} // namespace core
} // namespace endpoint
} // namespace privmx
