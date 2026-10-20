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

#include <privmx/endpoint/core/ConvertedExceptions.hpp>
#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/crypto/FormatHash.hpp>
#include <privmx/endpoint/core/crypto/KeyFormats.hpp>

using namespace privmx::endpoint::core;

namespace cs = privmx::cryptoservice;

namespace {

struct KeyAlgorithmSpec {
    /**
     * What the identity is called — the value `PublicKey::algorithm()` reports and the tag decodes to.
     *
     * Not always the algorithm of any one of its keys: a composed identity is several keys, and this
     * names the whole. Use `signingAlgorithm` or `agreementAlgorithm` when a half has to be handed
     * to the provider.
     */
    cs::AsymAlg algorithm;
    /**
     * The algorithm of the half that signs.
     *
     * Equal to `algorithm` for a one-key identity. For a composed one it is the only value the
     * provider will accept for the signing key, so importing or deriving that half must use this and
     * never `algorithm` — which may name a construction the provider has no usable key for.
     */
    cs::AsymAlg signingAlgorithm;
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
    /** Length of the raw signing key behind the tag, in bytes. */
    std::size_t publicKeyLength;
    /**
     * The algorithm the identity agrees keys with, when that is not the signing algorithm itself.
     *
     * Ed25519 signs and cannot do Diffie-Hellman, but an identity here has to do both: a container
     * key reaches a member by being wrapped to their public key (`EncKeyEncryptorV2` → ECIES). So an
     * Ed25519 identity is really two keys, and its tagged encoding carries both — signing half first,
     * agreement half second. `NoAlg` means the one key does both jobs, as secp256k1 does.
     */
    cs::AsymAlg agreementAlgorithm;
    /** Length of the raw agreement key, or 0 when there is none. */
    std::size_t agreementKeyLength;
    /**
     * A key-encapsulation algorithm whose secret is mixed into every wrap beside the Diffie-Hellman one.
     *
     * This is what makes an identity post-quantum for **confidentiality**. A KEM is not a
     * Diffie-Hellman: the sender encapsulates against the recipient's public key, getting a secret
     * and a ciphertext it must send along, so the two cannot be interchanged — hence a field of its
     * own rather than another `agreementAlgorithm`.
     *
     * Both secrets go through one KDF, so breaking the wrap means breaking X25519 **and**
     * ML-KEM-768. `NoAlg` means the identity has no post-quantum half and the wrap is the classical
     * one, byte for byte.
     */
    cs::AsymAlg kemAlgorithm;
    /** Length of the raw KEM public key, or 0 when there is none. */
    std::size_t kemKeyLength;
    /**
     * Whether `signatureScheme` already digests the message before signing it.
     *
     * `SigScheme::Compact` is ECDSA over `sha256(m)` — the provider does that hash. Ed25519's
     * `Default` signs the message as given, hashing only inside its own construction. Both have to
     * end up signing the same bytes, because the bridge verifies over a SHA-256 digest either way,
     * so an algorithm that does not digest gets one applied before the key ever sees the message.
     */
    bool schemeDigestsTheMessage;
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
constexpr std::array<KeyAlgorithmSpec, 4> KEY_ALGORITHMS{{
    {cs::AsymAlg::PrivmxSecp256k1, cs::AsymAlg::PrivmxSecp256k1, cs::SigScheme::Compact, 0x81, 33,
     cs::AsymAlg::NoAlg, 0, cs::AsymAlg::NoAlg, 0, true},
    {cs::AsymAlg::secp256k1, cs::AsymAlg::secp256k1, cs::SigScheme::Compact, UNTAGGED, 33,
     cs::AsymAlg::NoAlg, 0, cs::AsymAlg::NoAlg, 0, true},
    {cs::AsymAlg::ED25519, cs::AsymAlg::ED25519, cs::SigScheme::Default, 0x82, 32,
     cs::AsymAlg::X25519, 32, cs::AsymAlg::NoAlg, 0, false},
    // The same identity as 0x82 with an ML-KEM-768 half added, so container keys reach it through a
    // secret that an adversary must break both X25519 and ML-KEM-768 to recover.
    //
    // Signing stays Ed25519 on purpose. The urgent quantum risk here is harvest-now-decrypt-later:
    // a wrapped container key recorded today can be opened by a machine that does not exist yet,
    // while a signature only has to hold while it is being checked. Confidentiality is what needs
    // the post-quantum half first; an ML-DSA signing half is a separate row, and is blocked anyway
    // until pmx-crypto can derive a hybrid signature key from a seed.
    //
    // Named by `X25519MLKEM768` because that is what the key agreement is. It is *our* composition
    // of two primitives, never pmx-crypto's key of that name — that one's `deriveSharedSecret`
    // quietly drops the ML-KEM half and its `encapsulate` throws, so the halves are driven here.
    {cs::AsymAlg::X25519MLKEM768, cs::AsymAlg::ED25519, cs::SigScheme::Default, 0x83, 32,
     cs::AsymAlg::X25519, 32, cs::AsymAlg::MLKEM768, 1184, false},
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

/**
 * The algorithm new identity keys are generated with (level 1 of the choice).
 *
 * Set at build configuration time by `PRIVMX_DEFAULT_KEY_ALGORITHM`, expressed as the algorithm's
 * wire tag so the option and the encoding cannot name different things. It affects **generation
 * only** — `KEY_ALGORITHMS` stays complete whatever this is, because a key says which algorithm it
 * is, and a client built one way must still read keys made the other way.
 */
#ifndef PRIVMX_DEFAULT_KEY_ALGORITHM_TAG
#define PRIVMX_DEFAULT_KEY_ALGORITHM_TAG 0x81
#endif

constexpr cs::AsymAlg algorithmForDefaultTag() {
    for (const auto& spec : KEY_ALGORITHMS) {
        if (spec.keyTag == PRIVMX_DEFAULT_KEY_ALGORITHM_TAG) {
            return spec.algorithm;
        }
    }
    return cs::AsymAlg::NoAlg;
}

/// A build error rather than an exception on the first key generated, if the tag names nothing.
constexpr cs::AsymAlg DEFAULT_ALGORITHM = algorithmForDefaultTag();
static_assert(
    DEFAULT_ALGORITHM != cs::AsymAlg::NoAlg,
    "PRIVMX_DEFAULT_KEY_ALGORITHM_TAG matches no entry in KEY_ALGORITHMS"
);

} // namespace

namespace privmx {
namespace endpoint {
namespace core {

cs::AsymAlg defaultKeyAlgorithm() {
    return DEFAULT_ALGORITHM;
}

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

std::string messageToSignFor(cs::AsymAlg algorithm, const std::string& message) {
    const KeyAlgorithmSpec* spec = findSpec(algorithm);
    if (spec == nullptr) {
        throw UnsupportedKeyAlgorithmException("asymmetric algorithm: " + std::to_string(static_cast<int>(algorithm)));
    }
    return spec->schemeDigestsTheMessage ? message : FormatHash::sha256(message);
}

bool keyAlgorithmNeedsAgreementKey(cs::AsymAlg algorithm) {
    const KeyAlgorithmSpec* spec = findSpec(algorithm);
    return spec != nullptr && spec->agreementAlgorithm != cs::AsymAlg::NoAlg;
}

cs::AsymAlg agreementAlgorithmFor(cs::AsymAlg algorithm) {
    const KeyAlgorithmSpec* spec = findSpec(algorithm);
    if (spec == nullptr || spec->agreementAlgorithm == cs::AsymAlg::NoAlg) {
        throw UnsupportedKeyAlgorithmException(
            "algorithm has no separate agreement key: " + std::to_string(static_cast<int>(algorithm))
        );
    }
    return spec->agreementAlgorithm;
}

cs::AsymAlg signingAlgorithmFor(cs::AsymAlg algorithm) {
    const KeyAlgorithmSpec* spec = findSpec(algorithm);
    if (spec == nullptr) {
        throw UnsupportedKeyAlgorithmException("asymmetric algorithm: " + std::to_string(static_cast<int>(algorithm)));
    }
    return spec->signingAlgorithm;
}

bool keyAlgorithmNeedsKemKey(cs::AsymAlg algorithm) {
    const KeyAlgorithmSpec* spec = findSpec(algorithm);
    return spec != nullptr && spec->kemAlgorithm != cs::AsymAlg::NoAlg;
}

cs::AsymAlg kemAlgorithmFor(cs::AsymAlg algorithm) {
    const KeyAlgorithmSpec* spec = findSpec(algorithm);
    if (spec == nullptr || spec->kemAlgorithm == cs::AsymAlg::NoAlg) {
        throw UnsupportedKeyAlgorithmException(
            "algorithm has no key-encapsulation half: " + std::to_string(static_cast<int>(algorithm))
        );
    }
    return spec->kemAlgorithm;
}

std::string encodeTaggedPublicKey(
    const std::string& rawKey,
    cs::AsymAlg algorithm,
    const std::string& rawAgreementKey,
    const std::string& rawKemKey
) {
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
    if (rawAgreementKey.size() != spec->agreementKeyLength) {
        throw MalformedEncryptionKeyException(
            "agreement key of " + std::to_string(rawAgreementKey.size()) + " bytes, expected " +
            std::to_string(spec->agreementKeyLength)
        );
    }
    if (rawKemKey.size() != spec->kemKeyLength) {
        throw MalformedEncryptionKeyException(
            "KEM key of " + std::to_string(rawKemKey.size()) + " bytes, expected " +
            std::to_string(spec->kemKeyLength)
        );
    }
    // Fixed-length halves in a fixed order, so the split on the way back is by length alone and the
    // encoding needs no separators to get wrong.
    return privmx::utils::Base58::encodeWithChecksum(
        std::string(1, static_cast<char>(spec->keyTag)) + rawKey + rawAgreementKey + rawKemKey,
        FormatHash::sha256
    );
}

namespace {

/// The network byte of a Bitcoin-style WIF. A WIF is a secp256k1 private key by construction, which
/// is why reading one needs no tag and never consults the build's default.
constexpr std::uint8_t WIF_NETWORK_BYTE = 0x80;
constexpr std::size_t IDENTITY_SECRET_LENGTH = 32;

} // namespace

std::string encodePrivateKey(const std::string& secret, cs::AsymAlg algorithm) {
    const KeyAlgorithmSpec* spec = findSpec(algorithm);
    if (spec == nullptr || spec->keyTag == UNTAGGED) {
        throw UnsupportedKeyAlgorithmException(
            "no private key encoding for asymmetric algorithm: " + std::to_string(static_cast<int>(algorithm))
        );
    }
    if (secret.size() != IDENTITY_SECRET_LENGTH) {
        throw MalformedEncryptionKeyException(
            "identity secret of " + std::to_string(secret.size()) + " bytes, expected " +
            std::to_string(IDENTITY_SECRET_LENGTH)
        );
    }
    return privmx::utils::Base58::encodeWithChecksum(
        std::string(1, static_cast<char>(spec->keyTag)) + secret, FormatHash::sha256
    );
}

TaggedPrivateKey decodePrivateKey(const std::string& base58) {
    std::string payload;
    try {
        payload = privmx::utils::Base58::decodeWithChecksum(base58, FormatHash::sha256);
    } catch (...) {
        // Its own code, not the generic malformed-key one: a failed checksum means the key was
        // mistyped or truncated in transit, which is a different thing for a caller to report than a
        // key that decodes cleanly but is of an algorithm or length we cannot use.
        throw privmx::endpoint::crypto::InvalidChecksumException("private key is not valid Base58Check");
    }
    if (payload.empty()) {
        throw MalformedEncryptionKeyException("private key is empty");
    }
    const auto first = static_cast<std::uint8_t>(payload[0]);
    // A WIF: network byte, the secret, and an optional compression flag. It names secp256k1 by being
    // a WIF, so it is read as one on every build — the build's default has no say here.
    if (first == WIF_NETWORK_BYTE &&
        (payload.size() == 1 + IDENTITY_SECRET_LENGTH || payload.size() == 2 + IDENTITY_SECRET_LENGTH)) {
        return TaggedPrivateKey{
            .algorithm = cs::AsymAlg::PrivmxSecp256k1,
            .secret = payload.substr(1, IDENTITY_SECRET_LENGTH),
            .wasWif = true,
        };
    }
    const KeyAlgorithmSpec* spec = findSpecByTag(first);
    if (spec == nullptr || payload.size() != 1 + IDENTITY_SECRET_LENGTH) {
        throw MalformedEncryptionKeyException("private key carries no algorithm this build can read");
    }
    return TaggedPrivateKey{.algorithm = spec->algorithm, .secret = payload.substr(1), .wasWif = false};
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
    const std::size_t expected = spec->publicKeyLength + spec->agreementKeyLength + spec->kemKeyLength;
    if (payload.size() != 1 + expected) {
        throw MalformedEncryptionKeyException(
            "tagged public key of " + std::to_string(payload.size() - 1) + " bytes, expected " +
            std::to_string(expected)
        );
    }
    return TaggedPublicKey{
        .algorithm = spec->algorithm,
        .rawKey = payload.substr(1, spec->publicKeyLength),
        .rawAgreementKey = payload.substr(1 + spec->publicKeyLength, spec->agreementKeyLength),
        .rawKemKey = payload.substr(1 + spec->publicKeyLength + spec->agreementKeyLength),
    };
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
    return spec != nullptr &&
           payload.size() == 1 + spec->publicKeyLength + spec->agreementKeyLength + spec->kemKeyLength;
}

} // namespace core
} // namespace endpoint
} // namespace privmx
