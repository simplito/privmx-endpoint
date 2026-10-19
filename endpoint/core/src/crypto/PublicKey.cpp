/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/cryptoservice/base/CoreTypes.hpp>

#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/crypto/CryptoErrors.hpp>
#include <privmx/endpoint/core/crypto/KeyFormats.hpp>
#include <privmx/endpoint/core/crypto/ProviderAccess.hpp>
#include <privmx/endpoint/core/crypto/PublicKey.hpp>

using namespace privmx::endpoint::core;

namespace cs = privmx::cryptoservice;

PublicKey PublicKey::fromBase58DER(const std::string& base58DER) {
    return mapCryptoErrors("PublicKey::fromBase58DER", [&] {
        // The algorithm comes from the key's own tag, never from a default. An untagged key — the
        // encoding used before the 3.0.0 cut — is refused by `decodeTaggedPublicKey` rather than
        // guessed at, which is also what the bridge does with one.
        const TaggedPublicKey tagged = decodeTaggedPublicKey(base58DER);
        if (!keyAlgorithmNeedsAgreementKey(tagged.algorithm)) {
            return PublicKey(
                cryptoProvider().importPublicKey(keyBytes(tagged.rawKey), cs::KeyFormat::Der, tagged.algorithm),
                tagged.algorithm
            );
        }
        // Two halves behind one tag: the one that verifies signatures, then the one keys are wrapped to.
        return PublicKey(
            cryptoProvider().importPublicKey(keyBytes(tagged.rawKey), cs::KeyFormat::Raw, tagged.algorithm),
            tagged.algorithm,
            cryptoProvider().importPublicKey(
                keyBytes(tagged.rawAgreementKey), cs::KeyFormat::Raw, agreementAlgorithmFor(tagged.algorithm)
            )
        );
    });
}

PublicKey PublicKey::fromDER(const std::string& der) {
    // Two lengths, because the old implementation accepted both and external data (e.g. a key
    // extracted from a PGP block) arrives uncompressed.
    //
    //   33 B — compressed form, PrivMX's data format
    //   65 B — uncompressed form; `PrivmxSecp256k1` does not accept it, so the import goes through
    //          plain `secp256k1` + `Raw`. The export returns the compressed form either way, so the
    //          caller sees no difference.
    //   64 B — a composed identity, `ed25519(32) || x25519(32)`; see `toDER`.
    constexpr std::size_t COMPRESSED_LENGTH = 33;
    constexpr std::size_t UNCOMPRESSED_LENGTH = 65;
    constexpr std::size_t COMPOSED_LENGTH = 64;
    return mapCryptoErrors("PublicKey::fromDER", [&] {
        if (der.size() == COMPOSED_LENGTH) {
            constexpr std::size_t HALF = COMPOSED_LENGTH / 2;
            return PublicKey(
                cryptoProvider().importPublicKey(
                    keyBytes(der.substr(0, HALF)), cs::KeyFormat::Raw, cs::AsymAlg::ED25519
                ),
                cs::AsymAlg::ED25519,
                cryptoProvider().importPublicKey(
                    keyBytes(der.substr(HALF)), cs::KeyFormat::Raw, cs::AsymAlg::X25519
                )
            );
        }
        if (der.size() == UNCOMPRESSED_LENGTH) {
            // A different algorithm as `pmx-crypto` sees it (same curve, different data format), so
            // the key records that one — operations on it must follow the format it was read in.
            return PublicKey(
                cryptoProvider().importPublicKey(keyBytes(der), cs::KeyFormat::Raw, cs::AsymAlg::secp256k1),
                cs::AsymAlg::secp256k1
            );
        }
        if (der.size() != COMPRESSED_LENGTH) {
            throw MalformedEncryptionKeyException(
                "public key DER of unexpected length: " + std::to_string(der.size())
            );
        }
        // secp256k1 by definition, not by this build's default: a 33-byte compressed point is one of
        // that curve's encodings and nothing else's. Reading it as whatever the build happens to
        // generate made a secp256k1 key unparseable under an Ed25519 build — which is exactly what the
        // handshake does with its transport key.
        return PublicKey(
            cryptoProvider().importPublicKey(keyBytes(der), cs::KeyFormat::Der, cs::AsymAlg::PrivmxSecp256k1),
            cs::AsymAlg::PrivmxSecp256k1
        );
    });
}

const cs::IPublicKey& PublicKey::require() const {
    if (_key == nullptr) {
        throw MalformedEncryptionKeyException("operation on an empty public key");
    }
    return *_key;
}

bool PublicKey::operator==(const PublicKey& other) const {
    if (empty() || other.empty()) {
        return empty() && other.empty();
    }
    return toBase58DER() == other.toBase58DER();
}

std::string PublicKey::toDER() const {
    return mapCryptoErrors("PublicKey::toDER", [&] {
        if (_agreementKey == nullptr) {
            return keyString(require().export_(cs::KeyFormat::Der));
        }
        // A composed identity has no DER of its own — pmx-crypto does not implement one for 25519 —
        // and it would be the wrong shape anyway, being two keys. Its binary form is the same bytes
        // the tagged encoding carries, without the tag: `ed25519(32) || x25519(32)`. The length
        // tells it apart from the 33- and 65-byte secp256k1 forms, which is what `fromDER` keys on.
        return keyString(require().export_(cs::KeyFormat::Raw)) +
               keyString(_agreementKey->export_(cs::KeyFormat::Raw));
    });
}

std::string PublicKey::toBase58DER() const {
    return mapCryptoErrors("PublicKey::toBase58DER", [&] {
        // Built from the DER export rather than asking the provider for `Base58Der`, because the tag
        // has to go **inside** the Base58Check payload — a checksum over untagged bytes would not
        // cover the tag. A key imported as `secp256k1` (uncompressed) exports compressed and is
        // encoded under the one secp256k1 tag, so a key has exactly one spelling either way.
        const cs::AsymAlg algorithm =
            _algorithm == cs::AsymAlg::secp256k1 ? cs::AsymAlg::PrivmxSecp256k1 : _algorithm;
        if (!keyAlgorithmNeedsAgreementKey(algorithm)) {
            return encodeTaggedPublicKey(keyString(require().export_(cs::KeyFormat::Der)), algorithm);
        }
        if (_agreementKey == nullptr) {
            throw MalformedEncryptionKeyException(
                "an identity of this algorithm needs an agreement key and carries none"
            );
        }
        return encodeTaggedPublicKey(
            keyString(require().export_(cs::KeyFormat::Raw)),
            algorithm,
            keyString(_agreementKey->export_(cs::KeyFormat::Raw))
        );
    });
}

bool PublicKey::verifyCompactSignatureWithHash(const std::string& message, const std::string& signature) const {
    return mapCryptoErrors("PublicKey::verifyCompactSignatureWithHash", [&] {
        // The scheme comes from **this** key's algorithm, not from a constant: a user's key may be
        // of any algorithm, and verifying with the wrong scheme would reject valid signatures.
        const std::string signed_ = messageToSignFor(_algorithm, message);
        return require().verify(keyBytes(signed_), keyBytes(signature), signatureSchemeFor(_algorithm));
    });
}
