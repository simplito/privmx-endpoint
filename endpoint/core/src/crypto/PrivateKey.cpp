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
#include <privmx/endpoint/core/crypto/PrivateKey.hpp>
#include <privmx/endpoint/core/crypto/ProviderAccess.hpp>

using namespace privmx::endpoint::core;

namespace cs = privmx::cryptoservice;

namespace {

/**
 * Builds an identity out of one secret.
 *
 * An algorithm that signs and agrees keys with the same key — secp256k1 — gets that one key. One
 * that only signs gets a second, key-agreement key beside it, derived from a domain-separated
 * sub-secret of the same 32 bytes. That is what keeps an identity a single private key: a WIF still
 * carries everything needed to rebuild it.
 */
constexpr std::size_t IDENTITY_SECRET_LENGTH = 32;

PrivateKey identityFromSecret(const std::string& secret, cs::AsymAlg algorithm) {
    if (!keyAlgorithmNeedsAgreementKey(algorithm)) {
        return PrivateKey(
            cryptoProvider().importPrivateKey(keyBytes(secret), cs::KeyFormat::Raw, algorithm), algorithm
        );
    }
    // Checked rather than left to the KDF: `deriveIdentitySeed` hashes whatever it is given into 32
    // bytes, so without this a one-byte "secret" would quietly become a perfectly valid identity.
    // The one-key path gets this check from the provider, which rejects a wrong-sized scalar.
    if (secret.size() != IDENTITY_SECRET_LENGTH) {
        throw MalformedEncryptionKeyException(
            "identity secret of " + std::to_string(secret.size()) + " bytes, expected " +
            std::to_string(IDENTITY_SECRET_LENGTH)
        );
    }
    return PrivateKey(
        cryptoProvider().privateKeyFromSeed(keyBytes(deriveIdentitySeed(secret, false)), algorithm),
        algorithm,
        cryptoProvider().privateKeyFromSeed(
            keyBytes(deriveIdentitySeed(secret, true)), agreementAlgorithmFor(algorithm)
        ),
        secret
    );
}

} // namespace

// The algorithm comes from the key, never from this build. A build option picks what *new* keys are
// made of; it must not decide whether an existing key can be used at all, or the same private key
// would be a different identity — or none — depending on how the library happened to be configured.
PrivateKey PrivateKey::fromWIF(const std::string& wif) {
    return mapCryptoErrors("PrivateKey::fromWIF", [&] {
        const TaggedPrivateKey decoded = decodePrivateKey(wif);
        if (decoded.wasWif) {
            // Imported through the provider rather than from the decoded secret, so a WIF keeps
            // round-tripping to exactly the string it came from, compression flag and all.
            return PrivateKey(
                cryptoProvider().importPrivateKey(keyBytes(wif), cs::KeyFormat::Wif, decoded.algorithm),
                decoded.algorithm
            );
        }
        return identityFromSecret(decoded.secret, decoded.algorithm);
    });
}

PrivateKey PrivateKey::fromRaw(const std::string& raw) {
    return fromRaw(raw, defaultKeyAlgorithm());
}

PrivateKey PrivateKey::fromRaw(const std::string& raw, cs::AsymAlg algorithm) {
    return mapCryptoErrors("PrivateKey::fromRaw", [&] { return identityFromSecret(raw, algorithm); });
}

PrivateKey PrivateKey::generateRandom() {
    return generateRandom(defaultKeyAlgorithm());
}

PrivateKey PrivateKey::generateRandom(cs::AsymAlg algorithm) {
    return mapCryptoErrors("PrivateKey::generateRandom", [&] {
        if (!keyAlgorithmNeedsAgreementKey(algorithm)) {
            return PrivateKey(cryptoProvider().generatePrivateKey(algorithm), algorithm);
        }
        // Generated through a secret rather than two independent keys, so the identity stays
        // reconstructible from one value — the property `toWIF` depends on.
        return identityFromSecret(keyString(cryptoProvider().randomBytes(32)), algorithm);
    });
}

const cs::IPrivateKey& PrivateKey::require() const {
    if (_key == nullptr) {
        throw MalformedEncryptionKeyException("operation on an empty private key");
    }
    return *_key;
}

PublicKey PrivateKey::getPublicKey() const {
    // The public key inherits its private half's algorithm — otherwise a signature made with one
    // would be verified under the other's scheme — and both halves, so it can be wrapped to.
    return mapCryptoErrors("PrivateKey::getPublicKey", [&] {
        return PublicKey(
            require().publicKey(),
            _algorithm,
            _agreementKey != nullptr ? _agreementKey->publicKey() : nullptr
        );
    });
}

std::string PrivateKey::getPrivateEncKey() const {
    return mapCryptoErrors("PrivateKey::getPrivateEncKey", [&] {
        if (!_secret.empty()) {
            // The 32 secret bytes, same as for a one-key identity: this is what callers use as a
            // symmetric key or feed back to `fromRaw`, and for a composed identity the secret is the
            // only value that stands for the whole of it.
            require();
            return _secret;
        }
        return keyString(require().export_(cs::KeyFormat::Raw));
    });
}

std::string PrivateKey::toWIF() const {
    return mapCryptoErrors("PrivateKey::toWIF", [&] {
        if (!_secret.empty()) {
            // A composed identity has no single key to export, and pmx-crypto's WIF is EC-only, so it
            // goes out in the tagged encoding instead. That is also what makes it readable anywhere:
            // the tag says which algorithm the secret is for, so any build can rebuild this identity.
            require();
            return encodePrivateKey(_secret, _algorithm);
        }
        // secp256k1 stays a plain WIF. A WIF already names the curve by being one, so it is as
        // self-describing as a tagged key, and keeping it means existing keys and configs still work.
        return keyString(require().export_(cs::KeyFormat::Wif));
    });
}

std::string PrivateKey::signToCompactSignatureWithHash(const std::string& message) const {
    return mapCryptoErrors("PrivateKey::signToCompactSignatureWithHash", [&] {
        const std::string toSign = messageToSignFor(_algorithm, message);
        return keyString(require().sign(keyBytes(toSign), signatureSchemeFor(_algorithm)));
    });
}

std::string PrivateKey::derive(const PublicKey& publicKey) const {
    return mapCryptoErrors("PrivateKey::derive", [&] {
        if (publicKey.empty()) {
            throw MalformedEncryptionKeyException("cannot derive against an empty public key");
        }
        return keyString(agreementImpl()->deriveSharedSecret(*publicKey.agreementImpl()));
    });
}
