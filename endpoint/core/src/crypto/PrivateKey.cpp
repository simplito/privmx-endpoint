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

// A WIF carries 32 secret bytes and says nothing about the algorithm. It does not need to: it is the
// *private* side, never compared or stored by the bridge, and the public side says which algorithm
// it is through its tag. So the secret is read out and the identity built from it.
PrivateKey PrivateKey::fromWIF(const std::string& wif) {
    return mapCryptoErrors("PrivateKey::fromWIF", [&] {
        if (!keyAlgorithmNeedsAgreementKey(defaultKeyAlgorithm())) {
            return PrivateKey(
                cryptoProvider().importPrivateKey(keyBytes(wif), cs::KeyFormat::Wif, defaultKeyAlgorithm()),
                defaultKeyAlgorithm()
            );
        }
        // The WIF's 32 bytes are the secret; which curve they end up on is this build's choice.
        auto carrier = cryptoProvider().importPrivateKey(
            keyBytes(wif), cs::KeyFormat::Wif, cs::AsymAlg::PrivmxSecp256k1
        );
        return identityFromSecret(keyString(carrier->export_(cs::KeyFormat::Raw)), defaultKeyAlgorithm());
    });
}

PrivateKey PrivateKey::fromRaw(const std::string& raw) {
    return mapCryptoErrors("PrivateKey::fromRaw", [&] {
        return identityFromSecret(raw, defaultKeyAlgorithm());
    });
}

PrivateKey PrivateKey::generateRandom() {
    return mapCryptoErrors("PrivateKey::generateRandom", [&] {
        if (!keyAlgorithmNeedsAgreementKey(defaultKeyAlgorithm())) {
            return PrivateKey(cryptoProvider().generatePrivateKey(defaultKeyAlgorithm()), defaultKeyAlgorithm());
        }
        // Generated through a secret rather than two independent keys, so the identity stays
        // reconstructible from one value — the property `toWIF` depends on.
        return identityFromSecret(
            keyString(cryptoProvider().randomBytes(32)), defaultKeyAlgorithm()
        );
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
            // A composed identity has no single key to export, and pmx-crypto's WIF is EC-only. The
            // secret both halves came from is what a WIF would have to carry anyway, so it goes out
            // through the same encoding — `fromWIF` reads it back and rebuilds the identity.
            require();
            return keyString(
                cryptoProvider()
                    .importPrivateKey(keyBytes(_secret), cs::KeyFormat::Raw, cs::AsymAlg::PrivmxSecp256k1)
                    ->export_(cs::KeyFormat::Wif)
            );
        }
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
