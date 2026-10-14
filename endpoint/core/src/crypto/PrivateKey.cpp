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

// WIF i postac surowa nie nazywaja dzis swojego algorytmu - otagowane kodowanie czeka na uzgodnienie
// z Bridge'em (crypto-update/issue-bridge-crypto-agility.md §3). Import zaklada wiec algorytm domyslny,
// ale zapamietuje go na kluczu: gdy kodowanie zacznie go niesc, zmienia sie tylko te trzy funkcje.
PrivateKey PrivateKey::fromWIF(const std::string& wif) {
    return mapCryptoErrors("PrivateKey::fromWIF", [&] {
        return PrivateKey(
            cryptoProvider().importPrivateKey(keyBytes(wif), cs::KeyFormat::Wif, DEFAULT_KEY_ALGORITHM),
            DEFAULT_KEY_ALGORITHM
        );
    });
}

PrivateKey PrivateKey::fromRaw(const std::string& raw) {
    return mapCryptoErrors("PrivateKey::fromRaw", [&] {
        return PrivateKey(
            cryptoProvider().importPrivateKey(keyBytes(raw), cs::KeyFormat::Raw, DEFAULT_KEY_ALGORITHM),
            DEFAULT_KEY_ALGORITHM
        );
    });
}

PrivateKey PrivateKey::generateRandom() {
    return mapCryptoErrors("PrivateKey::generateRandom", [&] {
        return PrivateKey(cryptoProvider().generatePrivateKey(DEFAULT_KEY_ALGORITHM), DEFAULT_KEY_ALGORITHM);
    });
}

const cs::IPrivateKey& PrivateKey::require() const {
    if (_key == nullptr) {
        throw MalformedEncryptionKeyException("operation on an empty private key");
    }
    return *_key;
}

PublicKey PrivateKey::getPublicKey() const {
    // Klucz publiczny dziedziczy algorytm swojej polowy prywatnej - inaczej podpis zlozony jednym
    // weryfikowalby sie drugim schematem.
    return mapCryptoErrors("PrivateKey::getPublicKey", [&] {
        return PublicKey(require().publicKey(), _algorithm);
    });
}

std::string PrivateKey::getPrivateEncKey() const {
    return mapCryptoErrors("PrivateKey::getPrivateEncKey", [&] {
        return keyString(require().export_(cs::KeyFormat::Raw));
    });
}

std::string PrivateKey::toWIF() const {
    return mapCryptoErrors("PrivateKey::toWIF", [&] { return keyString(require().export_(cs::KeyFormat::Wif)); });
}

std::string PrivateKey::signToCompactSignatureWithHash(const std::string& message) const {
    return mapCryptoErrors("PrivateKey::signToCompactSignatureWithHash", [&] {
        return keyString(require().sign(keyBytes(message), signatureSchemeFor(_algorithm)));
    });
}

std::string PrivateKey::derive(const PublicKey& publicKey) const {
    return mapCryptoErrors("PrivateKey::derive", [&] {
        if (publicKey.empty()) {
            throw MalformedEncryptionKeyException("cannot derive against an empty public key");
        }
        return keyString(require().deriveSharedSecret(*publicKey.impl()));
    });
}
