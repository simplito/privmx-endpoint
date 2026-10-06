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
#include <privmx/endpoint/core/crypto/KeyFormats.hpp>
#include <privmx/endpoint/core/crypto/PrivateKey.hpp>
#include <privmx/endpoint/core/crypto/ProviderAccess.hpp>

using namespace privmx::endpoint::core;

namespace cs = privmx::cryptoservice;

PrivateKey PrivateKey::fromWIF(const std::string& wif) {
    return PrivateKey(cryptoProvider().importPrivateKey(keyBytes(wif), cs::KeyFormat::Wif, KEY_ALGORITHM));
}

PrivateKey PrivateKey::fromRaw(const std::string& raw) {
    return PrivateKey(cryptoProvider().importPrivateKey(keyBytes(raw), cs::KeyFormat::Raw, KEY_ALGORITHM));
}

PrivateKey PrivateKey::generateRandom() {
    return PrivateKey(cryptoProvider().generatePrivateKey(KEY_ALGORITHM));
}

const cs::IPrivateKey& PrivateKey::require() const {
    if (_key == nullptr) {
        throw MalformedEncryptionKeyException("operation on an empty private key");
    }
    return *_key;
}

PublicKey PrivateKey::getPublicKey() const {
    return PublicKey(require().publicKey());
}

std::string PrivateKey::getPrivateEncKey() const {
    return keyString(require().export_(cs::KeyFormat::Raw));
}

std::string PrivateKey::toWIF() const {
    return keyString(require().export_(cs::KeyFormat::Wif));
}

std::string PrivateKey::signToCompactSignatureWithHash(const std::string& message) const {
    return keyString(require().sign(keyBytes(message), SIGNATURE_SCHEME));
}

std::string PrivateKey::derive(const PublicKey& publicKey) const {
    if (publicKey.empty()) {
        throw MalformedEncryptionKeyException("cannot derive against an empty public key");
    }
    return keyString(require().deriveSharedSecret(*publicKey.impl()));
}
