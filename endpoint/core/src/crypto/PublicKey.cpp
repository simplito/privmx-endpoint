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
#include <privmx/endpoint/core/crypto/ProviderAccess.hpp>
#include <privmx/endpoint/core/crypto/PublicKey.hpp>

using namespace privmx::endpoint::core;

namespace cs = privmx::cryptoservice;

PublicKey PublicKey::fromBase58DER(const std::string& base58DER) {
    return PublicKey(cryptoProvider().importPublicKey(keyBytes(base58DER), cs::KeyFormat::Base58Der, KEY_ALGORITHM));
}

PublicKey PublicKey::fromDER(const std::string& der) {
    return PublicKey(cryptoProvider().importPublicKey(keyBytes(der), cs::KeyFormat::Der, KEY_ALGORITHM));
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
    return keyString(require().export_(cs::KeyFormat::Der));
}

std::string PublicKey::toBase58DER() const {
    return keyString(require().export_(cs::KeyFormat::Base58Der));
}

bool PublicKey::verifyCompactSignatureWithHash(const std::string& message, const std::string& signature) const {
    return require().verify(keyBytes(message), keyBytes(signature), SIGNATURE_SCHEME);
}
