/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/cryptoservice/base/CoreTypes.hpp>
#include <privmx/utils/Utils.hpp>

#include <privmx/endpoint/core/CoreException.hpp>
#include <privmx/endpoint/core/crypto/CryptoErrors.hpp>
#include <privmx/endpoint/core/crypto/Ecies.hpp>
#include <privmx/endpoint/core/crypto/KeyFormats.hpp>

using namespace privmx::endpoint::core;

std::string Ecies::encrypt(const PublicKey& pub, const std::string& data, const PrivateKey& privForSignature) {
    return mapCryptoErrors("Ecies::encrypt", [&] {
        if (pub.empty() || privForSignature.empty()) {
            throw MalformedEncryptionKeyException("ecies encrypt with an empty key");
        }
        return keyString(pub.impl()->seal(keyBytes(data), *privForSignature.impl()));
    });
}

std::string Ecies::decrypt(
    const PrivateKey& priv,
    const std::string& cipher,
    const std::optional<PublicKey>& pubOfSignature
) {
    return mapCryptoErrors("Ecies::decrypt", [&] {
        if (priv.empty()) {
            throw MalformedEncryptionKeyException("ecies decrypt with an empty key");
        }
        if (pubOfSignature.has_value() && pubOfSignature->empty()) {
            throw MalformedEncryptionKeyException("ecies decrypt against an empty signer key");
        }
        const privmx::cryptoservice::IPublicKey* expectedSender =
            pubOfSignature.has_value() ? pubOfSignature->impl().get() : nullptr;
        return keyString(priv.impl()->open(keyBytes(cipher), expectedSender));
    });
}

std::string Ecies::encryptToBase64(
    const PublicKey& pub,
    const std::string& data,
    const PrivateKey& privForSignature
) {
    return privmx::utils::Base64::from(encrypt(pub, data, privForSignature));
}

std::string Ecies::decryptFromBase64(
    const PrivateKey& priv,
    const std::string& cipherBase64,
    const std::optional<PublicKey>& pubOfSignature
) {
    return decrypt(priv, privmx::utils::Base64::toString(cipherBase64), pubOfSignature);
}

std::string Ecies::encryptObjectToBase64(
    const PublicKey& pub,
    Poco::JSON::Object::Ptr data,
    const PrivateKey& privForSignature
) {
    return encryptToBase64(pub, privmx::utils::Utils::stringify(data), privForSignature);
}

Poco::JSON::Object::Ptr Ecies::decryptObjectFromBase64(
    const PrivateKey& priv,
    const std::string& cipherBase64,
    const std::optional<PublicKey>& pubOfSignature
) {
    return privmx::utils::Utils::parseJsonObject(decryptFromBase64(priv, cipherBase64, pubOfSignature));
}
