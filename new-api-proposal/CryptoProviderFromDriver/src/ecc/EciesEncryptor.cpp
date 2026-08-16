/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

/* Temporary classes to facilitate rewriting 
    from an old implementation to a new one   */


#include <memory>
#include <string>

#include "PublicKey.hpp"
#include "PrivateKey.hpp"
#include "ECIES.hpp"
#include "Base58.hpp"
#include "Utils.hpp"
#include "EciesEncryptor.hpp"

// #include "CryptoProviderFromDriver.hpp"

#include <gmpxx.h>
#include <regex>

namespace privmx {
namespace cryptoservice {
namespace ecc {

Poco::JSON::Object::Ptr EciesEncryptor::decryptObjectFromBase64(const PrivateKey& priv, const std::string& cipher_base64, const std::optional<PublicKey>& pubOfSignature) {
    return Utils::parseJsonObject(decryptFromBase64(priv, cipher_base64, pubOfSignature));
}

std::string EciesEncryptor::decryptFromBase64(const PrivateKey& priv, const std::string& cipher_base64, const std::optional<PublicKey>& pubOfSignature) {
    return decrypt(priv, Base64::toString(cipher_base64), pubOfSignature);
}

std::string EciesEncryptor::decrypt(const PrivateKey& priv, const std::string& cipher, const std::optional<PublicKey>& pubOfSignature) {
    if (cipher.front() != 101 || cipher.size() < 67) {
        // throw InvalidFirstByteOfCipherException();
        throw std::runtime_error("EciesEncryptor: InvalidFirstByteOfCipherException");
    }
    auto external_pub = cipher.substr(1, 33);
    auto my_pub = cipher.substr(34, 33);
    auto external_pub_ec = PublicKey::fromDER(external_pub);
    if(pubOfSignature.has_value() && external_pub_ec != pubOfSignature.value()) {
        // throw GivenPublicKeyDoesNotMatchWithSignatureException();
        throw std::runtime_error("EciesEncryptor: GivenPublicKeyDoesNotMatchWithSignatureException");
    }
    auto my_pub_ec = PublicKey::fromDER(my_pub);
    if (my_pub_ec != priv.getPublicKey()) {
        // throw GivenPrivKeyDoesNotMatchException();
        throw std::runtime_error("EciesEncryptor: GivenPrivKeyDoesNotMatchException");
    }
    ECIES ecies(priv, external_pub_ec);
    auto key = ecies.decrypt(cipher.substr(67));
    return key;
}

std::string EciesEncryptor::decryptV0(const PrivateKey& priv, const PublicKey& pub, const std::string& cipher) {
    ECIES ecies(priv, pub);
    return ecies.decrypt(cipher);
}

std::string EciesEncryptor::encryptObjectToBase64(const PublicKey& pub, Poco::JSON::Object::Ptr data, const PrivateKey& privForSignature) {
    return encryptToBase64(pub, Utils::stringify(data), privForSignature);
}

std::string EciesEncryptor::encryptToBase64(const PublicKey& pub, const std::string& data, const PrivateKey& privForSignature) {
    return Base64::from(encrypt(pub, data, privForSignature));
}

std::string EciesEncryptor::encrypt(const PublicKey& pub, const std::string& data, const PrivateKey& privForSignature) {
    ECIES ecies(privForSignature, pub);
    auto cipher = ecies.encrypt(data);
    return std::string("e")
            .append(privForSignature.getPublicKey().toDER())
            .append(pub.toDER())
            .append(cipher);
}

} // ecc
} // cryptoservice
} // privmx
