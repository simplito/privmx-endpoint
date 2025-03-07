/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/crypto/CryptoException.hpp>
#include <privmx/crypto/ecc/ECIES.hpp>
#include <privmx/crypto/EciesEncryptor.hpp>
#include <privmx/utils/Utils.hpp>

using namespace privmx;
using namespace privmx::crypto;
using namespace privmx::utils;
using namespace std;

Poco::JSON::Object::Ptr EciesEncryptor::decryptObjectFromBase64(const PrivateKey& priv, const string& cipher_base64, const std::optional<PublicKey>& pubOfSignature) {
    return Utils::parseJsonObject(decryptFromBase64(priv, cipher_base64, pubOfSignature));
}

string EciesEncryptor::decryptFromBase64(const PrivateKey& priv, const string& cipher_base64, const std::optional<PublicKey>& pubOfSignature) {
    return decrypt(priv, Base64::toString(cipher_base64), pubOfSignature);
}

string EciesEncryptor::decrypt(const PrivateKey& priv, const string& cipher, const std::optional<PublicKey>& pubOfSignature) {
    if (cipher.front() != 101 || cipher.size() < 67) {
        throw InvalidFirstByteOfCipherException();
    }
    auto external_pub = cipher.substr(1, 33);
    auto my_pub = cipher.substr(34, 33);
    auto external_pub_ec = PublicKey::fromDER(external_pub);
    if(pubOfSignature.has_value() && external_pub_ec == pubOfSignature.value()) {
        throw GivenPubKeyDoesNotMatchException();
    }
    auto my_pub_ec = PublicKey::fromDER(my_pub);
    if (my_pub_ec != priv.getPublicKey()) {
        throw GivenPrivKeyDoesNotMatchException();
    }
    ECIES ecies(priv, external_pub_ec);
    auto key = ecies.decrypt(cipher.substr(67));
    return key;
}

string EciesEncryptor::decryptV0(const PrivateKey& priv, const PublicKey& pub, const string& cipher) {
    ECIES ecies(priv, pub);
    return ecies.decrypt(cipher);
}

string EciesEncryptor::encryptObjectToBase64(const PublicKey& pub, Poco::JSON::Object::Ptr data, const std::optional<PrivateKey>& privForSignature) {
    return encryptToBase64(pub, Utils::stringify(data), privForSignature);
}

string EciesEncryptor::encryptToBase64(const PublicKey& pub, const string& data, const std::optional<PrivateKey>& privForSignature) {
    return Base64::from(encrypt(pub, data, privForSignature));
}

string EciesEncryptor::encrypt(const PublicKey& pub, const string& data, const std::optional<PrivateKey>& privForSignature) {
    auto priv = privForSignature.has_value() ? privForSignature.value() : PrivateKey::generateRandom();
    ECIES ecies(privForSignature.value(), pub);
    auto cipher = ecies.encrypt(data);
    return string("e")
            .append(priv.getPublicKey().toDER())
            .append(pub.toDER())
            .append(cipher);
}
