#include <privmx/crypto/CryptoException.hpp>
#include <privmx/crypto/ecc/ECIES.hpp>
#include <privmx/crypto/EciesEncryptor.hpp>
#include <privmx/utils/Utils.hpp>

using namespace privmx;
using namespace privmx::crypto;
using namespace privmx::utils;
using namespace std;

Poco::JSON::Object::Ptr EciesEncryptor::decryptObjectFromBase64(const PrivateKey& priv, const string& cipher_base64) {
    return Utils::parseJsonObject(decryptFromBase64(priv, cipher_base64));
}

string EciesEncryptor::decryptFromBase64(const PrivateKey& priv, const string& cipher_base64) {
    return decrypt(priv, Base64::toString(cipher_base64));
}

string EciesEncryptor::decrypt(const PrivateKey& priv, const string& cipher) {
    if (cipher.front() != 101 || cipher.size() < 67) {
        throw InvalidFirstByteOfCipherException();
    }
    auto external_pub = cipher.substr(1, 33);
    auto my_pub = cipher.substr(34, 33);
    auto external_pub_ec = PublicKey::fromDER(external_pub);
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

string EciesEncryptor::encryptObjectToBase64(const PublicKey& pub, Poco::JSON::Object::Ptr data) {
    return encryptToBase64(pub, Utils::stringify(data));
}

string EciesEncryptor::encryptToBase64(const PublicKey& pub, const string& data) {
    return Base64::from(encrypt(pub, data));
}

string EciesEncryptor::encrypt(const PublicKey& pub, const string& data) {
    auto priv = PrivateKey::generateRandom();
    ECIES ecies(priv, pub);
    auto cipher = ecies.encrypt(data);
    return string("e")
            .append(priv.getPublicKey().toDER())
            .append(pub.toDER())
            .append(cipher);
}
