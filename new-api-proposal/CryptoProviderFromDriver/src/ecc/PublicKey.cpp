/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <functional>
#include <memory>
#include <string>
#include <openssl/bn.h>
#include <Poco/SharedPtr.h>

#include "ECC.hpp"
#include "PublicKey.hpp"
#include "Networks.hpp"
#include "Base58.hpp"
#include "Utils.hpp"
// #include "EciesEncryptor.hpp"   // not used - to be removed
#include "PrivateKey.hpp"
// #include "ECIES.hpp"            // not used - to be removed



namespace privmx {
namespace cryptoservice {
namespace ecc {

PublicKey PublicKey::fromDER(const std::string& der) {
    ECC key = ECC::fromPublicKey(der);
    return PublicKey(key);
}

PublicKey PublicKey::fromBase58DER(const std::string& base58) {
    std::string der = Base58::decodeWithChecksum(base58);
    return fromDER(der);
}

PublicKey::PublicKey(const ECC& key) : _key(key) {}

bool PublicKey::operator==(const PublicKey& obj) const {
    return (_key.getPublicKey() == obj._key.getPublicKey());
}

bool PublicKey::operator!=(const PublicKey& obj) const {
    return (_key.getPublicKey() != obj._key.getPublicKey());
}

std::string PublicKey::toDER() const {
    return _key.getPublicKey();
}

std::string PublicKey::toBase58DER() const {
    return Base58::encodeWithChecksum(_key.getPublicKey());
}

std::string PublicKey::toBase58Address() const {
    // std::string hash = Crypto::hash160(_key.getPublicKey());
    std::string hash = NewCrypto::digest(Hash::Hash160, _key.getPublicKey());
    std::string payload = Networks::BITCOIN.PUB_KEY_HASH + hash;
    return Base58::encodeWithChecksum(payload);
}

bool PublicKey::verifyCompactSignature(const std::string& message, const std::string& signature) const {
    return _key.verify(message, signature);
}

bool PublicKey::verifyCompactSignatureWithHash(const std::string& message, const std::string& signature) const {
    // std::string hash = Crypto::sha256(message);
    std::string hash = NewCrypto::digest(Hash::Sha256, message);
    return verifyCompactSignature(hash, signature);
}

bool PublicKey::verify(BytesView data, BytesView signature, SigScheme scheme) const {
    // throw PrivmxDriverCryptoException("PublicKey::verify: NOT IMPLEMENTED");
    switch (scheme) {
    case SigScheme::EcdsaSecp256k1Compact:
        return verifyCompactSignature(Utils::b2s(data), Utils::b2s(signature));
    case SigScheme::EcdsaSecp256k1CompactWithHash:
        return verifyCompactSignatureWithHash(Utils::b2s(data), Utils::b2s(signature));
    default:
        throw PrivmxDriverCryptoException("PublicKey::verify: Unknown signing scheme");
        break;
    }
}

// Bytes PublicKey::seal(BytesView data, const IPrivateKey& senderForSignature) const {
//     // previously EciesEncryptor::encrypt(*this,data,senderForSignature)
//     if (typeid(senderForSignature) != typeid(PrivateKey)) {
//         throw PrivmxDriverCryptoException("PublicKey::seal: Wrong type of private key");
//     }
//     return Utils::s2b(EciesEncryptor::encrypt(*this, Utils::b2s(data), (const PrivateKey&) senderForSignature));
// }
Bytes PublicKey::seal(BytesView data, const IPrivateKey& senderForSignature) const {
    // previously EciesEncryptor::encrypt(*this,data,senderForSignature)
    if (typeid(senderForSignature) != typeid(PrivateKey)) {
        throw PrivmxDriverCryptoException("PublicKey::seal: Wrong type of private key");
    }
    return Utils::s2b(encrypt(Utils::b2s(data), (const PrivateKey&) senderForSignature));
}


Bytes PublicKey::export_(KeyFormat format) const {
    if (format ==  KeyFormat::Wif) {
        throw PrivmxDriverCryptoException("PrivateKey::export_: Format WIF is used only for private keys");    
    } else if (format == KeyFormat::Der) {
        return Utils::s2b(toDER());   // TO BE REPLACED
        // return toDERb();
    } else if (format ==  KeyFormat::Base58Der) {
        return Utils::s2b(toBase58DER());   // TO BE REPLACED
        // return toBase58DERb();
    } else if (format ==  KeyFormat::Base58DerAddr) {
        return Utils::s2b(toBase58Address());   // TO BE REPLACED
        // return toBase58AddressB();
    } else {
        // other formats ...
        throw PrivmxDriverCryptoException("PrivateKey::export_: Unknown data format");    
    }
    throw PrivmxDriverCryptoException("PrivateKey::export_: NOT IMPLEMENTED");
}

void PublicKey::setSymProvider(std::shared_ptr<ISymCryptoProvider> provider) {
    _provider = provider;
}

// from EciesEncryptor class:
std::string PublicKey::encryptObjectToBase64(Poco::JSON::Object::Ptr data, const PrivateKey& privForSignature) const {
    return encryptToBase64(Utils::stringify(data), privForSignature);
}

std::string PublicKey::encryptToBase64(const std::string& data, const PrivateKey& privForSignature) const {
    return Base64::from(encrypt(data, privForSignature));
}

std::string PublicKey::encrypt(const std::string& data, const PrivateKey& privForSignature) const {
    // ECIES ecies(privForSignature, *this);
    // auto cipher = ecies.encrypt(data);
    auto cipher = eciesEncrypt(data, privForSignature);
    return std::string("e")
            .append(privForSignature.getPublicKey().toDER())
            .append(toDER())
            .append(cipher);
}

// from ECIES class:
    std::string PublicKey::eciesEncrypt(const std::string& data, const PrivateKey& private_key) const {
    std::string secret = private_key.derive(*this);
    // _shared_key = Crypto::sha512(secret);
    // std::string _shared_key = NewCrypto::digest(Hash::Sha512,secret);
    std::string _shared_key = Utils::b2s(_provider->digest(Hash::Sha512,Utils::s2b(secret)));
    std::string _private_enc_key = private_key.getPrivateEncKey();

    // string iv = Crypto::hmacSha256(_private_enc_key, data).substr(0, 16);
    // std::string iv = NewCrypto::hmac(Hash::Sha256,_private_enc_key, data).substr(0, 16);
    std::string iv = Utils::b2s(_provider->hmac(Hash::Sha256,Utils::s2b(_private_enc_key), Utils::s2b(data))).substr(0, 16);
    // std::string M = getM();
    std::string M = _shared_key.substr(32, 32);
    // std::string E = getE();
    std::string E = _shared_key.substr(0, 32);
    // string c = iv + Crypto::aes256CbcPkcs7Encrypt(data, E, iv);
    // std::string c = iv + NewCrypto::encrypt({SymAlg::Aes256Cbc, E, iv}, data);
    std::string c = iv + Utils::b2s(_provider->encrypt({SymAlg::Aes256Cbc, Utils::s2b(E), Utils::s2b(iv)}, Utils::s2b(data)));
    // return c + Crypto::hmacSha256(M, c).substr(0, 4);
    // return c + NewCrypto::hmac(Hash::Sha256,M, c).substr(0, 4);
    return c + Utils::b2s(_provider->hmac(Hash::Sha256,Utils::s2b(M), Utils::s2b(c))).substr(0, 4);
}
} // ecc
} // cryptoservice
} // privmx
