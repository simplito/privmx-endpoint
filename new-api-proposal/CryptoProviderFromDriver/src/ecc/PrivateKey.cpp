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
#include <typeinfo>

#include <openssl/bn.h>
#include <Poco/SharedPtr.h>

#include "ECC.hpp"
#include "PublicKey.hpp"
#include "PrivateKey.hpp"
#include "Networks.hpp"
#include "Base58.hpp"
#include "Utils.hpp"

namespace privmx {
namespace cryptoservice {
namespace ecc {

// from static version - has been replaced by injected provider
// std::shared_ptr<ISymCryptoProvider> PrivateKey::_provider(std::make_shared<CryptoProviderFromDriver>());

PrivateKey PrivateKey::fromWIF(const std::string& wif) {
    std::string payload = Base58::decodeWithChecksum(wif);
    if (payload.front() != Networks::BITCOIN.WIF) {
        // throw InvalidNetworkException();
        throw std::runtime_error("PrivateKey: InvalidNetworkException");
    }
    payload.erase(payload.begin());
    if (payload.length() == 33) {
        if (payload.back() != '\x01') {
            // throw InvalidCompressionFlagException();
            throw std::runtime_error("PrivateKey: InvalidCompressionFlagException");
        }
        payload.erase(payload.end() - 1);
    }
    if (payload.length() != 32) {
        // throw InvalidWIFPayloadLengthException();
        throw std::runtime_error("PrivateKey: InvalidWIFPayloadLengthException");
    }
    ECC key = ECC::fromPrivateKey(payload);
    return PrivateKey(std::move(key));
}

PrivateKey PrivateKey::fromWIFb(std::shared_ptr<ISymCryptoProvider> p, BytesView wif) {
    // Bytes payload = Base58::decodeWithChecksumB(_provider, wif);
    Bytes payload = Base58::decodeWithChecksumB(p, wif);
    if (payload.front() != (uint8_t) Networks::BITCOIN.WIF) {
        // throw InvalidNetworkException();
        throw std::runtime_error("PrivateKey: InvalidNetworkException");
    }
    payload.erase(payload.begin());
    if (payload.size() == 33) {
        if (payload.back() != '\x01') {
            // throw InvalidCompressionFlagException();
            throw std::runtime_error("PrivateKey: InvalidCompressionFlagException");
        }
        payload.erase(payload.end() - 1);
    }
    if (payload.size() != 32) {
        // throw InvalidWIFPayloadLengthException();
        throw std::runtime_error("PrivateKey: InvalidWIFPayloadLengthException");
    }
    ECC key = ECC::fromPrivateKey(Utils::b2s(payload));
    // return PrivateKey(std::move(key));
    return PrivateKey(p, std::move(key));
}

PrivateKey PrivateKey::generateRandom() {
    ECC key = ECC::genPair();
    return PrivateKey(std::move(key));
}

PrivateKey PrivateKey::generateRandom(std::shared_ptr<ISymCryptoProvider> p) {
    ECC key = ECC::genPair();
    return PrivateKey(p, std::move(key));
}

PrivateKey::PrivateKey(const ECC& key) : _key(key) {}

PrivateKey::PrivateKey(std::shared_ptr<ISymCryptoProvider> p) : _provider(p) {}

PrivateKey::PrivateKey(std::shared_ptr<ISymCryptoProvider> p, const ECC& key) : _provider(p), _key(key) {}

std::string PrivateKey::getPrivateEncKey() const {
    std::string key = _key.getPrivateKey();
    // return Utils::fillTo32(key);
    // if(key.length() >= 32) {
    //     return key;
    // }
    // return std::string(32 - key.length(), 0) + key;
    return Utils::fillTo32(key);
}

std::string PrivateKey::signToCompactSignature(const std::string& message) const {
    return _key.sign(message);
}

std::string PrivateKey::signToCompactSignatureWithHash(const std::string& message) const {
    // std::string hash = Crypto::sha256(message);
    std::string hash = NewCrypto::digest(Hash::Sha256, message);
    return signToCompactSignature(hash);
}

std::string PrivateKey::derive(const PublicKey& public_key) const {
    return _key.derive(public_key.getEcc());
}
Bytes PrivateKey::deriveB(const PublicKey& public_key) const {
    return Utils::s2b(_key.derive(public_key.getEcc()));
}

std::string PrivateKey::toWIF() const {
    std::string buffer(1, Networks::BITCOIN.WIF);
    buffer.append(Utils::fillTo32(_key.getPrivateKey()))
        .append(1, 0x01);
    return Base58::encodeWithChecksum(buffer);
}

Bytes PrivateKey::toWIFb() const {
    Bytes buffer = Utils::s2b(_key.getPrivateKey());
    Utils::fillTo32b(buffer);
    buffer.insert(buffer.begin(), 1, (uint8_t) Networks::BITCOIN.WIF);
    buffer.insert(buffer.end(), 1, 0x01);
    return Base58::encodeWithChecksumB(_provider, buffer);
}

Bytes PrivateKey::sign(BytesView data, SigScheme scheme) const {
    switch (scheme) {
        case SigScheme::EcdsaSecp256k1CompactWithHash: // first we need to obtain hash
            return Utils::s2b(_key.sign(Utils::b2s(_provider->digest(Hash::Sha256, data))));
        case SigScheme::EcdsaSecp256k1Compact:  // in both cases we compute signature
            return Utils::s2b(_key.sign(Utils::b2s(data)));
        default:
            throw PrivmxDriverCryptoException("PrivateKey::sign: Unknowne signning scheme");
            break;        
    }
}

std::shared_ptr<IPublicKey> PrivateKey::publicKey() const {
    PublicKey key = getPublicKey();
    return std::make_shared<PublicKey>(std::move(key));
}

// // Old implementaion:
// Bytes PrivateKey::deriveSharedSecret(const IPublicKey& publicKey) const {
//     if (typeid(publicKey) != typeid(PublicKey)) {
//         throw PrivmxDriverCryptoException("PrivateKey::deriveSharedSecret: Wrong type of public key");
//     }
//     return Utils::s2b(ECDHE(*this, (const PublicKey&) publicKey).getSecret());
// }

Bytes PrivateKey::deriveSharedSecret(const IPublicKey& publicKey) const {
    if (typeid(publicKey) != typeid(PublicKey)) {
        throw PrivmxDriverCryptoException("PrivateKey::deriveSharedSecret: Wrong type of public key");
    }
    Bytes secret = deriveB((const PublicKey&) publicKey);
    return Utils::fillTo32b(secret);
}

Bytes PrivateKey::open(BytesView sealed, const IPublicKey* expectedSender) const {
    if (expectedSender != nullptr && typeid(*expectedSender) != typeid(PublicKey)) {
        throw PrivmxDriverCryptoException("PrivateKey::deriveSharedSecret: Wrong type of public key");
    } else if (expectedSender != nullptr) {
        return Utils::s2b(decrypt(Utils::b2s(sealed)));
    } else {
        return Utils::s2b(decrypt(Utils::b2s(sealed), *((const PublicKey*) expectedSender)));
    }
}
Bytes PrivateKey::export_(KeyFormat format) const {
    if (format == KeyFormat::Wif) {
        return toWIFb();
    } else {
        // other formats ...
        throw PrivmxDriverCryptoException("PrivateKey::export_:: Unknown data format");    
    }
}

void PrivateKey::setSymProvider(std::shared_ptr<ISymCryptoProvider> provider) {
    _provider = provider;
}

// from EciesEncryptor class:

Poco::JSON::Object::Ptr PrivateKey::decryptObjectFromBase64(const std::string& cipher_base64, const std::optional<PublicKey>& pubOfSignature) const {
    return Utils::parseJsonObject(decryptFromBase64(cipher_base64, pubOfSignature));
}

std::string PrivateKey::decryptFromBase64(const std::string& cipher_base64, const std::optional<PublicKey>& pubOfSignature) const {
    return decrypt(Base64::toString(cipher_base64), pubOfSignature);
}

std::string PrivateKey::decrypt(const std::string& cipher, const std::optional<PublicKey>& pubOfSignature) const {
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
    if (my_pub_ec != getPublicKey()) {
        // throw GivenPrivKeyDoesNotMatchException();
        throw std::runtime_error("EciesEncryptor: GivenPrivKeyDoesNotMatchException");
    }
    auto key = eciesDecrypt(cipher.substr(67), external_pub_ec);
    return key;
}

std::string PrivateKey::decryptV0(const PublicKey& pub, const std::string& cipher) const {
    return eciesDecrypt(cipher, pub);
}

// from ECIES class:
std::string PrivateKey::eciesDecrypt(const std::string& enc_buf, const PublicKey& public_key) const {
    std::string secret = derive(public_key);
    std::string _shared_key = Utils::b2s(_provider->digest(Hash::Sha512,Utils::s2b(secret)));
    std::string _private_enc_key = getPrivateEncKey();

    std::string c = enc_buf.substr(0, enc_buf.length() - 4);
    std::string d = enc_buf.substr(enc_buf.length() - 4, 4);
    // std::string M = eciesGetM();
    std::string M = _shared_key.substr(32, 32);
    std::string d2 =  Utils::b2s(_provider->hmac(Hash::Sha256, Utils::s2b(M), Utils::s2b(c))).substr(0, 4);
    if (d != d2) {
        // throw InvalidChecksumException();
        throw std::runtime_error("ECIES: InvalidChecksumException");
    }
    // std::string E = eciesGetE();
    std::string E = _shared_key.substr(0, 32);
    return Utils::b2s(_provider->decrypt({SymAlg::Aes256Cbc, Utils::s2b(E), Utils::s2b(c.substr(0, 16))}, Utils::s2b(c.substr(16))));
}

} // ecc
} // cryptoservice
} // privmx
