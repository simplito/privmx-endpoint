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
#include "ECDHE.hpp"
#include "EciesEncryptor.hpp"

namespace privmx {
namespace cryptoservice {
namespace ecc {

// std::shared_ptr<ISymCryptoProvider> CryptoProviderRegistry::_provider(nullptr);
std::shared_ptr<ISymCryptoProvider> PrivateKey::_provider(std::make_shared<CryptoProviderFromDriver>());

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

PrivateKey PrivateKey::fromWIFb(BytesView wif) {
    Bytes payload = Base58::decodeWithChecksumB(_provider, wif);
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
    return PrivateKey(std::move(key));
}

PrivateKey PrivateKey::generateRandom() {
    ECC key = ECC::genPair();
    return PrivateKey(std::move(key));
}

PrivateKey::PrivateKey(const ECC& key) : _key(key) {}

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

Bytes PrivateKey::sign(BytesView data, SigScheme) const {
    throw PrivmxDriverCryptoException("PrivateKey::sign: NOT IMPLEMENTED");
}

std::shared_ptr<IPublicKey> PrivateKey::publicKey() const {
    PublicKey key = getPublicKey();
    return std::make_shared<PublicKey>(std::move(key));
    // throw PrivmxDriverCryptoException("PrivateKey::publicKey: NOT IMPLEMENTED");
}

Bytes PrivateKey::deriveSharedSecret(const IPublicKey& publicKey) const {
    // throw PrivmxDriverCryptoException("PrivateKey::deriveSharedSecret: NOT IMPLEMENTED");
    if (typeid(publicKey) != typeid(PublicKey)) {
        throw PrivmxDriverCryptoException("PrivateKey::deriveSharedSecret: Wrong type of public key");
    }
    return Utils::s2b(ECDHE(*this, (const PublicKey&) publicKey).getSecret());
}

Bytes PrivateKey::open(BytesView sealed, const IPublicKey* expectedSender) const {
    // Bytes open(BytesView sealed, const std::optional<IPublicKey>& pubOfSignature = std::nullopt) const {
    // throw PrivmxDriverCryptoException("PrivateKey::sign: NOT IMPLEMENTED");
    if (expectedSender != nullptr && typeid(*expectedSender) != typeid(PublicKey)) {
        throw PrivmxDriverCryptoException("PrivateKey::deriveSharedSecret: Wrong type of public key");
    } else if (expectedSender != nullptr) {
        return Utils::s2b(EciesEncryptor::decrypt(*this, Utils::b2s(sealed)));
    } else {
        return Utils::s2b(EciesEncryptor::decrypt(*this, Utils::b2s(sealed), *((const PublicKey*) expectedSender)));
    }
}

Bytes PrivateKey::export_(KeyFormat format) const {
    if (format == KeyFormat::Wif) {
        // PrivateKey key = toWIFb();
        // return std::make_shared<PrivateKey>(std::move(key));
        return toWIFb();
    } else {
        // other formats ...
        throw PrivmxDriverCryptoException("PrivateKey::export_:: Unknown data format");    
    }
    throw PrivmxDriverCryptoException("PrivateKey::export_: NOT IMPLEMENTED");
}

void PrivateKey::setSymProvider(std::shared_ptr<ISymCryptoProvider> provider) {
    // _provider = provider;
}

} // ecc
} // cryptoservice
} // privmx
