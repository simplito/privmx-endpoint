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
#include "EciesEncryptor.hpp"
#include "PrivateKey.hpp"


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

// inline Bytes PublicKey::seal(BytesView data, const IPrivateKey* senderForSignature) const {
//     throw PrivmxDriverCryptoException("PublicKey::seal: NOT IMPLEMENTED");
// }
Bytes PublicKey::seal(BytesView data, const IPrivateKey& senderForSignature) const {
    // previously EciesEncryptor::encrypt(*this,data,senderForSignature)
    // throw PrivmxDriverCryptoException("PublicKey::seal: NOT IMPLEMENTED");
    if (typeid(senderForSignature) != typeid(PrivateKey)) {
        throw PrivmxDriverCryptoException("PublicKey::seal: Wrong type of private key");
    }
    return Utils::s2b(EciesEncryptor::encrypt(*this, Utils::b2s(data), (const PrivateKey&) senderForSignature));
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

} // ecc
} // cryptoservice
} // privmx
