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

} // ecc
} // cryptoservice
} // privmx
