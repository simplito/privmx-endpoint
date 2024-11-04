/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/ecc/Networks.hpp>
#include <privmx/crypto/ecc/PublicKey.hpp>
#include <privmx/utils/Base58.hpp>

using namespace privmx;
using namespace privmx::crypto;
using namespace privmx::utils;
using namespace std;

PublicKey PublicKey::fromDER(const string& der) {
    ECC key = ECC::fromPublicKey(der);
    return PublicKey(key);
}

PublicKey PublicKey::fromBase58DER(const string& base58) {
    string der = Base58::decodeWithChecksum(base58);
    return fromDER(der);
}

PublicKey::PublicKey(const ECC& key) : _key(key) {}

bool PublicKey::operator==(const PublicKey& obj) const {
    return (_key.getPublicKey() == obj._key.getPublicKey());
}

bool PublicKey::operator!=(const PublicKey& obj) const {
    return (_key.getPublicKey() != obj._key.getPublicKey());
}

string PublicKey::toDER() const {
    return _key.getPublicKey();
}

string PublicKey::toBase58DER() const {
    return Base58::encodeWithChecksum(_key.getPublicKey());
}

string PublicKey::toBase58Address() const {
    string hash = Crypto::hash160(_key.getPublicKey());
    string payload = Networks::BITCOIN.PUB_KEY_HASH + hash;
    return Base58::encodeWithChecksum(payload);
}

bool PublicKey::verifyCompactSignature(const string& message, const string& signature) const {
    return _key.verify(message, signature);
}

bool PublicKey::verifyCompactSignatureWithHash(const string& message, const string& signature) const {
    string hash = Crypto::sha256(message);
    return verifyCompactSignature(hash, signature);
}
