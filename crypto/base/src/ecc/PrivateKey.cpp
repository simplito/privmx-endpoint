/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/CryptoException.hpp>
#include <privmx/crypto/ecc/Networks.hpp>
#include <privmx/crypto/ecc/PrivateKey.hpp>
#include <privmx/utils/Base58.hpp>
#include <privmx/utils/Utils.hpp>

using namespace privmx;
using namespace privmx::crypto;
using namespace privmx::utils;
using namespace std;

PrivateKey PrivateKey::fromWIF(const string& wif) {
    string payload = Base58::decodeWithChecksum(wif, Crypto::sha256);
    if (payload.front() != Networks::BITCOIN.WIF) {
        throw InvalidNetworkException();
    }
    payload.erase(payload.begin());
    if (payload.length() == 33) {
        if (payload.back() != '\x01') {
            throw InvalidCompressionFlagException();
        }
        payload.erase(payload.end() - 1);
    }
    if (payload.length() != 32) {
        throw InvalidWIFPayloadLengthException();
    }
    ECC key = ECC::fromPrivateKey(payload);
    return PrivateKey(move(key));
}

PrivateKey PrivateKey::generateRandom() {
    ECC key = ECC::genPair();
    return PrivateKey(move(key));
}

PrivateKey::PrivateKey(const ECC& key) : _key(key) {}

string PrivateKey::getPrivateEncKey() const {
    string key = _key.getPrivateKey();
    return Utils::fillTo32(key);
}

/**
 * ECDSA over `sha256(message)`, which is the signature every other side verifies.
 *
 * The hash is **not** applied here: `ECC::sign` digests the message itself. Doing both would sign
 * `sha256(sha256(message))`, which the bridge rejects as an invalid signature — `NonceService`
 * verifies over a single SHA-256 digest (`src/utils/crypto/VerifyKey.ts`), and so does the endpoint's
 * own `core::PublicKey`. There is deliberately no entry point that signs a digest handed to it: the
 * provider has no such scheme for secp256k1, so one could only be faked by hashing a second time.
 */
string PrivateKey::signToCompactSignatureWithHash(const string& message) const {
    return _key.sign(message);
}

string PrivateKey::derive(const PublicKey& public_key) const {
    return _key.derive(public_key.getEcc());
}

string PrivateKey::toWIF() const {
    string buffer(1, Networks::BITCOIN.WIF);
    buffer.append(Utils::fillTo32(_key.getPrivateKey()))
        .append(1, 0x01);
    return Base58::encodeWithChecksum(buffer, Crypto::sha256);
}
