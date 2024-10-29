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
    string payload = Base58::decodeWithChecksum(wif);
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

string PrivateKey::signToCompactSignature(const string& message) const {
    return _key.sign(message);
}

string PrivateKey::signToCompactSignatureWithHash(const string& message) const {
    string hash = Crypto::sha256(message);
    return signToCompactSignature(hash);
}

string PrivateKey::derive(const PublicKey& public_key) const {
    return _key.derive(public_key.getEcc());
}

string PrivateKey::toWIF() const {
    string buffer(1, Networks::BITCOIN.WIF);
    buffer.append(Utils::fillTo32(_key.getPrivateKey()))
        .append(1, 0x01);
    return Base58::encodeWithChecksum(buffer);
}
