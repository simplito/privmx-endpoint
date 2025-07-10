/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#include <gmpxx.h>
#include <Poco/ByteOrder.h>

#include <privmx/crypto/Crypto.hpp>
#include <privmx/crypto/CryptoException.hpp>
#include <privmx/crypto/ecc/ExtKey.hpp>
#include <privmx/crypto/ecc/Networks.hpp>
#include <privmx/utils/Base58.hpp>
#include <privmx/utils/Utils.hpp>

using namespace privmx;
using namespace privmx::crypto;
using namespace privmx::utils;
using namespace std;
using namespace Poco;

const std::string ExtKey::MASTER_SECRET = "Bitcoin seed";

ExtKey ExtKey::fromSeed(const string& seed) {
    string raw_key = Crypto::hmacSha512(MASTER_SECRET, seed);
    string key = raw_key.substr(0, 32);
    string chain_code = raw_key.substr(32, 32);
    return ExtKey(key, chain_code);
}

ExtKey ExtKey::fromBase58(const string& base58) {
    string raw_key = Base58::decodeWithChecksum(base58);
    UInt32 version = *reinterpret_cast<UInt32*>(raw_key.data());
    version = ByteOrder::fromBigEndian(version);
    if (version != Networks::BITCOIN.BIP39.PRIVATE && version != Networks::BITCOIN.BIP39.PUBLIC) {
        throw InvalidVersionException();
    }
    UInt8 depth = (UInt8)raw_key[4];
    UInt32 parent_fingerprint = *reinterpret_cast<UInt32*>(raw_key.data() + 5);
    parent_fingerprint = ByteOrder::fromBigEndian(parent_fingerprint);
    if (depth == 0 && parent_fingerprint != 0) {
        throw InvalidParentFingerprintException();
    }
    string chain_code = raw_key.substr(13, 32);
    ExtKey key;
    if (version == Networks::BITCOIN.BIP39.PRIVATE) {
        key = ExtKey(raw_key.substr(46, 32), chain_code);
    } else {
        key =  ExtKey(raw_key.substr(45, 33), chain_code, false);
    }
    return key;
}

ExtKey ExtKey::generateRandom() {
    string raw_buf = Crypto::randomBytes(64);
    string key = raw_buf.substr(0, 32);
    string chain_code = raw_buf.substr(32, 32);
    return ExtKey(key, chain_code);
}

ExtKey::ExtKey() {}

ExtKey::ExtKey(const string& key, const string& chain_code, bool private_key) {
    if (private_key) {
        _ec = ECC::fromPrivateKey(key);
    } else {
        _ec = ECC::fromPublicKey(key);
    }
    _chain_code = chain_code;
    _is_private = private_key;
}

ExtKey::ExtKey(const string& key, const string& chain_code, bool private_key, UInt8 depth,
               UInt32 parent_fingerprint, UInt32 index)
        : _depth(depth), _parent_fingerprint(parent_fingerprint), _index(index) {
    if (private_key) {
        _ec = ECC::fromPrivateKey(key);
    } else {
        _ec = ECC::fromPublicKey(key);
    }
    _chain_code = chain_code;
    _is_private = private_key;
}

ExtKey ExtKey::derive(UInt32 index, bool old_privmx_version) const {
    if (!_is_private) {
        throw DeriveFromPublicKeyNotImplementedException();
    }
    string private_key = _ec.getPrivateKey();
    UInt32 index_be = ByteOrder::toBigEndian(index);
    string data;
    if (index >= HIGHEST_BIT) {
        // NOTE:
        // Privmx implementation skips leanding zeros of private key
        // BIP32 requires 256-bit long serialized private key
        auto serialized_key = old_privmx_version ? private_key : Utils::fillTo32(private_key);
        data.append("\0", 1)
            .append(serialized_key)
            .append((char*)&index_be, 4);
    } else {
        data.append(_ec.getPublicKey())
            .append((char*)&index_be, 4);
    }
    string I = Crypto::hmacSha512(_chain_code, data);
    string IL = I.substr(0, 32);
    string LR = I.substr(32, 32);
    mpz_class pIL, k, n;
    mpz_import(pIL.get_mpz_t(), IL.size(), 1, 1, 0, 0, IL.data());
    mpz_import(k.get_mpz_t(), private_key.size(), 1, 1, 0, 0, private_key.data());
    string n_str = _ec.getOrder();
    mpz_import(n.get_mpz_t(), n_str.size(), 1, 1, 0, 0, n_str.data());
    if (pIL > n) {
        return derive(index + 1);
    }
    mpz_class ki = (pIL + k) % n;
    if (ki == 0) {
        return derive(index + 1);
    }
    size_t ki_size = (mpz_sizeinbase(ki.get_mpz_t(), 2) + 7) / 8;
    string ki_str(ki_size, 0);
    mpz_export((char*)ki_str.data(), &ki_size, 1, 1, 0, 0, ki.get_mpz_t());
    string identifier = Crypto::hash160(_ec.getPublicKey()).substr(0, 4);
    UInt32 parent_fingerprint = *reinterpret_cast<UInt32*>(identifier.data());
    parent_fingerprint = ByteOrder::fromBigEndian(parent_fingerprint);
    return ExtKey(ki_str, LR, true, _depth + 1, parent_fingerprint, index);
}

ExtKey ExtKey::derive(Poco::UInt32 index) const {
    return derive(index, false);
}

ExtKey ExtKey::deriveHardened(UInt32 index) const {
    return derive(index + HIGHEST_BIT);
}

ExtKey ExtKey::deriveOldPrivmxVersion(Poco::UInt32 index) const {
    return derive(index, true);
}

ExtKey ExtKey::deriveHardenedOldPrivmxVersion(Poco::UInt32 index) const {
    return deriveOldPrivmxVersion(index + HIGHEST_BIT);
}

string ExtKey::toBase58(bool is_private) const {
    if (is_private && !_is_private) {
        throw DeriveFromPublicKeyNotImplementedException();
    }
    string result(13, '\0');
    char* result_data = result.data();
    UInt32 version = is_private ? Networks::BITCOIN.BIP39.PRIVATE : Networks::BITCOIN.BIP39.PUBLIC;
    *reinterpret_cast<UInt32*>(result_data) = ByteOrder::toBigEndian(version);
    *reinterpret_cast<UInt8*>(result_data + 4) = _depth;
    *reinterpret_cast<UInt32*>(result_data + 5) = ByteOrder::toBigEndian(_parent_fingerprint);
    *reinterpret_cast<UInt32*>(result_data + 9) = ByteOrder::toBigEndian(_index);
    result.append(_chain_code);
    if (is_private) {
        string key = _ec.getPrivateKey();
        if (key.size() < 32) {
            key = string(32 - key.size(), '\0').append(key);
        }
        result.append("\0", 1)
            .append(key);
    } else {
        result.append(_ec.getPublicKey());
    }
    if (result.size() != 78) {
        throw InvalidResultSizeException();
    }
    return Base58::encodeWithChecksum(result);
}
