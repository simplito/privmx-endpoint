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
#include <cstring> // std::memcpy
#include <Poco/ByteOrder.h>

#include "ECC.hpp"
#include "PublicKey.hpp"
#include "PrivateKey.hpp"
#include "Networks.hpp"
#include "Base58.hpp"
#include "Utils.hpp"

#include "ExtKey.hpp"


namespace privmx {
namespace cryptoservice {
namespace ecc {

const std::string ExtKey::MASTER_SECRET = "Bitcoin seed";

ExtKey ExtKey::fromSeed(const std::string& seed) {
    // std::string raw_key = Crypto::hmacSha512(MASTER_SECRET, seed);
    std::string raw_key = NewCrypto::hmac(Hash::Sha512,MASTER_SECRET, seed);
    std::string key = raw_key.substr(0, 32);
    std::string chain_code = raw_key.substr(32, 32);
    return ExtKey(key, chain_code);
}

ExtKey ExtKey::fromSeed(std::shared_ptr<ISymCryptoProvider> p, BytesView seed) {
    Bytes raw_key = p->hmac(Hash::Sha512,Utils::s2b(MASTER_SECRET), seed);
    Bytes key(raw_key.begin(),raw_key.begin()+32);
    Bytes chain_code(raw_key.begin()+32,raw_key.end());
    return ExtKey(p, key, chain_code);
}

ExtKey ExtKey::fromBase58(const std::string& base58) {
    std::string raw_key = Base58::decodeWithChecksum(base58);

    // BIP32 extended key must be exactly 78 bytes
    if (raw_key.size() != 78) {
        // throw InvalidExtendedKeySizeException();
        throw std::runtime_error("ExtKey: InvalidExtendedKeySizeException");
    }

    // ===== version (4 bytes) =====
    Poco::UInt32 version = read_u32_be(raw_key, 0);

    if (version != Networks::BITCOIN.BIP39.PRIVATE &&
        version != Networks::BITCOIN.BIP39.PUBLIC) {
        // throw InvalidVersionException();
        throw std::runtime_error("ExtKey: InvalidVersionException");
        }

    // ===== depth (1 byte) =====
    Poco::UInt8 depth = static_cast<Poco::UInt8>(raw_key[4]);

    // ===== parent fingerprint (4 bytes) =====
    Poco::UInt32 parent_fingerprint = read_u32_be(raw_key, 5);

    if (depth == 0 && parent_fingerprint != 0) {
        // throw InvalidParentFingerprintException();
        throw std::runtime_error("ExtKey: InvalidParentFingerprintException");
    }

    // ===== chain code (32 bytes) =====
    std::string chain_code = raw_key.substr(13, 32);

    // ===== key data =====
    ExtKey key;
    if (version == Networks::BITCOIN.BIP39.PRIVATE) {
        // layout: [0x00][32-byte privkey]
        // key data starts at offset 45, private key at 46
        key = ExtKey(
            raw_key.substr(46, 32),
            chain_code
        );
    } else {
        // layout: [33-byte compressed pubkey]
        // key data starts at offset 45
        key = ExtKey(
            raw_key.substr(45, 33),
            chain_code,
            false
        );
    }

    return key;
}

ExtKey ExtKey::fromBase58(std::shared_ptr<ISymCryptoProvider> p, BytesView base58) {
    Bytes raw_key = Base58::decodeWithChecksumB(p, base58);

    // BIP32 extended key must be exactly 78 bytes
    if (raw_key.size() != 78) {
        // throw InvalidExtendedKeySizeException();
        throw std::runtime_error("ExtKey: InvalidExtendedKeySizeException");
    }

    // ===== version (4 bytes) =====
    Poco::UInt32 version = read_u32_be_b(raw_key, 0);

    if (version != Networks::BITCOIN.BIP39.PRIVATE &&
        version != Networks::BITCOIN.BIP39.PUBLIC) {
        // throw InvalidVersionException();
        throw std::runtime_error("ExtKey: InvalidVersionException");
        }

    // ===== depth (1 byte) =====
    Poco::UInt8 depth = static_cast<Poco::UInt8>(raw_key[4]);

    // ===== parent fingerprint (4 bytes) =====
    Poco::UInt32 parent_fingerprint = read_u32_be_b(raw_key, 5);

    if (depth == 0 && parent_fingerprint != 0) {
        // throw InvalidParentFingerprintException();
        throw std::runtime_error("ExtKey: InvalidParentFingerprintException");
    }

    // ===== chain code (32 bytes) =====
    // std::string chain_code = raw_key.substr(13, 32);
    Bytes chain_code(raw_key.begin()+13,raw_key.begin()+13+32);

    // ===== key data =====
    ExtKey key;
    if (version == Networks::BITCOIN.BIP39.PRIVATE) {
        // layout: [0x00][32-byte privkey]
        // key data starts at offset 45, private key at 46
        key = ExtKey(
            p,
            // raw_key.substr(46, 32),
            Bytes(raw_key.begin()+46,raw_key.begin()+46+32),
            chain_code
        );
    } else {
        // layout: [33-byte compressed pubkey]
        // key data starts at offset 45
        key = ExtKey(
            p,
            // raw_key.substr(45, 33),
            Bytes(raw_key.begin()+45,raw_key.begin()+45+33),
            chain_code,
            false
        );
    }

    return key;
}

ExtKey ExtKey::generateRandom() {
    // std::string raw_buf = Crypto::randomBytes(64);
    std::string raw_buf = NewCrypto::randomBytes(64);
    std::string key = raw_buf.substr(0, 32);
    std::string chain_code = raw_buf.substr(32, 32);
    return ExtKey(key, chain_code);
}

ExtKey ExtKey::generateRandom(std::shared_ptr<ISymCryptoProvider> p) {
    Bytes raw_buf = p->randomBytes(64);
    Bytes key(raw_buf.begin(), raw_buf.begin()+32);
    Bytes chain_code(raw_buf.begin()+32,raw_buf.end());
    // return ExtKey(p, Utils::b2s(key), Utils::b2s(chain_code));
    return ExtKey(p, key, chain_code);
}

ExtKey::ExtKey() {}

ExtKey::ExtKey(const std::string& key, const std::string& chain_code, bool private_key) {
    if (private_key) {
        _ec = ECC::fromPrivateKey(key);
    } else {
        _ec = ECC::fromPublicKey(key);
    }
    _chain_code = chain_code;
    _is_private = private_key;
}

ExtKey::ExtKey(const std::string& key, const std::string& chain_code, bool private_key, Poco::UInt8 depth,
               Poco::UInt32 parent_fingerprint, Poco::UInt32 index)
        : _depth(depth), _parent_fingerprint(parent_fingerprint), _index(index) {
    if (private_key) {
        _ec = ECC::fromPrivateKey(key);
    } else {
        _ec = ECC::fromPublicKey(key);
    }
    _chain_code = chain_code;
    _is_private = private_key;
}

ExtKey::ExtKey(std::shared_ptr<ISymCryptoProvider> p) : _provider(p) {}

ExtKey::ExtKey(std::shared_ptr<ISymCryptoProvider> p, 
    BytesView key, BytesView chain_code, bool private_key) : _provider(p) {
    if (private_key) {
        _ec = ECC::fromPrivateKey(Utils::b2s(key));
    } else {
        _ec = ECC::fromPublicKey(Utils::b2s(key));
    }
    _chain_code = Utils::b2s(chain_code);
    _is_private = private_key;
}

ExtKey::ExtKey(std::shared_ptr<ISymCryptoProvider> p, 
               BytesView key, BytesView chain_code, bool private_key, Poco::UInt8 depth,
               Poco::UInt32 parent_fingerprint, Poco::UInt32 index)
        : _depth(depth), _parent_fingerprint(parent_fingerprint), _index(index), _provider(p) {
    if (private_key) {
        _ec = ECC::fromPrivateKey(Utils::b2s(key));
    } else {
        _ec = ECC::fromPublicKey(Utils::b2s(key));
    }
    _chain_code = Utils::b2s(chain_code);
    _is_private = private_key;
}

ExtKey ExtKey::derive(Poco::UInt32 index, bool old_privmx_version) const {
    if (!_is_private) {
        // throw ExtKeyDoesNotHoldPrivateKeyException();
        throw std::runtime_error("ExtKey: ExtKeyDoesNotHoldPrivateKeyException");
    }
    std::string private_key = _ec.getPrivateKey();
    Poco::UInt32 index_be = Poco::ByteOrder::toBigEndian(index);
    std::string data;
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
    // std::string I = Crypto::hmacSha512(_chain_code, data);
    std::string I = NewCrypto::hmac(Hash::Sha512,_chain_code, data);
    std::string IL = I.substr(0, 32);
    std::string LR = I.substr(32, 32);
    mpz_class pIL, k, n;
    mpz_import(pIL.get_mpz_t(), IL.size(), 1, 1, 0, 0, IL.data());
    mpz_import(k.get_mpz_t(), private_key.size(), 1, 1, 0, 0, private_key.data());
    std::string n_str = _ec.getOrder();
    mpz_import(n.get_mpz_t(), n_str.size(), 1, 1, 0, 0, n_str.data());
    if (pIL > n) {
        return derive(index + 1);
    }
    mpz_class ki = (pIL + k) % n;
    if (ki == 0) {
        return derive(index + 1);
    }
    size_t ki_size = (mpz_sizeinbase(ki.get_mpz_t(), 2) + 7) / 8;
    std::string ki_str(ki_size, 0);
    mpz_export((char*)ki_str.data(), &ki_size, 1, 1, 0, 0, ki.get_mpz_t());
    // std::string identifier = Crypto::hash160(_ec.getPublicKey()).substr(0, 4);
    std::string identifier = NewCrypto::digest(Hash::Hash160, _ec.getPublicKey()).substr(0, 4);
    Poco::UInt32 parent_fingerprint = *reinterpret_cast<Poco::UInt32*>(identifier.data());
    parent_fingerprint = Poco::ByteOrder::fromBigEndian(parent_fingerprint);
    return ExtKey(ki_str, LR, true, _depth + 1, parent_fingerprint, index);
}

ExtKey ExtKey::derive(Poco::UInt32 index) const {
    return derive(index, false);
}

ExtKey ExtKey::deriveHardened(Poco::UInt32 index) const {
    return derive(index + HIGHEST_BIT);
}

ExtKey ExtKey::deriveOldPrivmxVersion(Poco::UInt32 index) const {
    return derive(index, true);
}

ExtKey ExtKey::deriveHardenedOldPrivmxVersion(Poco::UInt32 index) const {
    return deriveOldPrivmxVersion(index + HIGHEST_BIT);
}

std::string ExtKey::toBase58(bool is_private) const {
    if (is_private && !_is_private) {
        // throw ExtKeyDoesNotHoldPrivateKeyException();
        throw std::runtime_error("ExtKey: ExtKeyDoesNotHoldPrivateKeyException");
    }

    Poco::UInt32 version = is_private ? Networks::BITCOIN.BIP39.PRIVATE : Networks::BITCOIN.BIP39.PUBLIC;
    Poco::UInt32 versionBE = Poco::ByteOrder::toBigEndian(version);
    Poco::UInt32 fingerprintBE = Poco::ByteOrder::toBigEndian(_parent_fingerprint);
    Poco::UInt32 indexBE = Poco::ByteOrder::toBigEndian(_index);
    Poco::UInt8 depth = _depth;

    std::string result(13, '\0');
    char* result_data = result.data();

    std::memcpy(result_data,     &versionBE,     4); // Offset 0
    std::memcpy(result_data + 4, &depth,         1); // Offset 4
    std::memcpy(result_data + 5, &fingerprintBE, 4); // Offset 5 (Fixed!)
    std::memcpy(result_data + 9, &indexBE,       4); // Offset 9 (Fixed!)

    result.append(_chain_code);

    if (is_private) {
        std::string key = _ec.getPrivateKey();
        if (key.size() < 32) {
            key = std::string(32 - key.size(), '\0').append(key);
        }
        result.append("\0", 1).append(key);
    } else {
        result.append(_ec.getPublicKey());
    }

    if (result.size() != 78) {
        // throw InvalidResultSizeException();
        throw std::runtime_error("ExtKey: InvalidResultSizeException");
    }
    return Base58::encodeWithChecksum(result);
}

Poco::UInt32 ExtKey::read_u32_be(const std::string& raw_key, size_t offset) {
    Poco::UInt32 v;
    std::memcpy(&v, raw_key.data() + offset, 4);
    return Poco::ByteOrder::fromBigEndian(v);
}

// TO REWRITE
Poco::UInt32 ExtKey::read_u32_be_b(BytesView raw_key, size_t offset) {
    Poco::UInt32 v;
    std::memcpy(&v, raw_key.data() + offset, 4);
    return Poco::ByteOrder::fromBigEndian(v);
}

// inline std::shared_ptr<IExtKey> ExtKey::deriveChild(uint32_t index, bool hardened) const {
//     if (hardened) {
//         return std::make_shared<ExtKey>(std::move(deriveHardened(index)));
//     } else {
//         return std::make_shared<ExtKey>(std::move(derive(index)));
//     }
// }
std::shared_ptr<IExtKey> ExtKey::deriveChild(uint32_t index, bool hardened) const {
    
    if (hardened) {
        ExtKey key = deriveHardened(index);
        key.setSymProvider(_provider);
        return std::make_shared<ExtKey>(std::move(key));
    } else {
        ExtKey key = derive(index);
        key.setSymProvider(_provider);
        return std::make_shared<ExtKey>(std::move(key));
    }
}

// inline std::shared_ptr<IPrivateKey> ExtKey::privateKey() const {
//     return std::make_shared<PrivateKey>(std::move(getPrivateKey()));
// }
std::shared_ptr<IPrivateKey> ExtKey::privateKey() const {
    PrivateKey key = getPrivateKey();
    key.setSymProvider(_provider);
    return std::make_shared<PrivateKey>(std::move(key));
}

// inline std::shared_ptr<IPublicKey> ExtKey::publicKey() const {
//     return std::make_shared<PublicKey>(std::move(getPublicKey()));
// }
std::shared_ptr<IPublicKey> ExtKey::publicKey() const {
    PublicKey key = getPublicKey();
    key.setSymProvider(_provider);
    return std::make_shared<PublicKey>(std::move(key));
}

inline Bytes ExtKey::chainCode() const {
    // throw PrivmxDriverCryptoException("ExtKey::chainCode: NOT IMPLEMENTED");
    return Utils::s2b(getChainCode());
}

void ExtKey::setSymProvider(std::shared_ptr<ISymCryptoProvider> provider) {
    _provider = provider;
}

} // ecc
} // cryptoservice
} // privmx
