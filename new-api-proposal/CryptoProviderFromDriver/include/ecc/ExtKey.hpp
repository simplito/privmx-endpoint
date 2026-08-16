/*
PrivMX Endpoint.
Copyright © 2024 Simplito sp. z o.o.

This file is part of the PrivMX Platform (https://privmx.dev).
This software is Licensed under the PrivMX Free License.

See the License for the specific language governing permissions and
limitations under the License.
*/

#ifndef _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_EXTKEY_HPP_
#define _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_EXTKEY_HPP_

// #include <functional>
#include <memory>
#include <string>
// #include <openssl/bn.h>
#include <openssl/ec.h>

#include <gmpxx.h>
#include <Poco/ByteOrder.h>

#include "CoreTypes.hpp"
#include "CoreInterfaces.hpp"

#include "ECC.hpp"
#include "PublicKey.hpp"
#include "PrivateKey.hpp"

namespace privmx {
// namespace crypto {
namespace cryptoservice {
namespace ecc {

class ExtKey : public IExtKey
{
public:
    static ExtKey fromSeed(const std::string& seed);
    static ExtKey fromBase58(const std::string& base58);
    static ExtKey generateRandom();
    ExtKey();
    ExtKey(const std::string& key, const std::string& chain_code, bool private_key = true);
    ExtKey(const std::string& key, const std::string& chain_code, bool private_key, Poco::UInt8 depth,
           Poco::UInt32 parent_fingerprint, Poco::UInt32 index);
    operator bool() const;
    ExtKey derive(Poco::UInt32 index) const;
    ExtKey deriveHardened(Poco::UInt32 index) const;
    // Old Privmx implementation skips leanding zeros of private key
    ExtKey deriveOldPrivmxVersion(Poco::UInt32 index) const;
    ExtKey deriveHardenedOldPrivmxVersion(Poco::UInt32 index) const;
    std::string getPrivatePartAsBase58() const;
    std::string getPublicPartAsBase58() const;
    PrivateKey getPrivateKey() const;
    PublicKey getPublicKey() const;
    std::string getPrivateEncKey() const;
    std::string getPublicKeyAsBase58() const;
    std::string getPublicKeyAsBase58Address() const;
    const std::string& getChainCode() const;
    bool verifyCompactSignatureWithHash(const std::string& message, const std::string& signature) const;
    bool isPrivate() const;
    const ECC& getECC() const;

    virtual std::shared_ptr<IExtKey> deriveChild(uint32_t index, bool hardened) const override;
    virtual std::shared_ptr<IPrivateKey> privateKey() const override;
    virtual std::shared_ptr<IPublicKey>  publicKey()  const override;
    virtual Bytes chainCode() const override;

private:
    static const Poco::UInt32 HIGHEST_BIT = 0x80000000;
    static const std::string MASTER_SECRET;
    static Poco::UInt32 read_u32_be(const std::string& raw_key, size_t offset);

    std::string toBase58(bool is_private = false) const;
    ExtKey derive(Poco::UInt32 index, bool old_privmx_version) const;

    ECC _ec;
    std::string _chain_code;
    bool _is_private;
    Poco::UInt8 _depth = 0;
    Poco::UInt32 _parent_fingerprint = 0x00000000;
    Poco::UInt32 _index = 0;

    std::shared_ptr<ISymCryptoProvider> _provider;
};

inline ExtKey::operator bool() const {
    return _ec;
}

inline std::string ExtKey::getPrivatePartAsBase58() const {
    return toBase58(true);
}

inline std::string ExtKey::getPublicPartAsBase58() const {
    return toBase58();
}

inline PrivateKey ExtKey::getPrivateKey() const {
    if (!_is_private) {
        // throw ExtKeyDoesNotHoldPrivateKeyException();
        throw std::runtime_error("ExtKey: ExtKeyDoesNotHoldPrivateKeyException");
    }
    return PrivateKey(_ec);
}

inline PublicKey ExtKey::getPublicKey() const {
    return PublicKey(_ec);
}

inline std::string ExtKey::getPrivateEncKey() const {
    if (!_is_private) {
        // throw ExtKeyDoesNotHoldPrivateKeyException();
        throw std::runtime_error("ExtKey: ExtKeyDoesNotHoldPrivateKeyException");
    }
    return getPrivateKey().getPrivateEncKey();
}

inline std::string ExtKey::getPublicKeyAsBase58() const {
    return getPublicKey().toBase58DER();
}

inline std::string ExtKey::getPublicKeyAsBase58Address() const {
    return getPublicKey().toBase58Address();
}

inline const std::string& ExtKey::getChainCode() const {
    return _chain_code;
}

inline bool ExtKey::verifyCompactSignatureWithHash(const std::string& message, const std::string& signature) const {
    return getPublicKey().verifyCompactSignatureWithHash(message, signature);
}

inline bool ExtKey::isPrivate() const {
    return _is_private;
}

inline const ECC& ExtKey::getECC() const {
    return _ec;
}

inline std::shared_ptr<IExtKey> ExtKey::deriveChild(uint32_t index, bool hardened) const {
    throw PrivmxDriverCryptoException("ExtKey::deriveChild: NOT IMPLEMENTED");
}

inline std::shared_ptr<IPrivateKey> ExtKey::privateKey() const {
    throw PrivmxDriverCryptoException("ExtKey::privateKey: NOT IMPLEMENTED");
}

inline std::shared_ptr<IPublicKey> ExtKey::publicKey() const {
    throw PrivmxDriverCryptoException("ExtKey::publicKey: NOT IMPLEMENTED");
}

inline Bytes ExtKey::chainCode() const {
    throw PrivmxDriverCryptoException("ExtKey::chainCode: NOT IMPLEMENTED");
}

} // ecc
} // cryptoservice
} // privmx

#endif // _PRIVMXLIB_CRYPTOSERVICE_ECCIMPL_EXTKEY_HPP_